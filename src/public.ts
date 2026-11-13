import { env } from "cloudflare:workers";
import { checkDownload, signDownload } from "./auth";
import { allow } from "./db";
import { body, fail, ipHash, json, now } from "./http";

// Public API: the list of released versions, unlocking a download with a beta key, and the
// download itself.

export async function publicRoutes(request: Request, url: URL): Promise<Response> {
	const path = url.pathname;
	if (path === "/api/versions" && request.method === "GET") return versions();
	if (path === "/api/unlock" && request.method === "POST") return unlock(request);
	const dl = path.match(/^\/api\/download\/(\d+)$/);
	if (dl && request.method === "GET") return download(Number(dl[1]), url.searchParams.get("t") ?? "");
	return fail(404, "not_found", "Not found.");
}

/** Released builds, newest first (for the changelog). */
async function versions(): Promise<Response> {
	const { results } = await env.DB.prepare(
		"SELECT id, game, version, notes, size, published_at FROM versions WHERE published = 1 ORDER BY published_at DESC LIMIT 50",
	).all();
	return json({ versions: results });
}

type BetaKey = { id: number; max_uses: number; uses: number; revoked: number };

/** Checks a beta key and hands back a short-lived link to the newest build. */
async function unlock(request: Request): Promise<Response> {
	const ip = await ipHash(request, env.SESSION_SECRET);
	if (!(await allow(env.DB, "unlock:" + ip, 10, 600))) return fail(429, "rate_limited", "Too many tries. Wait a few minutes.");

	const { code } = await body<{ code?: string }>(request);
	const clean = (code ?? "").toUpperCase().replace(/[^A-Z0-9]/g, "");
	if (!clean) return fail(400, "bad_request", "Enter your beta key.");
	const key = await env.DB.prepare("SELECT id, max_uses, uses, revoked FROM beta_keys WHERE code = ?").bind(clean).first<BetaKey>();
	if (!key || key.revoked) return fail(403, "invalid_key", "That beta key isn't valid.");
	if (key.max_uses > 0 && key.uses >= key.max_uses) return fail(403, "key_used_up", "That beta key has been used up. Ask us for a new one.");

	const latest = await env.DB.prepare(
		"SELECT id, version, filename, size FROM versions WHERE published = 1 ORDER BY published_at DESC LIMIT 1",
	).first<{ id: number; version: string; filename: string; size: number }>();
	if (!latest) return fail(404, "no_build", "There's no build to download yet. Check back soon.");

	await env.DB.prepare("UPDATE beta_keys SET uses = uses + 1, last_used_at = ? WHERE id = ?").bind(now(), key.id).run();
	const token = await signDownload(env.SESSION_SECRET, latest.id, key.id);
	return json({
		version: latest.version,
		filename: latest.filename,
		size: latest.size,
		url: `/api/download/${latest.id}?t=${encodeURIComponent(token)}`,
	});
}

/** Streams a build out of KV, chunk after chunk, as one file. */
async function download(versionId: number, token: string): Promise<Response> {
	const keyId = await checkDownload(env.SESSION_SECRET, token, versionId);
	if (keyId === null) return fail(403, "link_expired", "This download link has expired. Enter your beta key again.");
	const v = await env.DB.prepare("SELECT filename, size, chunks FROM versions WHERE id = ? AND published = 1")
		.bind(versionId)
		.first<{ filename: string; size: number; chunks: number }>();
	if (!v) return fail(404, "not_found", "That build isn't available any more.");
	await env.DB.prepare("UPDATE versions SET downloads = downloads + 1 WHERE id = ?").bind(versionId).run();

	const { readable, writable } = new FixedLengthStream(v.size);
	(async () => {
		try {
			for (let i = 0; i < v.chunks; i++) {
				const part = await env.FILES.get(`file:${versionId}:${i}`, "stream");
				if (!part) throw new Error(`missing chunk ${i} of version ${versionId}`);
				await part.pipeTo(writable, { preventClose: true });
			}
			await writable.close();
		} catch (err) {
			console.error(err);
			await writable.abort(err);
		}
	})();
	return new Response(readable, {
		headers: {
			"Content-Type": "application/octet-stream",
			"Content-Disposition": `attachment; filename="${v.filename.replace(/"/g, "")}"`,
			"Cache-Control": "no-store",
		},
	});
}
