import { env } from "cloudflare:workers";
import { checkTotp, createSession, hashPassword, newTotpSecret, otpauthUrl, sessionAdmin, sessionCookie, verifyPassword, cookieToken } from "./auth";
import { allow } from "./db";
import { body, fail, hmacHex, ipHash, json, now, randomToken, safeEqual } from "./http";

// The admin API behind /admin: first-time setup, login (password + authenticator code, always),
// beta keys, uploading and releasing game builds, and adding more admins.

/** Builds are uploaded in pieces this size (KV values can't exceed 25 MB). */
export const CHUNK_BYTES = 20 * 1024 * 1024;
/** KV's free plan holds 1 GB; uploads stop before that. */
const STORAGE_LIMIT_BYTES = 950 * 1024 * 1024;

type Admin = { id: number; username: string };

export async function adminRoutes(request: Request, url: URL): Promise<Response> {
	const path = url.pathname.slice("/api/admin".length);
	const m = request.method;

	// Open routes: setup and login.
	if (path === "/state" && m === "GET") return state(request);
	if (path === "/setup/secret" && m === "POST") return setupSecret(request);
	if (path === "/setup" && m === "POST") return setup(request);
	if (path === "/login" && m === "POST") return login(request);
	if (path === "/login/2fa" && m === "POST") return login2fa(request);
	if (path === "/logout" && m === "POST") return logout(request);

	const admin = await sessionAdmin(env.DB, request, env.SESSION_SECRET);
	if (!admin) return fail(401, "unauthorized", "Sign in again.");

	if (path === "/keys" && m === "GET") return listKeys();
	if (path === "/keys" && m === "POST") return createKeys(request);
	let match = path.match(/^\/keys\/(\d+)\/(revoke|restore)$/);
	if (match && m === "POST") return setRevoked(Number(match[1]), match[2] === "revoke");

	if (path === "/versions" && m === "GET") return listVersions();
	if (path === "/versions" && m === "POST") return startUpload(request);
	match = path.match(/^\/versions\/(\d+)\/chunks\/(\d+)$/);
	if (match && m === "PUT") return putChunk(request, Number(match[1]), Number(match[2]));
	match = path.match(/^\/versions\/(\d+)\/(publish|unpublish)$/);
	if (match && m === "POST") return setPublished(Number(match[1]), match[2] === "publish");
	match = path.match(/^\/versions\/(\d+)$/);
	if (match && m === "DELETE") return deleteVersion(Number(match[1]));

	if (path === "/admins" && m === "GET") return listAdmins();
	if (path === "/admins/secret" && m === "POST") return json(newSecret("new admin"));
	if (path === "/admins" && m === "POST") return addAdmin(request, admin);

	return fail(404, "not_found", "Not found.");
}

// ---------- Setup and login ----------

async function adminCount(): Promise<number> {
	return (await env.DB.prepare("SELECT COUNT(*) AS n FROM admins").first<{ n: number }>())!.n;
}

async function state(request: Request): Promise<Response> {
	const admin = await sessionAdmin(env.DB, request, env.SESSION_SECRET);
	return json({ needs_setup: (await adminCount()) === 0, admin: admin ? { username: admin.username } : null });
}

function newSecret(username: string) {
	const secret = newTotpSecret();
	return { totp_secret: secret, otpauth_url: otpauthUrl(secret, username) };
}

async function checkSetupKey(request: Request, key: string | undefined): Promise<Response | null> {
	if (!(await allow(env.DB, "setup:" + (await ipHash(request, env.SESSION_SECRET)), 10, 600))) return fail(429, "rate_limited", "Too many tries. Wait a few minutes.");
	if ((await adminCount()) > 0) return fail(403, "forbidden", "Setup is already done. Sign in instead.");
	if (!key || !safeEqual(key.trim(), env.SETUP_KEY)) return fail(403, "forbidden", "That setup key is wrong.");
	return null;
}

/** First run, step 1: a fresh authenticator secret to add to your phone. */
async function setupSecret(request: Request): Promise<Response> {
	const { setup_key, username } = await body<{ setup_key?: string; username?: string }>(request);
	return (await checkSetupKey(request, setup_key)) ?? json(newSecret(username || "admin"));
}

type NewAdmin = { username?: string; password?: string; totp_secret?: string; code?: string };

function checkNewAdmin(a: NewAdmin): string | null {
	if (!a.username || !/^[A-Za-z0-9_]{3,20}$/.test(a.username)) return "Usernames are 3 to 20 letters, numbers or underscores.";
	if (!a.password || a.password.length < 10) return "Use a password of at least 10 characters.";
	if (!a.totp_secret || !/^[A-Z2-7]{32}$/.test(a.totp_secret)) return "Start the 2FA step again.";
	return null;
}

/** First run, step 2: create the first admin, once their authenticator shows a working code. */
async function setup(request: Request): Promise<Response> {
	const b = await body<NewAdmin & { setup_key?: string }>(request);
	const denied = await checkSetupKey(request, b.setup_key);
	if (denied) return denied;
	const problem = checkNewAdmin(b);
	if (problem) return fail(400, "bad_request", problem);
	if (!(await checkTotp(b.totp_secret!, b.code ?? ""))) return fail(401, "bad_code", "That code didn't work. Use the newest code from your app.");
	await env.DB.prepare("INSERT INTO admins (username, password_hash, totp_secret, created_at) VALUES (?, ?, ?, ?)")
		.bind(b.username, await hashPassword(b.password!), b.totp_secret, now())
		.run();
	return json({ ok: true });
}

async function login(request: Request): Promise<Response> {
	const ip = await ipHash(request, env.SESSION_SECRET);
	if (!(await allow(env.DB, "login:" + ip, 10, 600))) return fail(429, "rate_limited", "Too many tries. Wait a few minutes.");
	const { username, password } = await body<{ username?: string; password?: string }>(request);
	const admin = await env.DB.prepare("SELECT id, password_hash FROM admins WHERE username = ?").bind(username ?? "").first<{ id: number; password_hash: string }>();
	if (!admin || !(await verifyPassword(password ?? "", admin.password_hash))) return fail(401, "unauthorized", "Wrong username or password.");

	const ticket = randomToken();
	await env.DB.prepare("DELETE FROM pending_logins WHERE expires_at < ?").bind(now()).run();
	await env.DB.prepare("INSERT INTO pending_logins (ticket_hash, admin_id, expires_at) VALUES (?, ?, ?)")
		.bind(await hmacHex(env.SESSION_SECRET, ticket), admin.id, now() + 300)
		.run();
	return json({ ticket });
}

async function login2fa(request: Request): Promise<Response> {
	const { ticket, code } = await body<{ ticket?: string; code?: string }>(request);
	const ticketHash = await hmacHex(env.SESSION_SECRET, ticket ?? "");
	const pending = await env.DB.prepare(
		"SELECT p.admin_id, a.totp_secret FROM pending_logins p JOIN admins a ON a.id = p.admin_id WHERE p.ticket_hash = ? AND p.expires_at > ?",
	).bind(ticketHash, now()).first<{ admin_id: number; totp_secret: string }>();
	if (!pending) return fail(401, "unauthorized", "That sign-in took too long. Start again.");
	if (!(await allow(env.DB, "2fa:" + pending.admin_id, 6, 300))) return fail(429, "rate_limited", "Too many codes tried. Wait a few minutes.");
	if (!(await checkTotp(pending.totp_secret, code ?? ""))) return fail(401, "bad_code", "That code didn't work.");

	await env.DB.prepare("DELETE FROM pending_logins WHERE ticket_hash = ?").bind(ticketHash).run();
	const token = await createSession(env.DB, pending.admin_id, env.SESSION_SECRET);
	return json({ ok: true }, 200, { "Set-Cookie": sessionCookie(token) });
}

async function logout(request: Request): Promise<Response> {
	const token = cookieToken(request);
	if (token) await env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?").bind(await hmacHex(env.SESSION_SECRET, token)).run();
	return json({ ok: true }, 200, { "Set-Cookie": sessionCookie("", 0) });
}

// ---------- Beta keys ----------

async function listKeys(): Promise<Response> {
	const { results } = await env.DB.prepare("SELECT * FROM beta_keys ORDER BY id DESC LIMIT 500").all();
	return json({ keys: results });
}

/** Keys look like LF-ABCD-EFGH (typed without dashes too). */
function newKeyCode(): string {
	const alphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
	const pick = crypto.getRandomValues(new Uint8Array(8));
	const chars = [...pick].map((b) => alphabet[b % alphabet.length]).join("");
	return `LF${chars}`;
}

async function createKeys(request: Request): Promise<Response> {
	const { label, max_uses, count } = await body<{ label?: string; max_uses?: number; count?: number }>(request);
	const n = Math.min(Math.max(Math.floor(count ?? 1), 1), 50);
	const uses = Math.max(Math.floor(max_uses ?? 0), 0);
	const codes: string[] = [];
	for (let i = 0; i < n; i++) {
		const code = newKeyCode();
		await env.DB.prepare("INSERT INTO beta_keys (code, label, max_uses, created_at) VALUES (?, ?, ?, ?)")
			.bind(code, (label ?? "").slice(0, 80), uses, now())
			.run();
		codes.push(code);
	}
	return json({ codes });
}

async function setRevoked(id: number, revoked: boolean): Promise<Response> {
	await env.DB.prepare("UPDATE beta_keys SET revoked = ? WHERE id = ?").bind(revoked ? 1 : 0, id).run();
	return json({ ok: true });
}

// ---------- Versions ----------

async function storageUsed(): Promise<number> {
	return (await env.DB.prepare("SELECT COALESCE(SUM(size), 0) AS n FROM versions").first<{ n: number }>())!.n;
}

async function listVersions(): Promise<Response> {
	const { results } = await env.DB.prepare("SELECT * FROM versions ORDER BY id DESC").all();
	return json({ versions: results, storage_used: await storageUsed(), storage_limit: STORAGE_LIMIT_BYTES, chunk_bytes: CHUNK_BYTES });
}

async function startUpload(request: Request): Promise<Response> {
	const { version, notes, filename, size } = await body<{ version?: string; notes?: string; filename?: string; size?: number }>(request);
	if (!version || !/^[0-9A-Za-z.\-]{1,20}$/.test(version)) return fail(400, "bad_request", "Give a version like 0.3.");
	if (!filename || !size || size <= 0) return fail(400, "bad_request", "Pick a file to upload.");
	if (size > 500 * 1024 * 1024) return fail(400, "bad_request", "That file is too big (500 MB at most).");
	if ((await storageUsed()) + size > STORAGE_LIMIT_BYTES)
		return fail(409, "storage_full", "Not enough free space. Delete an old version first (the free plan holds about 1 GB).");
	const chunks = Math.ceil(size / CHUNK_BYTES);
	const row = await env.DB.prepare(
		"INSERT INTO versions (version, notes, filename, size, chunks, created_at) VALUES (?, ?, ?, ?, ?, ?) RETURNING id",
	).bind(version, (notes ?? "").slice(0, 4000), filename.replace(/[^\w.\-]/g, "_").slice(0, 100), size, chunks, now()).first<{ id: number }>();
	return json({ id: row!.id, chunks, chunk_bytes: CHUNK_BYTES });
}

async function putChunk(request: Request, id: number, n: number): Promise<Response> {
	const v = await env.DB.prepare("SELECT size, chunks, uploaded FROM versions WHERE id = ?").bind(id).first<{ size: number; chunks: number; uploaded: number }>();
	if (!v) return fail(404, "not_found", "No such upload.");
	if (n < 0 || n >= v.chunks) return fail(400, "bad_request", "Wrong piece number.");
	const data = await request.arrayBuffer();
	const expected = n < v.chunks - 1 ? CHUNK_BYTES : v.size - CHUNK_BYTES * (v.chunks - 1);
	if (data.byteLength !== expected) return fail(400, "bad_request", `Piece ${n + 1} is the wrong size. Try the upload again.`);
	await env.FILES.put(`file:${id}:${n}`, data);
	await env.DB.prepare("UPDATE versions SET uploaded = uploaded + 1 WHERE id = ?").bind(id).run();
	return json({ ok: true });
}

async function setPublished(id: number, publish: boolean): Promise<Response> {
	const v = await env.DB.prepare("SELECT chunks FROM versions WHERE id = ?").bind(id).first<{ chunks: number }>();
	if (!v) return fail(404, "not_found", "No such version.");
	if (publish) {
		// Make sure every piece made it before anyone can download it.
		for (let i = 0; i < v.chunks; i++) {
			const meta = await env.FILES.getWithMetadata(`file:${id}:${i}`, "stream");
			if (!meta.value) return fail(409, "incomplete", `Piece ${i + 1} is missing. Upload this version again.`);
			await meta.value.cancel();
		}
	}
	await env.DB.prepare("UPDATE versions SET published = ?, published_at = ? WHERE id = ?").bind(publish ? 1 : 0, publish ? now() : null, id).run();
	return json({ ok: true });
}

async function deleteVersion(id: number): Promise<Response> {
	const v = await env.DB.prepare("SELECT chunks FROM versions WHERE id = ?").bind(id).first<{ chunks: number }>();
	if (!v) return fail(404, "not_found", "No such version.");
	for (let i = 0; i < v.chunks; i++) await env.FILES.delete(`file:${id}:${i}`);
	await env.DB.prepare("DELETE FROM versions WHERE id = ?").bind(id).run();
	return json({ ok: true });
}

// ---------- Admins ----------

async function listAdmins(): Promise<Response> {
	const { results } = await env.DB.prepare("SELECT id, username, created_at FROM admins ORDER BY id").all();
	return json({ admins: results });
}

/** An admin adds another; the new admin's authenticator must show a working code first. */
async function addAdmin(request: Request, by: Admin): Promise<Response> {
	const b = await body<NewAdmin>(request);
	const problem = checkNewAdmin(b);
	if (problem) return fail(400, "bad_request", problem);
	if (!(await checkTotp(b.totp_secret!, b.code ?? ""))) return fail(401, "bad_code", "That code didn't work. Use the newest code from their app.");
	const exists = await env.DB.prepare("SELECT 1 FROM admins WHERE username = ?").bind(b.username).first();
	if (exists) return fail(409, "conflict", "That username is taken.");
	await env.DB.prepare("INSERT INTO admins (username, password_hash, totp_secret, created_at) VALUES (?, ?, ?, ?)")
		.bind(b.username, await hashPassword(b.password!), b.totp_secret, now())
		.run();
	console.log(`admin ${by.username} added admin ${b.username}`);
	return json({ ok: true });
}
