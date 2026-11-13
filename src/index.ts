import { env } from "cloudflare:workers";
import { adminRoutes } from "./admin";
import { publicRoutes } from "./public";
import { rgsRoutes, serverForKey } from "./rgs";
import { ensureSchema } from "./db";
import { fail, json } from "./http";

export { ServerLink } from "./link";

// Everything under /api/, /rgs/api/ and /rgs/s/ comes here; the rest of the site is static
// files from public/.
export default {
	async fetch(request) {
		const url = new URL(request.url);
		try {
			await ensureSchema(env.DB);
			if (url.pathname.startsWith("/api/admin/")) return await adminRoutes(request, url);
			if (url.pathname === "/rgs/api/link") return await link(request);
			if (url.pathname.startsWith("/rgs/api/")) return await rgsRoutes(request, url);
			const relayed = url.pathname.match(/^\/rgs\/s\/(\d+)(\/api\/v1\/.*)$/);
			if (relayed) return await relay(request, url, Number(relayed[1]), relayed[2]);
			return await publicRoutes(request, url);
		} catch (err) {
			console.error(err);
			return json({ error: "internal", message: "Something went wrong on our side. Try again in a moment." }, 500);
		}
	},
} satisfies ExportedHandler<Env>;

function linkFor(serverId: number) {
	return env.LINKS.get(env.LINKS.idFromName(String(serverId)));
}

/** An RGS server opening its relay connection, proving who it is with its server key. */
async function link(request: Request): Promise<Response> {
	if (request.headers.get("Upgrade") !== "websocket") return fail(426, "upgrade_required", "Connect with a WebSocket.");
	const key = (request.headers.get("Authorization") ?? "").replace(/^Bearer\s+/i, "");
	const serverId = await serverForKey(key);
	if (serverId === null) return fail(401, "unauthorized", "Unknown server key. Link the server again from your RGS account.");
	return linkFor(serverId).fetch(request);
}

/** A request for a linked server's API (admin panel, player page, games), passed down its link. */
async function relay(request: Request, url: URL, serverId: number, apiPath: string): Promise<Response> {
	const exists = await env.DB.prepare("SELECT 1 FROM rgs_servers WHERE id = ?").bind(serverId).first();
	if (!exists) return fail(404, "not_found", "No such RGS server.");
	const forward = new Request(new URL(apiPath + url.search, url.origin), request);
	forward.headers.set("x-rgs-client-ip", request.headers.get("CF-Connecting-IP") ?? "");
	return linkFor(serverId).fetch(forward);
}
