import { env } from "cloudflare:workers";
import { checkTotp, hashPassword, newTotpSecret, verifyPassword } from "./auth";
import { allow } from "./db";
import { body, fail, hmacHex, ipHash, json, now, randomToken } from "./http";
import { LINKED_BY, serverLink } from "./link";

// RGS hub, under /rgs: accounts for people who run RGS servers, and their servers.
// Each server is linked to one account by a secret server key that only that account sees
// (once, when it's made). The server sends a status report with that key every minute, so an
// account only ever sees and manages its own servers. 2FA is required for every account.

const SESSION_HOURS = 12;
let ready = false;

async function schema(db: D1Database): Promise<void> {
	if (ready) return;
	await db.batch([
		db.prepare(`CREATE TABLE IF NOT EXISTS rgs_accounts (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE COLLATE NOCASE,
			password_hash TEXT NOT NULL,
			totp_secret TEXT NOT NULL,
			created_at INTEGER NOT NULL)`),
		db.prepare(`CREATE TABLE IF NOT EXISTS rgs_sessions (
			token_hash TEXT PRIMARY KEY, account_id INTEGER NOT NULL, expires_at INTEGER NOT NULL)`),
		db.prepare(`CREATE TABLE IF NOT EXISTS rgs_pending (
			ticket_hash TEXT PRIMARY KEY, account_id INTEGER NOT NULL, expires_at INTEGER NOT NULL)`),
		db.prepare(`CREATE TABLE IF NOT EXISTS rgs_servers (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			owner_id INTEGER NOT NULL,
			name TEXT NOT NULL,
			key_hash TEXT NOT NULL UNIQUE,
			created_at INTEGER NOT NULL,
			last_seen INTEGER,
			report TEXT)`),
	]);
	ready = true;
}

export async function rgsRoutes(request: Request, url: URL): Promise<Response> {
	await schema(env.DB);
	const path = url.pathname.slice("/rgs/api".length);
	const m = request.method;

	if (path === "/heartbeat" && m === "POST") return heartbeat(request);
	if (path === "/signup/secret" && m === "POST") return signupSecret(request);
	if (path === "/signup" && m === "POST") return signup(request);
	if (path === "/login" && m === "POST") return login(request);
	if (path === "/login/2fa" && m === "POST") return login2fa(request);
	if (path === "/logout" && m === "POST") return logout(request);

	const me = await sessionAccount(request);
	if (path === "/me" && m === "GET") return json({ account: me });
	if (!me) return fail(401, "unauthorized", "Sign in again.");

	if (path === "/servers" && m === "GET") return listServers(me.id);
	if (path === "/servers" && m === "POST") return addServer(request, me.id);
	let match = path.match(/^\/servers\/(\d+)\/key$/);
	if (match && m === "POST") return newKey(me.id, Number(match[1]));
	match = path.match(/^\/servers\/(\d+)\/admin$/);
	if (match && m === "POST") return openAdmin(me, Number(match[1]));
	match = path.match(/^\/servers\/(\d+)$/);
	if (match && m === "DELETE") return removeServer(me.id, Number(match[1]));
	return fail(404, "not_found", "Not found.");
}

// ---------- Accounts ----------

function cookie(token: string, maxAge = SESSION_HOURS * 3600): string {
	return `spx_rgs=${token}; Path=/rgs/api; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;
}

function cookieToken(request: Request): string | null {
	const match = (request.headers.get("Cookie") ?? "").match(/(?:^|;\s*)spx_rgs=([^;]+)/);
	return match ? match[1] : null;
}

async function sessionAccount(request: Request): Promise<{ id: number; username: string } | null> {
	const token = cookieToken(request);
	if (!token) return null;
	return env.DB.prepare(
		"SELECT a.id, a.username FROM rgs_sessions s JOIN rgs_accounts a ON a.id = s.account_id WHERE s.token_hash = ? AND s.expires_at > ?",
	).bind(await hmacHex(env.SESSION_SECRET, "rgs:" + token), now()).first<{ id: number; username: string }>();
}

async function startSession(accountId: number): Promise<Response> {
	const token = randomToken();
	await env.DB.prepare("DELETE FROM rgs_sessions WHERE expires_at < ?").bind(now()).run();
	await env.DB.prepare("INSERT INTO rgs_sessions (token_hash, account_id, expires_at) VALUES (?, ?, ?)")
		.bind(await hmacHex(env.SESSION_SECRET, "rgs:" + token), accountId, now() + SESSION_HOURS * 3600)
		.run();
	return json({ ok: true }, 200, { "Set-Cookie": cookie(token) });
}

async function limited(request: Request, what: string, max: number): Promise<boolean> {
	return !(await allow(env.DB, `rgs-${what}:` + (await ipHash(request, env.SESSION_SECRET)), max, 600));
}

/** Sign-up step 1: a fresh authenticator secret (2FA is required). */
async function signupSecret(request: Request): Promise<Response> {
	if (await limited(request, "signup", 10)) return fail(429, "rate_limited", "Too many tries. Wait a few minutes.");
	const { username } = await body<{ username?: string }>(request);
	const secret = newTotpSecret();
	return json({ totp_secret: secret, otpauth_url: `otpauth://totp/RGS:${encodeURIComponent(username || "account")}?secret=${secret}&issuer=RGS` });
}

/** Sign-up step 2: the account is made once the authenticator shows a working code. */
async function signup(request: Request): Promise<Response> {
	if (await limited(request, "signup", 10)) return fail(429, "rate_limited", "Too many tries. Wait a few minutes.");
	const b = await body<{ username?: string; password?: string; totp_secret?: string; code?: string }>(request);
	if (!b.username || !/^[A-Za-z0-9_]{3,20}$/.test(b.username)) return fail(400, "bad_request", "Usernames are 3 to 20 letters, numbers or underscores.");
	if (!b.password || b.password.length < 10) return fail(400, "bad_request", "Use a password of at least 10 characters.");
	if (!b.totp_secret || !/^[A-Z2-7]{32}$/.test(b.totp_secret)) return fail(400, "bad_request", "Start the 2FA step again.");
	if (!(await checkTotp(b.totp_secret, b.code ?? ""))) return fail(401, "bad_code", "That code didn't work. Use the newest code from your app.");
	if (await env.DB.prepare("SELECT 1 FROM rgs_accounts WHERE username = ?").bind(b.username).first()) return fail(409, "conflict", "That username is taken.");
	const row = await env.DB.prepare("INSERT INTO rgs_accounts (username, password_hash, totp_secret, created_at) VALUES (?, ?, ?, ?) RETURNING id")
		.bind(b.username, await hashPassword(b.password), b.totp_secret, now())
		.first<{ id: number }>();
	return startSession(row!.id);
}

async function login(request: Request): Promise<Response> {
	if (await limited(request, "login", 10)) return fail(429, "rate_limited", "Too many tries. Wait a few minutes.");
	const { username, password } = await body<{ username?: string; password?: string }>(request);
	const a = await env.DB.prepare("SELECT id, password_hash FROM rgs_accounts WHERE username = ?").bind(username ?? "").first<{ id: number; password_hash: string }>();
	if (!a || !(await verifyPassword(password ?? "", a.password_hash))) return fail(401, "unauthorized", "Wrong username or password.");
	const ticket = randomToken();
	await env.DB.prepare("DELETE FROM rgs_pending WHERE expires_at < ?").bind(now()).run();
	await env.DB.prepare("INSERT INTO rgs_pending (ticket_hash, account_id, expires_at) VALUES (?, ?, ?)")
		.bind(await hmacHex(env.SESSION_SECRET, "rgs:" + ticket), a.id, now() + 300)
		.run();
	return json({ ticket });
}

async function login2fa(request: Request): Promise<Response> {
	const { ticket, code } = await body<{ ticket?: string; code?: string }>(request);
	const ticketHash = await hmacHex(env.SESSION_SECRET, "rgs:" + (ticket ?? ""));
	const p = await env.DB.prepare(
		"SELECT p.account_id, a.totp_secret FROM rgs_pending p JOIN rgs_accounts a ON a.id = p.account_id WHERE p.ticket_hash = ? AND p.expires_at > ?",
	).bind(ticketHash, now()).first<{ account_id: number; totp_secret: string }>();
	if (!p) return fail(401, "unauthorized", "That sign-in took too long. Start again.");
	if (!(await allow(env.DB, "rgs-2fa:" + p.account_id, 6, 300))) return fail(429, "rate_limited", "Too many codes tried. Wait a few minutes.");
	if (!(await checkTotp(p.totp_secret, code ?? ""))) return fail(401, "bad_code", "That code didn't work.");
	await env.DB.prepare("DELETE FROM rgs_pending WHERE ticket_hash = ?").bind(ticketHash).run();
	return startSession(p.account_id);
}

async function logout(request: Request): Promise<Response> {
	const token = cookieToken(request);
	if (token) await env.DB.prepare("DELETE FROM rgs_sessions WHERE token_hash = ?").bind(await hmacHex(env.SESSION_SECRET, "rgs:" + token)).run();
	return json({ ok: true }, 200, { "Set-Cookie": cookie("", 0) });
}

// ---------- Servers ----------

type ServerRow = { id: number; name: string; created_at: number; last_seen: number | null; report: string | null };

async function listServers(ownerId: number): Promise<Response> {
	const { results } = await env.DB.prepare("SELECT id, name, created_at, last_seen, report FROM rgs_servers WHERE owner_id = ? ORDER BY id")
		.bind(ownerId)
		.all<ServerRow>();
	const servers = results.map((s) => ({
		id: s.id,
		name: s.name,
		created_at: s.created_at,
		last_seen: s.last_seen,
		// Online if it reported in the last 3 minutes (reports come every minute).
		online: s.last_seen !== null && now() - s.last_seen < 180,
		report: s.report ? JSON.parse(s.report) : null,
	}));
	return json({ servers });
}

/** A new server key: shown once, stored only as a hash. */
async function makeKey(): Promise<{ key: string; hash: string }> {
	const key = "rgs_" + randomToken(32);
	return { key, hash: await hmacHex(env.SESSION_SECRET, "server:" + key) };
}

async function addServer(request: Request, ownerId: number): Promise<Response> {
	const { name } = await body<{ name?: string }>(request);
	const clean = (name ?? "").trim().slice(0, 60);
	if (!clean) return fail(400, "bad_request", "Give your server a name.");
	const count = (await env.DB.prepare("SELECT COUNT(*) AS n FROM rgs_servers WHERE owner_id = ?").bind(ownerId).first<{ n: number }>())!.n;
	if (count >= 20) return fail(409, "conflict", "That's the most servers one account can link (20).");
	const { key, hash } = await makeKey();
	const row = await env.DB.prepare("INSERT INTO rgs_servers (owner_id, name, key_hash, created_at) VALUES (?, ?, ?, ?) RETURNING id")
		.bind(ownerId, clean, hash, now())
		.first<{ id: number }>();
	return json({ id: row!.id, key });
}

async function newKey(ownerId: number, id: number): Promise<Response> {
	const { key, hash } = await makeKey();
	const done = await env.DB.prepare("UPDATE rgs_servers SET key_hash = ? WHERE id = ? AND owner_id = ?").bind(hash, id, ownerId).run();
	if (!done.meta.changes) return fail(404, "not_found", "No such server.");
	return json({ id, key });
}

/** One account: the account that linked a server opens its admin panel with no second sign-in.
 * This account signed in here with 2FA, so the Worker vouches for it over the relay and the
 * server answers with an admin panel session as its owner. */
async function openAdmin(me: { id: number; username: string }, id: number): Promise<Response> {
	const own = await env.DB.prepare("SELECT 1 FROM rgs_servers WHERE id = ? AND owner_id = ?").bind(id, me.id).first();
	if (!own) return fail(404, "not_found", "That server isn't linked to your RGS account.");
	const res = await serverLink(env, id).fetch(new Request("https://relay.internal/api/v1/admin/hub-session", {
		method: "POST",
		headers: { [LINKED_BY]: me.username },
	}));
	return new Response(res.body, { status: res.status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });
}

async function removeServer(ownerId: number, id: number): Promise<Response> {
	const done = await env.DB.prepare("DELETE FROM rgs_servers WHERE id = ? AND owner_id = ?").bind(id, ownerId).run();
	if (!done.meta.changes) return fail(404, "not_found", "No such server.");
	return json({ ok: true });
}

/** The linked server a server key belongs to, or null. */
export async function serverForKey(key: string): Promise<number | null> {
	await schema(env.DB);
	if (!key.startsWith("rgs_")) return null;
	const row = await env.DB.prepare("SELECT id FROM rgs_servers WHERE key_hash = ?").bind(await hmacHex(env.SESSION_SECRET, "server:" + key)).first<{ id: number }>();
	return row ? row.id : null;
}

/** A linked RGS server reporting in, authorized by its server key. */
async function heartbeat(request: Request): Promise<Response> {
	const key = (request.headers.get("Authorization") ?? "").replace(/^Bearer\s+/i, "");
	if (!key.startsWith("rgs_")) return fail(401, "unauthorized", "Missing server key.");
	const server = await env.DB.prepare("SELECT id FROM rgs_servers WHERE key_hash = ?").bind(await hmacHex(env.SESSION_SECRET, "server:" + key)).first<{ id: number }>();
	if (!server) return fail(401, "unauthorized", "Unknown server key. Link the server again from your RGS account.");
	const r = await body<Record<string, unknown>>(request);
	// Keep only the fields the dashboard shows, with sane sizes.
	const report = {
		version: String(r.version ?? "").slice(0, 20),
		status: String(r.status ?? "").slice(0, 30),
		accounts: Number(r.accounts) || 0,
		active_players: Number(r.active_players) || 0,
		open_reports: Number(r.open_reports) || 0,
		announcement: String(r.announcement ?? "").slice(0, 200),
		games: Array.isArray(r.games) ? r.games.slice(0, 20).map((g) => String(g).slice(0, 60)) : [],
	};
	await env.DB.prepare("UPDATE rgs_servers SET last_seen = ?, report = ? WHERE id = ?").bind(now(), JSON.stringify(report), server.id).run();
	return json({ ok: true });
}
