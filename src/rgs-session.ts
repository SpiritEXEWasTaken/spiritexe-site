import { env } from "cloudflare:workers";
import { hmacHex, ipHash, now, randomToken, safeEqual } from "./http";

// Sign-ins for RGS website accounts, made hard to steal and reuse:
// - The cookie is __Host- (only this exact site, https, path /), HttpOnly (page scripts can't
//   read it) and SameSite=Strict (never sent from another site).
// - Without "Keep me signed in" it's a browser-session cookie, and the sign-in ends after 12
//   hours anyway. With it, the sign-in lasts while you keep visiting: a week without a visit ends
//   it, and so does 30 days whatever happens.
// - The token changes at most once an hour while you use the site. If an old token shows up after
//   that, someone copied the cookie, so the whole sign-in is ended for everyone holding it.
// - A sign-in only works from the browser it was made in (user agent, minus version numbers so a
//   browser update doesn't sign you out).
// - Changing your password or 2FA ends every other sign-in (see rgs.ts).
// - Sudo mode, like GitHub's: big actions need a fresh 2FA code once. That gives a sudo token kept
//   only in the tab (sessionStorage), so it ends when you leave the site, and it only works from
//   the same network address and sign-in it was made for (and for 12 hours at most).

const SHORT_HOURS = 12;
const IDLE_DAYS = 7;
const MAX_DAYS = 30;
const ROTATE_SECONDS = 3600;
/** An old token still works this long after it was replaced (requests already on their way). */
const GRACE_SECONDS = 60;
const SUDO_HOURS = 12;
const COOKIE = "__Host-rgs";

export const LOGINS_SCHEMA = [
	`CREATE TABLE IF NOT EXISTS rgs_logins (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		account_id INTEGER NOT NULL,
		token_hash TEXT NOT NULL UNIQUE,
		prev_hash TEXT,
		rotated_at INTEGER NOT NULL,
		remember INTEGER NOT NULL,
		agent_hash TEXT NOT NULL,
		created_at INTEGER NOT NULL,
		last_used INTEGER NOT NULL,
		sudo_hash TEXT,
		sudo_ip TEXT,
		sudo_until INTEGER)`,
	"CREATE INDEX IF NOT EXISTS rgs_logins_prev ON rgs_logins(prev_hash)",
	"CREATE INDEX IF NOT EXISTS rgs_logins_account ON rgs_logins(account_id)",
	// The old 12-hour sessions (everyone signs in once more).
	"DROP TABLE IF EXISTS rgs_sessions",
];

export type Login = {
	id: number;
	account_id: number;
	username: string;
	remember: boolean;
	sudo_hash: string | null;
	sudo_ip: string | null;
	sudo_until: number | null;
};

type Row = {
	id: number; account_id: number; username: string; token_hash: string; prev_hash: string | null; rotated_at: number;
	remember: number; agent_hash: string; created_at: number; last_used: number;
	sudo_hash: string | null; sudo_ip: string | null; sudo_until: number | null;
};

const tokenHash = (token: string) => hmacHex(env.SESSION_SECRET, "rgs:" + token);

/** The browser, without version numbers (a browser update shouldn't sign you out). */
function agentHash(request: Request): Promise<string> {
	const agent = (request.headers.get("User-Agent") ?? "").replace(/[\d._]+/g, "").replace(/\s+/g, " ").trim();
	return hmacHex(env.SESSION_SECRET, "agent:" + agent);
}

export function cookie(token: string, remember: boolean): string {
	return `${COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Strict${remember ? `; Max-Age=${IDLE_DAYS * 86400}` : ""}`;
}

export function clearCookies(): string[] {
	return [
		`${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`,
		// The cookie from before sign-ins could be kept (Path=/rgs/api).
		"spx_rgs=; Path=/rgs/api; HttpOnly; Secure; SameSite=Strict; Max-Age=0",
	];
}

function cookieToken(request: Request): string | null {
	const match = (request.headers.get("Cookie") ?? "").match(new RegExp(`(?:^|;\\s*)${COOKIE}=([^;]+)`));
	return match ? match[1] : null;
}

/** Signs an account in; returns the cookie(s) to set. */
export async function startLogin(request: Request, accountId: number, remember: boolean): Promise<string[]> {
	const token = randomToken();
	const t = now();
	await env.DB.prepare("DELETE FROM rgs_logins WHERE (remember = 0 AND created_at < ?) OR created_at < ? OR last_used < ?")
		.bind(t - SHORT_HOURS * 3600, t - MAX_DAYS * 86400, t - IDLE_DAYS * 86400)
		.run();
	await env.DB.prepare(
		"INSERT INTO rgs_logins (account_id, token_hash, rotated_at, remember, agent_hash, created_at, last_used) VALUES (?, ?, ?, ?, ?, ?, ?)",
	).bind(accountId, await tokenHash(token), t, remember ? 1 : 0, await agentHash(request), t, t).run();
	return [cookie(token, remember), clearCookies()[1]];
}

/** The sign-in this request carries, if it's still good. `setCookie` is a new or cleared cookie
 * the response must carry (the token was rotated, or the sign-in ended). */
export async function currentLogin(request: Request): Promise<{ login: Login | null; setCookie: string[] }> {
	const token = cookieToken(request);
	if (!token) return { login: null, setCookie: [] };
	const h = await tokenHash(token);
	const row = await env.DB.prepare(
		`SELECT l.*, a.username FROM rgs_logins l JOIN rgs_accounts a ON a.id = l.account_id
		 WHERE l.token_hash = ? OR l.prev_hash = ?`,
	).bind(h, h).first<Row>();
	const end = async (why: string) => {
		if (row) {
			await env.DB.prepare("DELETE FROM rgs_logins WHERE id = ?").bind(row.id).run();
			console.warn(`rgs sign-in ${row.id} ended: ${why}`);
		}
		return { login: null, setCookie: clearCookies() };
	};
	if (!row) return end("unknown token");

	const t = now();
	const current = safeEqual(row.token_hash, h);
	// An old token long after it was replaced: the cookie was copied. End it for everyone.
	if (!current && t - row.rotated_at > GRACE_SECONDS) return end("an old token was used again (copied cookie?)");
	if (row.remember ? t - row.last_used > IDLE_DAYS * 86400 || t - row.created_at > MAX_DAYS * 86400 : t - row.created_at > SHORT_HOURS * 3600) return end("expired");
	if (!safeEqual(row.agent_hash, await agentHash(request))) return end("used from a different browser");

	const setCookie: string[] = [];
	if (current && t - row.rotated_at > ROTATE_SECONDS) {
		const fresh = randomToken();
		const done = await env.DB.prepare("UPDATE rgs_logins SET token_hash = ?, prev_hash = ?, rotated_at = ?, last_used = ? WHERE id = ? AND token_hash = ?")
			.bind(await tokenHash(fresh), h, t, t, row.id, h)
			.run();
		if (done.meta.changes) setCookie.push(cookie(fresh, !!row.remember));
	} else if (t - row.last_used > 300) {
		await env.DB.prepare("UPDATE rgs_logins SET last_used = ? WHERE id = ?").bind(t, row.id).run();
	}
	const login: Login = {
		id: row.id, account_id: row.account_id, username: row.username, remember: !!row.remember,
		sudo_hash: row.sudo_hash, sudo_ip: row.sudo_ip, sudo_until: row.sudo_until,
	};
	return { login, setCookie };
}

/** Gives the sign-in a fresh token (after a password or 2FA change); returns the cookie. */
export async function rotateNow(login: Login): Promise<string> {
	const fresh = randomToken();
	await env.DB.prepare("UPDATE rgs_logins SET token_hash = ?, prev_hash = NULL, rotated_at = ?, last_used = ? WHERE id = ?")
		.bind(await tokenHash(fresh), now(), now(), login.id)
		.run();
	return cookie(fresh, login.remember);
}

export async function endLogin(login: Login): Promise<void> {
	await env.DB.prepare("DELETE FROM rgs_logins WHERE id = ?").bind(login.id).run();
}

/** Ends every sign-in of an account, except `keep` if given. */
export async function endOtherLogins(accountId: number, keep?: number): Promise<number> {
	const done = await env.DB.prepare("DELETE FROM rgs_logins WHERE account_id = ? AND id != ?").bind(accountId, keep ?? -1).run();
	return done.meta.changes ?? 0;
}

// ---------- Sudo mode ----------

const sudoHash = (token: string) => hmacHex(env.SESSION_SECRET, "sudo:" + token);

/** Starts sudo mode for this sign-in (after a fresh 2FA code); returns the tab's sudo token. */
export async function startSudo(request: Request, login: Login): Promise<string> {
	const token = randomToken();
	await env.DB.prepare("UPDATE rgs_logins SET sudo_hash = ?, sudo_ip = ?, sudo_until = ? WHERE id = ?")
		.bind(await sudoHash(token), await ipHash(request, env.SESSION_SECRET), now() + SUDO_HOURS * 3600, login.id)
		.run();
	return token;
}

/** True if the request carries this sign-in's sudo token, from the address it was made on. */
export async function inSudo(request: Request, login: Login): Promise<boolean> {
	const token = request.headers.get("X-RGS-Sudo");
	if (!token || !login.sudo_hash || !login.sudo_until || login.sudo_until < now()) return false;
	if (!safeEqual(login.sudo_hash, await sudoHash(token))) return false;
	return login.sudo_ip === (await ipHash(request, env.SESSION_SECRET));
}
