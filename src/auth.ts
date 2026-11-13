import { hex, hmacHex, now, randomToken, safeEqual } from "./http";

// Admin passwords (PBKDF2-SHA256), authenticator codes (TOTP), admin sessions, and the
// short-lived signed links that let a beta key holder download a build.

// Kept moderate so a login fits in the free plan's CPU budget; 2FA is required on top.
const PBKDF2_ITERATIONS = 10_000;

export async function hashPassword(password: string): Promise<string> {
	const salt = crypto.getRandomValues(new Uint8Array(16));
	const hash = await pbkdf2(password, salt, PBKDF2_ITERATIONS);
	return `pbkdf2$${PBKDF2_ITERATIONS}$${hex(salt)}$${hash}`;
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
	const [kind, iterations, saltHex, expected] = stored.split("$");
	if (kind !== "pbkdf2") return false;
	const salt = new Uint8Array(saltHex.match(/../g)!.map((h) => parseInt(h, 16)));
	return safeEqual(await pbkdf2(password, salt, Number(iterations)), expected);
}

async function pbkdf2(password: string, salt: Uint8Array, iterations: number): Promise<string> {
	const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
	const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, key, 256);
	return hex(new Uint8Array(bits));
}

// ---------- TOTP (authenticator apps) ----------

const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function newTotpSecret(): string {
	const bytes = crypto.getRandomValues(new Uint8Array(20));
	let bits = "";
	for (const b of bytes) bits += b.toString(2).padStart(8, "0");
	let out = "";
	for (let i = 0; i + 5 <= bits.length; i += 5) out += BASE32[parseInt(bits.slice(i, i + 5), 2)];
	return out;
}

function base32Bytes(secret: string): Uint8Array {
	let bits = "";
	for (const c of secret.toUpperCase().replace(/=+$/, "")) bits += BASE32.indexOf(c).toString(2).padStart(5, "0");
	const out = new Uint8Array(Math.floor(bits.length / 8));
	for (let i = 0; i < out.length; i++) out[i] = parseInt(bits.slice(i * 8, i * 8 + 8), 2);
	return out;
}

async function totpAt(secret: string, counter: number): Promise<string> {
	const key = await crypto.subtle.importKey("raw", base32Bytes(secret), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
	const msg = new Uint8Array(8);
	let c = counter;
	for (let i = 7; i >= 0; i--) {
		msg[i] = c & 0xff;
		c = Math.floor(c / 256);
	}
	const h = new Uint8Array(await crypto.subtle.sign("HMAC", key, msg));
	const o = h[19] & 0xf;
	const num = ((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
	return (num % 1_000_000).toString().padStart(6, "0");
}

/** Accepts the current code and the ones just before and after (phone clocks drift). */
export async function checkTotp(secret: string, code: string): Promise<boolean> {
	const clean = code.replace(/\s/g, "");
	if (!/^\d{6}$/.test(clean)) return false;
	const step = Math.floor(Date.now() / 30_000);
	for (const d of [-1, 0, 1]) if (safeEqual(await totpAt(secret, step + d), clean)) return true;
	return false;
}

export function otpauthUrl(secret: string, username: string): string {
	return `otpauth://totp/SpiritEXE:${encodeURIComponent(username)}?secret=${secret}&issuer=SpiritEXE`;
}

// ---------- Admin sessions ----------

export const SESSION_HOURS = 12;

export async function createSession(db: D1Database, adminId: number, secret: string): Promise<string> {
	const token = randomToken();
	await db.prepare("DELETE FROM sessions WHERE expires_at < ?").bind(now()).run();
	await db.prepare("INSERT INTO sessions (token_hash, admin_id, expires_at) VALUES (?, ?, ?)")
		.bind(await hmacHex(secret, token), adminId, now() + SESSION_HOURS * 3600)
		.run();
	return token;
}

export function sessionCookie(token: string, maxAge = SESSION_HOURS * 3600): string {
	return `spx_admin=${token}; Path=/api/admin; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;
}

export function cookieToken(request: Request): string | null {
	const match = (request.headers.get("Cookie") ?? "").match(/(?:^|;\s*)spx_admin=([^;]+)/);
	return match ? match[1] : null;
}

export async function sessionAdmin(db: D1Database, request: Request, secret: string): Promise<{ id: number; username: string } | null> {
	const token = cookieToken(request);
	if (!token) return null;
	return db.prepare(
		"SELECT a.id, a.username FROM sessions s JOIN admins a ON a.id = s.admin_id WHERE s.token_hash = ? AND s.expires_at > ?",
	).bind(await hmacHex(secret, token), now()).first<{ id: number; username: string }>();
}

// ---------- Download links ----------

/** A link that lets one person download one build for the next 15 minutes. */
export async function signDownload(secret: string, versionId: number, keyId: number): Promise<string> {
	const exp = now() + 15 * 60;
	const payload = `${versionId}.${keyId}.${exp}`;
	return `${payload}.${await hmacHex(secret, "dl:" + payload)}`;
}

export async function checkDownload(secret: string, token: string, versionId: number): Promise<number | null> {
	const parts = token.split(".");
	if (parts.length !== 4) return null;
	const [v, k, exp, sig] = parts;
	if (Number(v) !== versionId || Number(exp) < now()) return null;
	if (!safeEqual(await hmacHex(secret, `dl:${v}.${k}.${exp}`), sig)) return null;
	return Number(k);
}
