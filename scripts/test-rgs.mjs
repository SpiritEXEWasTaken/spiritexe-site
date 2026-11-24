// Checks the RGS hub against a local `cf dev`: operator sign-up with required 2FA, "Keep me
// signed in", sudo mode, linking a server, its heartbeat, password and 2FA changes ending other
// sign-ins, and that one account can't see or touch another account's servers.
//   node scripts/test-rgs.mjs     (SITE=... for another address)
import crypto from "node:crypto";
import fs from "node:fs";

const base = process.env.SITE ?? "http://localhost:5173";
let pass = 0, failed = 0;
const check = (name, ok, extra = "") => { console.log(`${ok ? "PASS" : "FAIL"}  ${name}${ok || !extra ? "" : "  " + extra}`); ok ? pass++ : failed++; };

/** A browser: keeps its cookie (and the last Set-Cookie seen), its user agent and its sudo token. */
function client(agent = "test-browser/1.0") {
	const c = { cookie: "", setCookie: [], sudo: "", agent };
	c.call = async (method, path, body, headers = {}) => {
		const res = await fetch(base + "/rgs/api" + path, {
			method,
			headers: { "Content-Type": "application/json", "User-Agent": c.agent, ...(c.cookie ? { Cookie: c.cookie } : {}), ...(c.sudo ? { "X-RGS-Sudo": c.sudo } : {}), ...headers },
			body: body ? JSON.stringify(body) : undefined,
		});
		c.setCookie = res.headers.getSetCookie();
		for (const s of c.setCookie) if (s.startsWith("__Host-rgs=")) c.cookie = /Max-Age=0/.test(s) ? "" : s.split(";")[0];
		return { status: res.status, data: await res.json().catch(() => ({})) };
	};
	return c;
}

function totp(secret, offset = 0) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
	let bits = "";
	for (const ch of secret) bits += alphabet.indexOf(ch).toString(2).padStart(5, "0");
	const key = Buffer.from(bits.match(/.{8}/g).map((b) => parseInt(b, 2)));
	const msg = Buffer.alloc(8);
	msg.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000) + offset));
	const h = crypto.createHmac("sha1", key).update(msg).digest();
	const o = h[19] & 0xf;
	return (((h[o] & 0x7f) << 24 | h[o + 1] << 16 | h[o + 2] << 8 | h[o + 3]) % 1e6).toString().padStart(6, "0");
}

async function signUp(c, username, remember = false) {
	const s = await c.call("POST", "/signup/secret", { username });
	const r = await c.call("POST", "/signup", { username, password: "long enough pw", totp_secret: s.data.totp_secret, code: totp(s.data.totp_secret), remember });
	return { ok: r.status === 200, secret: s.data.totp_secret };
}
async function sudo(c, secret) {
	const r = await c.call("POST", "/sudo", { code: totp(secret) });
	c.sudo = r.data.sudo ?? "";
	return r;
}
async function signIn(c, username, password, secret, remember = false) {
	const t = await c.call("POST", "/login", { username, password });
	return c.call("POST", "/login/2fa", { ticket: t.data.ticket, code: totp(secret), remember });
}

const a = client(), b = client(), anon = client();
const suffix = Date.now().toString(36);
const userA = "op_" + suffix;

const noCode = await a.call("POST", "/signup", { username: userA, password: "long enough pw", totp_secret: "A".repeat(32), code: "000000" });
check("sign-up refused without a working 2FA code", noCode.status === 401);
const A = await signUp(a, userA);
check("operator A signs up (2FA confirmed)", A.ok);
const cookieA = a.setCookie.find((s) => s.startsWith("__Host-rgs=")) ?? "";
check("cookie is __Host-, HttpOnly, Secure, SameSite=Strict", /Path=\//.test(cookieA) && /HttpOnly/.test(cookieA) && /Secure/.test(cookieA) && /SameSite=Strict/.test(cookieA));
check("without Keep me signed in it's a browser-session cookie", !/Max-Age/.test(cookieA));
check("A is signed in", (await a.call("GET", "/me")).data.account?.username === userA);
const B = await signUp(b, "other_" + suffix, true);
check("operator B signs up with Keep me signed in", B.ok && /Max-Age=604800/.test(b.setCookie.find((s) => s.startsWith("__Host-rgs=")) ?? ""));
check("B's sign-in is kept", (await b.call("GET", "/me")).data.account?.remember === true);

// Sudo mode
const noSudo = await a.call("POST", "/servers", { name: "Test Mac mini" });
check("linking a server asks for sudo mode first", noSudo.status === 403 && noSudo.data.error === "sudo_required");
check("sudo refused with a wrong code", (await a.call("POST", "/sudo", { code: "000000" })).status === 401);
check("sudo mode with a 2FA code", (await sudo(a, A.secret)).status === 200 && !!a.sudo);
check("/me shows sudo mode", (await a.call("GET", "/me")).data.account?.sudo === true);
const added = await a.call("POST", "/servers", { name: "Test Mac mini" });
check("A links a server and gets a key", added.data.key?.startsWith("rgs_"));
const key = added.data.key;
const stolenSudo = client(); stolenSudo.cookie = b.cookie; stolenSudo.sudo = a.sudo;
check("A's sudo token doesn't work with B's sign-in", (await stolenSudo.call("POST", "/servers", { name: "x" })).data.error === "sudo_required");
const crossSite = await a.call("POST", "/servers", { name: "x" }, { Origin: "https://evil.example" });
check("requests from another website refused", crossSite.status === 403 && crossSite.data.error === "forbidden");

await sudo(b, B.secret);
check("B can't see A's server", (await b.call("GET", "/servers")).data.servers.length === 0);
check("B can't make a new key for it", (await b.call("POST", `/servers/${added.data.id}/key`)).status === 404);
check("B can't unlink it", (await b.call("DELETE", `/servers/${added.data.id}`)).status === 404);
check("signed-out visitors get nothing", (await anon.call("GET", "/servers")).status === 401);

check("heartbeat with a bad key refused", (await anon.call("POST", "/heartbeat", { version: "x" }, { Authorization: "Bearer rgs_wrong" })).status === 401);
const hb = await anon.call("POST", "/heartbeat", { version: "0.1.0", status: "online", accounts: 3, active_players: 1, open_reports: 2, games: ["Lanternfall 0.3"] }, { Authorization: "Bearer " + key });
check("heartbeat with the right key accepted", hb.status === 200);
const mine = (await a.call("GET", "/servers")).data.servers[0];
check("A sees it online with its report", mine.online && mine.report.accounts === 3 && mine.report.games[0] === "Lanternfall 0.3");

const rotated = await a.call("POST", `/servers/${added.data.id}/key`);
check("new key issued", rotated.data.key && rotated.data.key !== key);
check("old key stops working", (await anon.call("POST", "/heartbeat", {}, { Authorization: "Bearer " + key })).status === 401);

// Login flow: password, then 2FA.
const c = client();
const t = await c.call("POST", "/login", { username: userA, password: "long enough pw" });
check("login asks for 2FA", !!t.data.ticket && (await c.call("GET", "/servers")).status === 401);
check("login with 2FA works", (await c.call("POST", "/login/2fa", { ticket: t.data.ticket, code: totp(A.secret) })).status === 200 && (await c.call("GET", "/servers")).status === 200);

// A copied cookie used from another browser ends that sign-in.
const thief = client("other-browser/9.0"); thief.cookie = c.cookie;
check("copied cookie refused in another browser", (await thief.call("GET", "/servers")).status === 401);
check("...and that sign-in is ended", (await c.call("GET", "/servers")).status === 401);
const updated = client("test-browser/2.0"); updated.cookie = a.cookie;
check("a browser update (new version number) keeps the sign-in", (await updated.call("GET", "/servers")).status === 200);

// Changing the password ends the other sign-ins, but not this one.
const other = client();
await signIn(other, userA, "long enough pw", A.secret, true);
check("A signed in on a second browser", (await other.call("GET", "/servers")).status === 200);
const wrongPw = await a.call("POST", "/password", { current: "nope nope nope", password: "a new long password" });
check("password change needs the current password", wrongPw.status === 401);
const pw = await a.call("POST", "/password", { current: "long enough pw", password: "a new long password" });
check("password changed, other sign-in ended", pw.status === 200 && pw.data.signed_out_elsewhere >= 1);
check("this browser stays signed in (new cookie)", a.setCookie.some((s) => s.startsWith("__Host-rgs=") && !/Max-Age=0/.test(s)) && (await a.call("GET", "/servers")).status === 200);
check("the second browser is signed out", (await other.call("GET", "/servers")).status === 401);
check("old password no longer works", (await anon.call("POST", "/login", { username: userA, password: "long enough pw" })).status === 401);

// Changing 2FA does the same.
const other2 = client();
await signIn(other2, userA, "a new long password", A.secret);
const fresh = await a.call("POST", "/2fa/secret");
const newSecret = fresh.data.totp_secret;
check("2FA change refused with a code from the old app", (await a.call("POST", "/2fa", { totp_secret: newSecret, code: totp(A.secret, 5) })).status === 401);
const mfa = await a.call("POST", "/2fa", { totp_secret: newSecret, code: totp(newSecret) });
check("2FA switched, other sign-in ended", mfa.status === 200 && (await other2.call("GET", "/servers")).status === 401);
const old2fa = client(); const tk = await old2fa.call("POST", "/login", { username: userA, password: "a new long password" });
check("the old authenticator no longer signs in", (await old2fa.call("POST", "/login/2fa", { ticket: tk.data.ticket, code: totp(A.secret, 5) })).status === 401);

// Sign out everywhere (sudo mode survives a password change in this tab).
const other3 = client();
await signIn(other3, userA, "a new long password", newSecret);
check("sign out everywhere", (await a.call("POST", "/logout/all")).status === 200);
check("...ends this browser and the others", (await a.call("GET", "/servers")).status === 401 && (await other3.call("GET", "/servers")).status === 401);

for (const page of ["/rgs/", "/rgs/account/", "/rgs/sudo.js"]) check(`page ${page} served`, (await fetch(base + page)).status === 200);

if (process.env.KEY_OUT) fs.writeFileSync(process.env.KEY_OUT, rotated.data.key);
console.log(`\n${pass} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
