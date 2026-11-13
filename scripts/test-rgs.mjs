// Checks the RGS hub against a local `cf dev`: operator sign-up with required 2FA, linking a
// server, its heartbeat, and that one account can't see or touch another account's servers.
//   node scripts/test-rgs.mjs            (server key is printed to scratch for the live test)
import crypto from "node:crypto";
import fs from "node:fs";

const base = process.env.SITE ?? "http://localhost:8787";
let pass = 0, failed = 0;
const check = (name, ok) => { console.log(`${ok ? "PASS" : "FAIL"}  ${name}`); ok ? pass++ : failed++; };

function client() {
	let cookie = "";
	return async (method, path, body, headers = {}) => {
		const res = await fetch(base + "/rgs/api" + path, {
			method,
			headers: { "Content-Type": "application/json", ...(cookie ? { Cookie: cookie } : {}), ...headers },
			body: body ? JSON.stringify(body) : undefined,
		});
		const set = res.headers.get("set-cookie");
		if (set) cookie = set.split(";")[0];
		return { status: res.status, data: await res.json().catch(() => ({})) };
	};
}

function totp(secret) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
	let bits = "";
	for (const c of secret) bits += alphabet.indexOf(c).toString(2).padStart(5, "0");
	const key = Buffer.from(bits.match(/.{8}/g).map((b) => parseInt(b, 2)));
	const msg = Buffer.alloc(8);
	msg.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)));
	const h = crypto.createHmac("sha1", key).update(msg).digest();
	const o = h[19] & 0xf;
	return (((h[o] & 0x7f) << 24 | h[o + 1] << 16 | h[o + 2] << 8 | h[o + 3]) % 1e6).toString().padStart(6, "0");
}

async function signUp(call, username) {
	const s = await call("POST", "/signup/secret", { username });
	const r = await call("POST", "/signup", { username, password: "long enough pw", totp_secret: s.data.totp_secret, code: totp(s.data.totp_secret) });
	return { ok: r.status === 200, secret: s.data.totp_secret };
}

const a = client(), b = client(), anon = client();
const suffix = Date.now().toString(36);

const noCode = await a("POST", "/signup", { username: "op_" + suffix, password: "long enough pw", totp_secret: "A".repeat(32), code: "000000" });
check("sign-up refused without a working 2FA code", noCode.status === 401);
const A = await signUp(a, "op_" + suffix);
check("operator A signs up (2FA confirmed)", A.ok);
check("A is signed in", (await a("GET", "/me")).data.account?.username === "op_" + suffix);
const B = await signUp(b, "other_" + suffix);
check("operator B signs up", B.ok);

const added = await a("POST", "/servers", { name: "Test Mac mini" });
check("A links a server and gets a key", added.data.key?.startsWith("rgs_"));
const key = added.data.key;

check("B can't see A's server", (await b("GET", "/servers")).data.servers.length === 0);
check("B can't make a new key for it", (await b("POST", `/servers/${added.data.id}/key`)).status === 404);
check("B can't unlink it", (await b("DELETE", `/servers/${added.data.id}`)).status === 404);
check("signed-out visitors get nothing", (await anon("GET", "/servers")).status === 401);

check("heartbeat with a bad key refused", (await anon("POST", "/heartbeat", { version: "x" }, { Authorization: "Bearer rgs_wrong" })).status === 401);
const hb = await anon("POST", "/heartbeat", { version: "0.1.0", status: "online", accounts: 3, active_players: 1, open_reports: 2, games: ["Lanternfall 0.3"] }, { Authorization: "Bearer " + key });
check("heartbeat with the right key accepted", hb.status === 200);
const mine = (await a("GET", "/servers")).data.servers[0];
check("A sees it online with its report", mine.online && mine.report.accounts === 3 && mine.report.games[0] === "Lanternfall 0.3");

const rotated = await a("POST", `/servers/${added.data.id}/key`);
check("new key issued", rotated.data.key && rotated.data.key !== key);
check("old key stops working", (await anon("POST", "/heartbeat", {}, { Authorization: "Bearer " + key })).status === 401);

// Login flow: password, then 2FA.
const c = client();
const t = await c("POST", "/login", { username: "op_" + suffix, password: "long enough pw" });
check("login asks for 2FA", !!t.data.ticket && (await c("GET", "/servers")).status === 401);
check("login with 2FA works", (await c("POST", "/login/2fa", { ticket: t.data.ticket, code: totp(A.secret) })).status === 200 && (await c("GET", "/servers")).status === 200);

for (const page of ["/rgs/", "/rgs/account/"]) check(`page ${page} served`, (await fetch(base + page)).status === 200);

if (process.env.KEY_OUT) fs.writeFileSync(process.env.KEY_OUT, rotated.data.key);
console.log(`\n${pass} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
