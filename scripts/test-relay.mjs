// Checks the relay end to end: an operator links a server, a real RGS server connects out to
// the site with that key, and its API (status, sign-up, 2FA, admin) answers through
// /rgs/s/<id>/api/v1. Needs `cf dev --port 8787` and an RGS build; starts its own RGS.
//   node scripts/test-relay.mjs <path to rgs-server executable> <empty scratch folder>
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";

const site = process.env.SITE ?? "http://localhost:8787";
const [exe, dir] = process.argv.slice(2);
let pass = 0, failed = 0;
const check = (name, ok) => { console.log(`${ok ? "PASS" : "FAIL"}  ${name}`); ok ? pass++ : failed++; };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function totp(secret) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
	let bits = "";
	for (const c of secret.replace(/=+$/, "")) bits += alphabet.indexOf(c).toString(2).padStart(5, "0");
	const key = Buffer.from(bits.match(/.{8}/g).map((b) => parseInt(b, 2)));
	const msg = Buffer.alloc(8);
	msg.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)));
	const h = crypto.createHmac("sha1", key).update(msg).digest();
	const o = h[19] & 0xf;
	return (((h[o] & 0x7f) << 24 | h[o + 1] << 16 | h[o + 2] << 8 | h[o + 3]) % 1e6).toString().padStart(6, "0");
}

// Operator signs up on the site and links a server.
let cookie = "";
async function hub(method, p, body) {
	const res = await fetch(site + "/rgs/api" + p, { method, headers: { "Content-Type": "application/json", ...(cookie ? { Cookie: cookie } : {}) }, body: body ? JSON.stringify(body) : undefined });
	const set = res.headers.get("set-cookie");
	if (set) cookie = set.split(";")[0];
	return res.json();
}
const name = "relay_" + Date.now().toString(36);
const s = await hub("POST", "/signup/secret", { username: name });
await hub("POST", "/signup", { username: name, password: "long enough pw", totp_secret: s.totp_secret, code: totp(s.totp_secret) });
const linked = await hub("POST", "/servers", { name: "Relay test" });
check("server linked", !!linked.key);
const api = `${site}/rgs/s/${linked.id}/api/v1`;

check("offline server gives a clear error", (await (await fetch(api + "/status")).json()).error === "server_offline");

// Start a real RGS server with that key; it connects out to the site.
fs.mkdirSync(dir, { recursive: true });
fs.writeFileSync(path.join(dir, "rgs.toml"), `listen = "127.0.0.1:8653"\nhub_url = "${site}/rgs/api"\nhub_key = "${linked.key}"\n[[games]]\nid = "lanternfall"\nname = "Lanternfall"\nlatest_version = "0.3"\nmin_version = "0.3"\n`);
const rgs = spawn(exe, [], { env: { ...process.env, RGS_CONFIG: path.join(dir, "rgs.toml"), RGS_DATA_DIR: dir }, stdio: "ignore" });
let status;
for (let i = 0; i < 40; i++) {
	await sleep(500);
	status = await (await fetch(api + "/status")).json();
	if (status.status) break;
}
check("status answers through the relay", status.status === "online" && status.games?.[0]?.id === "lanternfall");

const call = async (method, p, body, token, headers = {}) => {
	const res = await fetch(api + p, { method, headers: { "Content-Type": "application/json", ...(token ? { Authorization: "Bearer " + token } : {}), ...headers }, body: body ? JSON.stringify(body) : undefined });
	return { status: res.status, data: await res.json().catch(() => ({})) };
};
const owner = await call("POST", "/auth/register", { username: "owner1", password: "correct horse" });
check("first account on the server becomes owner (via relay)", owner.data.account?.role === "owner");
const setup = await call("POST", "/auth/2fa/setup", null, owner.data.token);
await call("POST", "/auth/2fa/confirm", { code: totp(setup.data.secret) }, owner.data.token);
const t = await call("POST", "/auth/login", { username: "owner1", password: "correct horse", admin: true });
const a = await call("POST", "/auth/login/2fa", { ticket: t.data.ticket, code: totp(setup.data.secret) });
check("admin panel login with 2FA through the relay", !!a.data.token);
const stats = await call("GET", "/admin/stats", null, a.data.token);
check("admin API works through the relay", stats.status === 200 && stats.data.accounts === 1);
const old = await call("GET", "/auth/me", null, owner.data.token, { "X-Game-Id": "lanternfall", "X-Game-Version": "0.2" });
check("old game version still told to update", old.data.error === "update_required");
const dev = await call("POST", "/device/start", { device_name: "Quest 3" });
check("headset sign-in code through the relay", /^[A-Z2-9]{3}-[A-Z2-9]{3}$/.test(dev.data.user_code ?? ""));
let limited = false;
for (let i = 0; i < 12 && !limited; i++) limited = (await call("POST", "/auth/login", { username: "nobody", password: "x" })).status === 429;
check("rate limiting still sees separate visitors", limited);
check("relay can't reach anything but the API", (await fetch(`${site}/rgs/s/${linked.id}/admin`)).status !== 200);

rgs.kill();
for (const p of ["/rgs/", "/rgs/servers/", `/rgs/admin/?server=${linked.id}`, `/rgs/account/?server=${linked.id}`]) check(`page ${p} served`, (await fetch(site + p)).status === 200);

console.log(`\n${pass} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
