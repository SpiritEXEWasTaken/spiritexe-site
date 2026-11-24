// End-to-end check against a local `cf dev` with a fresh database:
//   cf dev --port 8787        (with .dev.vars holding SESSION_SECRET and SETUP_KEY)
//   node scripts/test-local.mjs local-test-setup-key
// Covers first-time setup with 2FA, login, beta keys, a chunked upload, release, and download.
import crypto from "node:crypto";

const base = process.env.SITE ?? "http://localhost:8787";
const setupKey = process.argv[2];
let cookie = "";
let pass = 0, failed = 0;

function check(name, ok) {
	console.log(`${ok ? "PASS" : "FAIL"}  ${name}`);
	ok ? pass++ : failed++;
}

async function call(method, path, body, raw) {
	const res = await fetch(base + path, {
		method,
		headers: { ...(raw ? {} : { "Content-Type": "application/json" }), ...(cookie ? { Cookie: cookie } : {}) },
		body: raw ?? (body ? JSON.stringify(body) : undefined),
	});
	const set = res.headers.get("set-cookie");
	if (set) cookie = set.split(";")[0];
	const text = await res.text();
	let data;
	try { data = JSON.parse(text); } catch { data = text; }
	return { status: res.status, data, res };
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

const st = await call("GET", "/api/admin/state");
check("fresh site needs setup", st.data.needs_setup === true);
check("wrong setup key refused", (await call("POST", "/api/admin/setup/secret", { setup_key: "nope" })).status === 403);
const sec = await call("POST", "/api/admin/setup/secret", { setup_key: setupKey, username: "boss" });
check("setup key gives a 2FA secret", !!sec.data.totp_secret);
const secret = sec.data.totp_secret;
check("wrong 2FA code refused at setup", (await call("POST", "/api/admin/setup", { setup_key: setupKey, username: "boss", password: "correct horse battery", totp_secret: secret, code: "000000" })).status === 401);
check("first admin created", (await call("POST", "/api/admin/setup", { setup_key: setupKey, username: "boss", password: "correct horse battery", totp_secret: secret, code: totp(secret) })).status === 200);
check("setup closed afterwards", (await call("POST", "/api/admin/setup/secret", { setup_key: setupKey })).status === 403);

check("admin API needs a login", (await call("GET", "/api/admin/keys")).status === 401);
check("wrong password refused", (await call("POST", "/api/admin/login", { username: "boss", password: "wrong" })).status === 401);
const t = await call("POST", "/api/admin/login", { username: "boss", password: "correct horse battery" });
check("password step gives a ticket", !!t.data.ticket);
check("password alone isn't enough", (await call("GET", "/api/admin/keys")).status === 401);
const l2 = await call("POST", "/api/admin/login/2fa", { ticket: t.data.ticket, code: totp(secret) });
check("2FA step signs in (cookie set)", l2.status === 200 && cookie.startsWith("spx_admin="));

const keys = await call("POST", "/api/admin/keys", { label: "test", max_uses: 2, count: 2 });
check("two beta keys created", keys.data.codes?.length === 2);
const [k1, k2] = keys.data.codes;

check("no build yet: unlock says so", (await call("POST", "/api/unlock", { code: k1 })).data.error === "no_build");

// A 3-piece upload, with a small chunk size faked by uploading a file just over 2 chunks? The
// server's chunk size is 20 MB, so use 45 MB of random data to get 3 pieces.
const file = crypto.randomBytes(45 * 1024 * 1024);
const up = await call("POST", "/api/admin/versions", { version: "0.3", notes: "Test notes", filename: "Lanternfall.apk", size: file.length });
check("upload started in 3 pieces", up.data.chunks === 3);
const cb = up.data.chunk_bytes;
for (let i = 0; i < up.data.chunks; i++) {
	const piece = file.subarray(i * cb, Math.min(file.length, (i + 1) * cb));
	const r = await call("PUT", `/api/admin/versions/${up.data.id}/chunks/${i}`, null, piece);
	check(`piece ${i + 1} uploaded`, r.status === 200);
}
check("released", (await call("POST", `/api/admin/versions/${up.data.id}/publish`)).status === 200);
const pub = await call("GET", "/api/versions");
check("public list shows 0.3 with notes", pub.data.versions?.[0]?.version === "0.3" && pub.data.versions[0].notes === "Test notes");

check("bad key refused", (await call("POST", "/api/unlock", { code: "LFNOTAREAL1" })).data.error === "invalid_key");
const un = await call("POST", "/api/unlock", { code: k1.toLowerCase().replace(/^lf/, "lf-") });
check("key works typed with dashes and lower case", !!un.data.url);
const dl = await fetch(base + un.data.url);
const got = Buffer.from(await dl.arrayBuffer());
check("download is the exact same file", got.length === file.length && crypto.createHash("sha256").update(got).digest("hex") === crypto.createHash("sha256").update(file).digest("hex"));
check("download has the right filename", (dl.headers.get("content-disposition") ?? "").includes("Lanternfall.apk"));
check("tampered link refused", (await fetch(base + un.data.url.replace(/.$/, "0"))).status === 403);

await call("POST", "/api/unlock", { code: k1 });
check("key stops after its 2 uses", (await call("POST", "/api/unlock", { code: k1 })).data.error === "key_used_up");
const list = await call("GET", "/api/admin/keys");
const k2id = list.data.keys.find((k) => k.code === k2).id;
await call("POST", `/api/admin/keys/${k2id}/revoke`);
check("revoked key refused", (await call("POST", "/api/unlock", { code: k2 })).data.error === "invalid_key");

check("delete version", (await call("DELETE", `/api/admin/versions/${up.data.id}`)).status === 200);
check("nothing to download after delete", (await call("GET", "/api/versions")).data.versions.length === 0);
await call("POST", "/api/admin/logout");
check("signed out", (await call("GET", "/api/admin/keys")).status === 401);

for (const page of ["/", "/admin/", "/style.css", "/fonts/Geist-Variable-latin.woff2", "/fonts/Unbounded-Variable-latin.woff2", "/favicon.svg", "/icons/pipevr.png"]) check(`page ${page} served`, (await fetch(base + page)).status === 200);
check("unknown page gets 404", (await fetch(base + "/nope")).status === 404);

console.log(`\n${pass} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
