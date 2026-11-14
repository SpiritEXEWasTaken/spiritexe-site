// Uploads and publishes a Lanternfall build, and/or makes beta keys, straight to the live site's
// D1 database and KV storage with the cf CLI's sign-in (no admin page login needed).
//
//   node scripts/publish-build.mjs --apk <path> --version 0.3 [--notes "..."]
//   node scripts/publish-build.mjs --new-key [--label "..."] [--max-uses 0]
//
// New keys are written to .secrets/beta-keys.txt (gitignored), never printed.
import { readFileSync, appendFileSync, mkdirSync, statSync, openSync, readSync, closeSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { randomInt } from "node:crypto";

const CHUNK_BYTES = 20 * 1024 * 1024; // must match src/admin.ts
const root = fileURLToPath(new URL("..", import.meta.url));

const args = process.argv.slice(2);
const opt = (name) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined; };
const flag = (name) => args.includes(name);

function cfToken() {
	const file = join(process.env.APPDATA, "xdg.config", "cloudflare", "config", "default.json");
	const cfg = JSON.parse(readFileSync(file, "utf8"));
	for (const k of ["oauth_token", "access_token", "token", "api_token"]) if (typeof cfg[k] === "string") return cfg[k];
	for (const v of Object.values(cfg)) if (v && typeof v === "object" && typeof v.access_token === "string") return v.access_token;
	throw new Error("Couldn't find the cf sign-in. Run `cf auth login` first.");
}
const token = cfToken();
const API = "https://api.cloudflare.com/client/v4";

async function cf(path, init = {}) {
	const res = await fetch(API + path, { ...init, headers: { Authorization: `Bearer ${token}`, ...(init.headers ?? {}) } });
	const data = await res.json().catch(() => ({}));
	if (!res.ok || data.success === false) throw new Error(`${init.method ?? "GET"} ${path}: ${res.status} ${JSON.stringify(data.errors ?? data)}`);
	return data.result;
}

const account = (await cf("/accounts"))[0].id;
const db = (await cf(`/accounts/${account}/d1/database?name=spiritexe-site`)).find((d) => d.name === "spiritexe-site");
if (!db) throw new Error("No D1 database named spiritexe-site.");

async function sql(query, params = []) {
	const result = await cf(`/accounts/${account}/d1/database/${db.uuid}/query`, {
		method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ sql: query, params }),
	});
	return result[0].results;
}

// The Worker's KV binding: read it from the deployed Worker's settings.
async function kvNamespace() {
	const settings = await cf(`/accounts/${account}/workers/scripts/spiritexe-site/settings`);
	const b = settings.bindings.find((x) => x.name === "FILES" && x.type === "kv_namespace");
	if (!b) throw new Error("The spiritexe-site Worker has no FILES binding.");
	return b.namespace_id;
}

const now = () => Math.floor(Date.now() / 1000);

if (flag("--new-key")) {
	const alphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"; // same as src/admin.ts
	let chars = "";
	for (let i = 0; i < 8; i++) chars += alphabet[randomInt(alphabet.length)];
	const code = "LF" + chars;
	const label = (opt("--label") ?? "").slice(0, 80);
	await sql("INSERT INTO beta_keys (code, label, max_uses, created_at) VALUES (?, ?, ?, ?)", [code, label, Number(opt("--max-uses") ?? 0), now()]);
	mkdirSync(join(root, ".secrets"), { recursive: true });
	const pretty = `${code.slice(0, 2)}-${code.slice(2, 6)}-${code.slice(6)}`;
	appendFileSync(join(root, ".secrets", "beta-keys.txt"), `${pretty}  ${label}  (made ${new Date().toISOString()})\n`);
	console.log("Made a beta key; it's in .secrets/beta-keys.txt");
}

const apk = opt("--apk");
if (apk) {
	const version = opt("--version");
	if (!version || !/^[0-9A-Za-z.\-]{1,20}$/.test(version)) throw new Error("Give --version like 0.3.");
	const size = statSync(apk).size;
	const chunks = Math.ceil(size / CHUNK_BYTES);
	const ns = await kvNamespace();
	const [{ id }] = await sql(
		"INSERT INTO versions (version, notes, filename, size, chunks, created_at) VALUES (?, ?, ?, ?, ?, ?) RETURNING id",
		[version, (opt("--notes") ?? "").slice(0, 4000), `Lanternfall-${version}.apk`, size, chunks, now()],
	);
	console.log(`Version row ${id}: ${(size / 1048576).toFixed(1)} MB in ${chunks} pieces`);
	const fd = openSync(apk, "r");
	for (let n = 0; n < chunks; n++) {
		const len = Math.min(CHUNK_BYTES, size - n * CHUNK_BYTES);
		const buf = Buffer.alloc(len);
		readSync(fd, buf, 0, len, n * CHUNK_BYTES);
		await cf(`/accounts/${account}/storage/kv/namespaces/${ns}/values/${encodeURIComponent(`file:${id}:${n}`)}`, {
			method: "PUT", headers: { "content-type": "application/octet-stream" }, body: buf,
		});
		await sql("UPDATE versions SET uploaded = uploaded + 1 WHERE id = ?", [id]);
		console.log(`  piece ${n + 1}/${chunks} uploaded`);
	}
	closeSync(fd);
	await sql("UPDATE versions SET published = 1, published_at = ? WHERE id = ?", [now(), id]);
	console.log(`Published Lanternfall ${version}`);
}
