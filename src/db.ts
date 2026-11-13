// The database layout. Tables are created on first use, so a fresh deploy needs no extra steps.

let ready = false;

export async function ensureSchema(db: D1Database): Promise<void> {
	if (ready) return;
	await db.batch([
		db.prepare(`CREATE TABLE IF NOT EXISTS admins (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE COLLATE NOCASE,
			password_hash TEXT NOT NULL,
			totp_secret TEXT NOT NULL,
			created_at INTEGER NOT NULL)`),
		db.prepare(`CREATE TABLE IF NOT EXISTS sessions (
			token_hash TEXT PRIMARY KEY,
			admin_id INTEGER NOT NULL,
			expires_at INTEGER NOT NULL)`),
		db.prepare(`CREATE TABLE IF NOT EXISTS pending_logins (
			ticket_hash TEXT PRIMARY KEY,
			admin_id INTEGER NOT NULL,
			expires_at INTEGER NOT NULL)`),
		db.prepare(`CREATE TABLE IF NOT EXISTS attempts (
			key TEXT PRIMARY KEY,
			count INTEGER NOT NULL,
			window_start INTEGER NOT NULL)`),
		// Beta keys: who it's for, how many times it can unlock a download (0 = no limit).
		db.prepare(`CREATE TABLE IF NOT EXISTS beta_keys (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			code TEXT NOT NULL UNIQUE,
			label TEXT NOT NULL DEFAULT '',
			max_uses INTEGER NOT NULL DEFAULT 0,
			uses INTEGER NOT NULL DEFAULT 0,
			revoked INTEGER NOT NULL DEFAULT 0,
			created_at INTEGER NOT NULL,
			last_used_at INTEGER)`),
		// Game builds. The file lives in KV as file:<id>:0, file:<id>:1, ...
		db.prepare(`CREATE TABLE IF NOT EXISTS versions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			game TEXT NOT NULL DEFAULT 'lanternfall',
			version TEXT NOT NULL,
			notes TEXT NOT NULL DEFAULT '',
			filename TEXT NOT NULL,
			size INTEGER NOT NULL,
			chunks INTEGER NOT NULL,
			uploaded INTEGER NOT NULL DEFAULT 0,
			published INTEGER NOT NULL DEFAULT 0,
			downloads INTEGER NOT NULL DEFAULT 0,
			created_at INTEGER NOT NULL,
			published_at INTEGER)`),
	]);
	ready = true;
}

/** Counts a try against `key`; false once there have been more than `max` in `windowSeconds`. */
export async function allow(db: D1Database, key: string, max: number, windowSeconds: number): Promise<boolean> {
	const t = Math.floor(Date.now() / 1000);
	const row = await db.prepare("SELECT count, window_start FROM attempts WHERE key = ?").bind(key).first<{ count: number; window_start: number }>();
	if (!row || t - row.window_start >= windowSeconds) {
		await db.prepare("INSERT INTO attempts (key, count, window_start) VALUES (?, 1, ?) ON CONFLICT(key) DO UPDATE SET count = 1, window_start = excluded.window_start").bind(key, t).run();
		return true;
	}
	await db.prepare("UPDATE attempts SET count = count + 1 WHERE key = ?").bind(key).run();
	return row.count + 1 <= max;
}
