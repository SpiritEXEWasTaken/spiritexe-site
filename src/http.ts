// Small helpers for JSON responses and errors. Errors look like RGS's:
// { "error": "<code>", "message": "<text to show a person>" }.

export function json(body: unknown, status = 200, headers: HeadersInit = {}): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...headers },
	});
}

export function fail(status: number, error: string, message: string): Response {
	return json({ error, message }, status);
}

export async function body<T>(request: Request): Promise<T> {
	try {
		return (await request.json()) as T;
	} catch {
		return {} as T;
	}
}

export function now(): number {
	return Math.floor(Date.now() / 1000);
}

/** A hash of the visitor's IP, only for rate limiting; the raw address is never stored. */
export async function ipHash(request: Request, secret: string): Promise<string> {
	const ip = request.headers.get("CF-Connecting-IP") ?? "unknown";
	return (await hmacHex(secret, "ip:" + ip)).slice(0, 32);
}

export async function hmacHex(secret: string, value: string): Promise<string> {
	const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
	const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value));
	return hex(new Uint8Array(sig));
}

export function hex(bytes: Uint8Array): string {
	return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function randomToken(bytes = 32): string {
	const b = crypto.getRandomValues(new Uint8Array(bytes));
	return btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Compares two strings in constant time. */
export function safeEqual(a: string, b: string): boolean {
	if (a.length !== b.length) return false;
	let diff = 0;
	for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
	return diff === 0;
}
