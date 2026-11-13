import { DurableObject } from "cloudflare:workers";

// The relay to RGS servers. A linked RGS server keeps one WebSocket open to its ServerLink
// (it connects out, so nothing has to be opened on its network and its address stays private).
// Requests to /rgs/s/<server>/api/v1/... are sent down that socket and the server's answer comes
// back the same way. The admin panel, the player page and games all use this, from anywhere.

const TIMEOUT_MS = 25_000;
const MAX_BODY = 900 * 1024;

type Pending = { resolve: (r: Response) => void; timer: ReturnType<typeof setTimeout> };

function offline(): Response {
	return Response.json(
		{ error: "server_offline", message: "That RGS server isn't connected right now. Try again in a minute." },
		{ status: 503, headers: { "Cache-Control": "no-store" } },
	);
}

function b64(bytes: ArrayBuffer): string {
	let s = "";
	const u = new Uint8Array(bytes);
	for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode(...u.subarray(i, i + 0x8000));
	return btoa(s);
}

function unb64(s: string): Uint8Array {
	const bin = atob(s);
	const out = new Uint8Array(bin.length);
	for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
	return out;
}

export class ServerLink extends DurableObject<Env> {
	pending = new Map<string, Pending>();

	async fetch(request: Request): Promise<Response> {
		// The RGS server connecting (already checked by the Worker). A new connection replaces the old.
		if (request.headers.get("Upgrade") === "websocket") {
			for (const old of this.ctx.getWebSockets()) old.close(1000, "replaced by a new connection");
			const pair = new WebSocketPair();
			this.ctx.acceptWebSocket(pair[1]);
			return new Response(null, { status: 101, webSocket: pair[0] });
		}

		// A request for the server.
		const socket = this.ctx.getWebSockets()[0];
		if (!socket) return offline();
		const body = request.method === "GET" || request.method === "HEAD" ? null : await request.arrayBuffer();
		if (body && body.byteLength > MAX_BODY) return Response.json({ error: "bad_request", message: "That request is too big." }, { status: 413 });

		const url = new URL(request.url);
		const headers: Record<string, string> = {};
		for (const name of ["authorization", "content-type", "x-game-id", "x-game-version"]) {
			const v = request.headers.get(name);
			if (v) headers[name] = v;
		}
		const id = crypto.randomUUID();
		const msg = {
			t: "req",
			id,
			method: request.method,
			path: url.pathname + url.search,
			headers,
			client_ip: request.headers.get("x-rgs-client-ip") ?? "",
			body: body ? b64(body) : null,
		};

		return new Promise<Response>((resolve) => {
			const timer = setTimeout(() => {
				this.pending.delete(id);
				resolve(Response.json({ error: "server_timeout", message: "The RGS server took too long to answer." }, { status: 504 }));
			}, TIMEOUT_MS);
			this.pending.set(id, { resolve, timer });
			try {
				socket.send(JSON.stringify(msg));
			} catch {
				clearTimeout(timer);
				this.pending.delete(id);
				resolve(offline());
			}
		});
	}

	async webSocketMessage(ws: WebSocket, data: string | ArrayBuffer): Promise<void> {
		let msg: { t?: string; id?: string; status?: number; content_type?: string; body?: string | null };
		try {
			msg = JSON.parse(typeof data === "string" ? data : new TextDecoder().decode(data));
		} catch {
			return;
		}
		if (msg.t === "ping") {
			ws.send(JSON.stringify({ t: "pong" }));
			return;
		}
		if (msg.t !== "res" || !msg.id) return;
		const p = this.pending.get(msg.id);
		if (!p) return;
		clearTimeout(p.timer);
		this.pending.delete(msg.id);
		p.resolve(new Response(msg.body ? unb64(msg.body) : null, {
			status: msg.status ?? 502,
			headers: { "Content-Type": msg.content_type ?? "application/json", "Cache-Control": "no-store" },
		}));
	}

	async webSocketClose(ws: WebSocket, code: number): Promise<void> {
		ws.close(code === 1005 ? 1000 : code, "closing");
	}
}
