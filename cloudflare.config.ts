import { bindings, defineConfig, exports } from "cf/config";
import * as entrypoint from "./src/index.ts" with { type: "cf-worker" };

// The SpiritEXE site: static pages from public/, plus a Worker for /api/* (beta keys, game
// builds, admin login) and /rgs/* (RGS accounts, and the relay that reaches RGS servers).
export default defineConfig({
	worker: {
		name: "spiritexe-site",
		compatibilityDate: "2026-11-13",
		entrypoint,
		assets: {
			notFoundHandling: "404-page",
			runWorkerFirst: ["/api/*", "/rgs/api/*", "/rgs/s/*"],
		},
		exports: {
			// One per linked RGS server: holds the server's connection and passes requests down it.
			ServerLink: exports.durableObject({ storage: "sqlite" }),
		},
		env: {
			// Beta keys, versions, admins, sessions and login attempts.
			DB: bindings.d1({ name: "spiritexe-site" }),
			// The game builds themselves, stored in chunks (KV values are capped at 25 MB).
			FILES: bindings.kv(),
			LINKS: bindings.durableObject({ worker: "spiritexe-site", exportName: "ServerLink" }),
			// Signs admin sessions and download links.
			SESSION_SECRET: bindings.secret(),
			// One-time key to create the first admin account.
			SETUP_KEY: bindings.secret(),
		},
	},
});
