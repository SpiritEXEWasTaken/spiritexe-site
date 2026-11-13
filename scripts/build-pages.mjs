// Builds pages/dist for the spiritexe.pages.dev front: the same pages as public/, plus a
// small _worker.js that hands API, RGS API and relay requests to the main Worker
// (service binding BACKEND, set on the Pages project) and serves everything else.
import { cpSync, rmSync, mkdirSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const out = root + "pages/dist";

rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });
cpSync(root + "public", out, { recursive: true });

writeFileSync(out + "/_worker.js", `const BACKEND_PATHS = ["/api/", "/rgs/api/", "/rgs/s/"];

export default {
  async fetch(request, env) {
    const path = new URL(request.url).pathname;
    if (BACKEND_PATHS.some((p) => path.startsWith(p))) return env.BACKEND.fetch(request);
    return env.ASSETS.fetch(request);
  },
};
`);

console.log("Built " + out);
