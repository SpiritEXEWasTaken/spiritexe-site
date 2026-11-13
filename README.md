# SpiritEXE site

The SpiritEXE website, on Cloudflare Workers (free plan): the studio page, the Lanternfall beta
download (unlocked with a beta key), the admin page for releasing versions and making beta keys,
and the RGS pages under `/rgs`.

- `public/`: the pages (static files).
- `src/`: the Worker behind `/api/*` (downloads, admin) and `/rgs/api/*` (RGS accounts and servers).
- Builds are stored in Workers KV in 20 MB pieces; everything else is in D1.

## Run it locally

Needs Node.js 22.18+ and Cloudflare's `cf` CLI (`npm install -g cf`).

1. Create `.dev.vars` with `SESSION_SECRET=<random>` and `SETUP_KEY=<anything>`.
2. `cf dev --port 8787`
3. Tests: `node scripts/test-local.mjs <SETUP_KEY>` and `node scripts/test-rgs.mjs`
   (both against a fresh local database).

## Deploy

`cf deploy --secrets-file .secrets/production.json`, where that file (never committed) holds
`SESSION_SECRET` and `SETUP_KEY`. The first admin is created at `/admin` with the setup key.

The public address is **https://spiritexe.pages.dev**, a Cloudflare Pages project (`spiritexe`)
in front of the Worker: it serves the same pages, and a small `_worker.js` passes `/api/*`,
`/rgs/api/*` and `/rgs/s/*` to the Worker through a service binding (`BACKEND`, set on the
Pages project). After changing anything in `public/`, update it too:

`powershell -ExecutionPolicy Bypass -File scripts\deploy-pages.ps1`

(builds `pages/dist` with `scripts/build-pages.mjs` and deploys it with Wrangler, reusing the
`cf` sign-in). The Worker's own address, spiritexe-site.spiritexe.workers.dev, keeps working.
