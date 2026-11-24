# SpiritEXE site

The SpiritEXE website, on Cloudflare Workers (free plan): the studio page, the Lanternfall beta
download (unlocked with a beta key), the admin page for releasing versions and making beta keys,
and the RGS pages under `/rgs`.

- `public/`: the pages (static files).
- `src/`: the Worker behind `/api/*` (downloads, admin) and `/rgs/api/*` (RGS accounts and servers).
- Builds are stored in Workers KV in 20 MB pieces; everything else is in D1.

## Look and feel

Everything is styled by `public/style.css`: a light grey page, one colour per project
(`--lanternfall`, `--pipevr`, `--jellyvr`, `--cleanmyvr`, `--rgs`), Unbounded for headings and
Geist for text. Both fonts are free (SIL OFL) and served from `public/fonts/`, so the site makes no
calls to Google.

**Project icons.** A project with its own icon uses an image; the others show a coloured tile with
their first letter. To add an icon, put a square PNG (at least 128×128) in `public/icons/`, then in
`public/index.html` replace that project's `<span class="icon ...">X</span>` (in the app library
at the top, and again in its section further down) with
`<img class="icon" src="/icons/<name>.png" width="128" height="128" alt="">`, like PipeVR's.
Icons are drawn with sharp pixels (`image-rendering: pixelated`), which suits pixel art.

**A new project** is one more `<li>` in the app library list and one more `<article class="project p-...">`
in "Other projects"; give it a colour in `:root` and a `.p-<name>` class in `style.css`.

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
