# Aero server (free: Cloudflare Workers + D1)

One deploy hosts both the **website** (`site/`) and the **API** (`src/worker.js`).

| Route | What |
|---|---|
| `/` | Website: downloads, Discord, live counters (totals only, no player data) |
| `GET /api/stats` | `{online, total}` (cached 15 s) |
| `GET /api/users` | List of active Aero users + cosmetics, same shape as the old `users.json` (cached 60 s) |
| `GET /api/version` | Latest mod and launcher release from GitHub |
| `GET /download/mod`, `/download/launcher` | Redirect to the latest release asset |
| `POST /api/auth/start`, `/api/auth/finish` | Mojang session-server login (mod side) |
| `POST /api/heartbeat` | Mod sends equipped cosmetics every minute (needs token) |
| `DELETE /api/me` | Delete own data (needs token) |

## Deploy (once, about 10 minutes)

You need Node.js and a free Cloudflare account (no card).

```bash
cd aero-server
npm install
npx wrangler login
npx wrangler d1 create aero
```

Copy the `database_id` from the output into `wrangler.toml` (replace the `0000…` placeholder), then:

```bash
npm run db:init
npx wrangler secret put TOKEN_SECRET -c wrangler.toml   # paste a long random string, e.g. from https://generate-secret.vercel.app/48
npm run deploy
```

The deploy prints your address, like `https://aero-client.<your-name>.workers.dev`.

> Note: the `-c wrangler.toml` flag is needed because the parent folder has another `wrangler.jsonc`; the npm scripts already include it.

## Connect the mod

In the game: module **Client Badge** -> **Server URL** -> paste your address. (Or set `apiBase` in the client config.)
Players who leave **Share profile online** on appear in `/api/users` and everyone else sees their cosmetics.

## Downloads and auto-update

`/download/mod` and `/download/launcher` redirect to the newest GitHub release of
`KingF3rdi/aero-client` (asset `.jar`) and `KingF3rdi/aero-client-launcher` (asset `.exe`).
Publish a release there to update everyone. Repos are set in `wrangler.toml` (`MOD_REPO`, `LAUNCHER_REPO`).

## Limits of the free tier

Workers: 100,000 requests/day. The mod sends one heartbeat per minute per player and reads the user list every 10 minutes (cached at the edge), so roughly 60-70 simultaneous players fit. Beyond that, Workers Paid is $5/month.

## Local test

```bash
npm run db:init:local
echo TOKEN_SECRET=dev-secret > .dev.vars
npm run dev      # http://localhost:8787
```
