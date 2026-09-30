// Aero Client backend: player/cosmetic data, live counters and download redirects.
// Auth: the mod proves who it is with Mojang's session server (joinServer -> hasJoined), then gets a signed token.

const ONLINE_MS = 3 * 60 * 1000; // "in game" = heartbeat within 3 minutes
const ACTIVE_MS = 7 * 24 * 60 * 60 * 1000; // listed for other players for 7 days after the last heartbeat
const TOKEN_MS = 24 * 60 * 60 * 1000;
const NONCE_MS = 3 * 60 * 1000;
const ID_RE = /^[a-z0-9_]{1,24}$/;
const COSMETIC_KINDS = ["cape", "wings", "head", "pet", "shield", "trail", "kill", "mace", "emote", "tag"];

const json = (data, status = 200, extra = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store", ...extra },
  });

const enc = new TextEncoder();
const b64url = (buf) =>
  btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");

async function hmac(secret, data) {
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return crypto.subtle.sign("HMAC", key, enc.encode(data));
}

function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

const dash = (u) => `${u.slice(0, 8)}-${u.slice(8, 12)}-${u.slice(12, 16)}-${u.slice(16, 20)}-${u.slice(20)}`;

async function makeToken(env, uuid, name, guest = false) {
  const body = b64url(enc.encode(JSON.stringify({ u: uuid, n: name, g: guest ? 1 : 0, e: Date.now() + TOKEN_MS })));
  return `${body}.${b64url(await hmac(env.TOKEN_SECRET, body))}`;
}

async function readToken(env, request) {
  const h = request.headers.get("authorization") || "";
  const t = h.startsWith("Bearer ") ? h.slice(7) : "";
  const [body, sig] = t.split(".");
  if (!body || !sig) return null;
  if (!safeEqual(sig, b64url(await hmac(env.TOKEN_SECRET, body)))) return null;
  try {
    const data = JSON.parse(atob(body.replace(/-/g, "+").replace(/_/g, "/")));
    return data.e > Date.now() ? data : null;
  } catch {
    return null;
  }
}

/** Cloudflare edge cache so the free D1 quota survives many clients polling. */
async function cached(request, ctx, seconds, produce) {
  const cache = caches.default;
  const key = new Request(new URL(request.url).toString(), { method: "GET" });
  const hit = await cache.match(key);
  if (hit) return hit;
  const res = await produce();
  const out = new Response(res.body, res);
  out.headers.set("cache-control", `public, max-age=${seconds}`);
  out.headers.set("access-control-allow-origin", "*"); // public, read-only data; the launcher webview reads it
  if (res.status === 200) ctx.waitUntil(cache.put(key, out.clone())); // never cache a failure for everyone
  return out;
}

async function latestRelease(repo) {
  const r = await fetch(`https://api.github.com/repos/${repo}/releases/latest`, {
    headers: { "user-agent": "aero-client-server", accept: "application/vnd.github+json" },
  });
  if (r.status === 404) return null; // no release yet
  if (!r.ok) return { failed: true, assets: [] }; // e.g. GitHub rate limit for shared Cloudflare IPs
  const rel = await r.json();
  return { version: rel.tag_name, assets: rel.assets || [] };
}

/**
 * Newest stable launcher .exe across recent releases. The repo is shared with the mod, so the "latest"
 * release is usually a mod release without an exe; the launcher ships in its own (non-latest) releases.
 */
async function latestLauncherExe(repo) {
  const r = await fetch(`https://api.github.com/repos/${repo}/releases?per_page=30`, {
    headers: { "user-agent": "aero-client-server", accept: "application/vnd.github+json" },
  });
  if (!r.ok) return { failed: true };
  const exes = (await r.json())
    .filter((x) => !x.draft && !x.prerelease)
    .flatMap((x) => (x.assets || []).map((a) => ({ ...a, tag: x.tag_name })))
    .filter((a) => a.name.toLowerCase().endsWith(".exe"))
    .sort((a, b) => (b.updated_at || "").localeCompare(a.updated_at || ""));
  return { asset: exes[0] || null };
}

/** Newest pre-release (Preview channel); GitHub's /releases/latest skips these. */
async function latestPreview(repo) {
  const headers = { "user-agent": "aero-client-server", accept: "application/vnd.github+json" };
  // The rolling "preview" tag first (the release list is sorted by commit date and can push it far down).
  const t = await fetch(`https://api.github.com/repos/${repo}/releases/tags/preview`, { headers });
  if (t.ok) {
    const rel = await t.json();
    return { version: rel.tag_name, assets: rel.assets || [] };
  }
  const r = await fetch(`https://api.github.com/repos/${repo}/releases?per_page=100`, { headers });
  if (!r.ok) return null;
  const rel = (await r.json()).find((x) => x.prerelease && !x.draft);
  return rel ? { version: rel.tag_name, assets: rel.assets || [] } : null;
}

/**
 * Last known-good answers from GitHub, kept in D1. The unauthenticated GitHub API rate-limits
 * Cloudflare's shared addresses now and then; downloads and /api/version then use what was seen last.
 */
async function remember(env, key, value) {
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL)").run();
  if (value === undefined) return (await env.DB.prepare("SELECT v FROM meta WHERE k = ?").bind(key).first())?.v || null;
  await env.DB.prepare("INSERT INTO meta (k, v) VALUES (?1, ?2) ON CONFLICT(k) DO UPDATE SET v = ?2").bind(key, value).run();
  return value;
}

/** {tag, url} of the newest launcher exe: fresh from GitHub, else the last one seen; null if never seen. */
async function launcherNow(env) {
  const found = await latestLauncherExe(env.LAUNCHER_REPO);
  if (found.asset) {
    const v = { tag: found.asset.tag, url: found.asset.browser_download_url };
    await remember(env, "launcher", JSON.stringify(v));
    return v;
  }
  return found.failed ? JSON.parse((await remember(env, "launcher")) || "null") : null;
}

let schemaReady = false;
/** Adds the "verified" column on first use (guests = no valid Mojang session, e.g. offline accounts). */
async function ensureSchema(env) {
  if (schemaReady) return;
  try {
    await env.DB.prepare("ALTER TABLE users ADD COLUMN verified INTEGER NOT NULL DEFAULT 1").run();
  } catch {} // already there
  schemaReady = true;
}

let downloadsReady = false;
/** Download counter table is created on first use, so no manual SQL is needed. */
async function ensureDownloads(env) {
  if (downloadsReady) return;
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS downloads (kind TEXT PRIMARY KEY, n INTEGER NOT NULL DEFAULT 0)").run();
  downloadsReady = true;
}

async function countDownload(env, kind) {
  try {
    await ensureDownloads(env);
    await env.DB.prepare("INSERT INTO downloads (kind, n) VALUES (?1, 1) ON CONFLICT(kind) DO UPDATE SET n = n + 1").bind(kind).run();
  } catch {}
}

const CAPE_MAX_BYTES = 8192;
const CAPE_LIMIT_PER_PLAYER = 5;

let capesReady = false;
/** Custom capes table is created on first use, so no manual SQL is needed. */
async function ensureCapes(env) {
  if (capesReady) return;
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS capes (
       id INTEGER PRIMARY KEY AUTOINCREMENT,
       owner_uuid TEXT NOT NULL,
       owner_name TEXT NOT NULL,
       name TEXT NOT NULL,
       png BLOB NOT NULL,
       created_at INTEGER NOT NULL
     )`
  ).run();
  await env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_capes_owner ON capes(owner_uuid)").run();
  capesReady = true;
}

// ---- Shards economy ----------------------------------------------------------------------------
// Shards are earned server-side only: 10 per 10 minutes actually in game (the heartbeat says whether
// the player was in a world and not sitting in menus), plus a daily login streak (10 -> 50). Capes
// and some badges are bought with them; the store rotates a weekly featured item (25% off) and three
// daily picks (20% off). Prices come from rarity, so client and server can't disagree.
const DAY_MS = 24 * 60 * 60 * 1000;
const WEEK_MS = 7 * DAY_MS;
const PAYOUT_MS = 10 * 60 * 1000;
const PAYOUT = 10;
const MAX_BEAT_GAP_MS = 150 * 1000; // a longer gap means the player wasn't continuously in game
const MAX_BEAT_CREDIT_MS = 90 * 1000;
const STREAK_REWARDS = [10, 15, 20, 25, 30, 40, 50];
const RARITY_PRICE = { common: 150, uncommon: 300, rare: 600, legendary: 1200 };
const MILESTONES = [
  { id: "h1", hours: 1, reward: 25 },
  { id: "h5", hours: 5, reward: 50 },
  { id: "h10", hours: 10, reward: 100 },
  { id: "h25", hours: 25, reward: 200 },
  { id: "h50", hours: 50, reward: 400 },
  { id: "h100", hours: 100, reward: 750 },
];
// Buyable catalog. "added" orders the "New" shelf (higher = newer). Keep in sync with Cosmetics.java.
const CATALOG = [
  { id: "cape:frost", name: "Frost", rarity: "common", added: 1 },
  { id: "cape:ember", name: "Ember", rarity: "common", added: 1 },
  { id: "cape:tide", name: "Tide", rarity: "common", added: 1 },
  { id: "cape:checker", name: "Checker", rarity: "common", added: 1 },
  { id: "cape:verdant", name: "Verdant", rarity: "uncommon", added: 1 },
  { id: "cape:nightfall", name: "Nightfall", rarity: "uncommon", added: 1 },
  { id: "cape:sunset", name: "Sunset", rarity: "uncommon", added: 1 },
  { id: "cape:circuit", name: "Circuit", rarity: "rare", added: 1 },
  { id: "cape:aero", name: "Aero", rarity: "rare", added: 1 },
  { id: "cape:galaxy", name: "Galaxy", rarity: "legendary", added: 1 },
  { id: "cape:katana", name: "Katana", rarity: "uncommon", added: 2 },
  { id: "cape:kitsune", name: "Kitsune", rarity: "rare", added: 2 },
  { id: "cape:dragon", name: "Dragon", rarity: "rare", added: 2 },
  { id: "cape:samurai", name: "Samurai", rarity: "legendary", added: 2 },
  { id: "cape:blossom", name: "Blossom", rarity: "legendary", added: 2 },
  { id: "badge:supporter", name: "Supporter", rarity: "rare", added: 1 },
];
const BETA_FREE = ["cape:blossom", "cape:samurai", "cape:dragon"];
const LOCKED_KINDS = ["kill", "mace"]; // cosmetics locked for now

const catalogItem = (id) => CATALOG.find((c) => c.id === id);
const basePrice = (item) => RARITY_PRICE[item.rarity] || 300;
const dayIndex = (now) => Math.floor(now / DAY_MS);
// Weeks start on Monday 00:00 UTC (the epoch was a Thursday).
const weekIndex = (now) => Math.floor((now + 3 * DAY_MS) / WEEK_MS);

function mulberry32(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** This week's featured cape and today's three picks with their discounted prices. */
function storeRotation(now) {
  const week = weekIndex(now);
  const day = dayIndex(now);
  const capes = CATALOG.filter((c) => c.id.startsWith("cape:"));
  const featured = capes[Math.floor(mulberry32(week * 7919)() * capes.length)];
  const pool = CATALOG.filter((c) => c.id !== featured.id);
  const rnd = mulberry32(day * 104729 + 17);
  const daily = [];
  while (daily.length < 3 && pool.length) daily.push(pool.splice(Math.floor(rnd() * pool.length), 1)[0]);
  return {
    featured: { ...featured, base: basePrice(featured), price: Math.round(basePrice(featured) * 0.75), off: 25 },
    daily: daily.map((c) => ({ ...c, base: basePrice(c), price: Math.round(basePrice(c) * 0.8), off: 20 })),
    weekEndsAt: (week + 1) * WEEK_MS - 3 * DAY_MS,
    dayEndsAt: (day + 1) * DAY_MS,
  };
}

/** Current price of an item (rotation discounts applied), or null for an unknown id. */
function priceNow(id, now) {
  const item = catalogItem(id);
  if (!item) return null;
  const rot = storeRotation(now);
  if (rot.featured.id === id) return rot.featured.price;
  const d = rot.daily.find((c) => c.id === id);
  return d ? d.price : basePrice(item);
}

let economyReady = false;
async function ensureEconomy(env) {
  if (economyReady) return;
  await env.DB.batch([
    env.DB.prepare(
      `CREATE TABLE IF NOT EXISTS wallets (
         uuid TEXT PRIMARY KEY,
         shards INTEGER NOT NULL DEFAULT 0,
         play_ms INTEGER NOT NULL DEFAULT 0,
         pending_ms INTEGER NOT NULL DEFAULT 0,
         last_play INTEGER NOT NULL DEFAULT 0,
         streak INTEGER NOT NULL DEFAULT 0,
         best_streak INTEGER NOT NULL DEFAULT 0,
         last_claim_day INTEGER NOT NULL DEFAULT -1,
         milestones TEXT NOT NULL DEFAULT '',
         beta_free INTEGER NOT NULL DEFAULT 1,
         rank TEXT NOT NULL DEFAULT ''
       )`
    ),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS owned (uuid TEXT NOT NULL, item TEXT NOT NULL, at INTEGER NOT NULL, PRIMARY KEY (uuid, item))"),
    env.DB.prepare(
      "CREATE TABLE IF NOT EXISTS ledger (id INTEGER PRIMARY KEY AUTOINCREMENT, uuid TEXT NOT NULL, delta INTEGER NOT NULL, reason TEXT NOT NULL, at INTEGER NOT NULL)"
    ),
    env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_ledger_uuid ON ledger(uuid, at)"),
  ]);
  economyReady = true;
}

/** The player's wallet row (created on first use). Rank comes from the row or the OWNER_UUIDS var. */
async function wallet(env, uuid) {
  await ensureEconomy(env);
  await env.DB.prepare("INSERT OR IGNORE INTO wallets (uuid) VALUES (?)").bind(uuid).run();
  const w = await env.DB.prepare("SELECT * FROM wallets WHERE uuid = ?").bind(uuid).first();
  const owners = String(env.OWNER_UUIDS || "").toLowerCase().replace(/-/g, "").split(/[ ,]+/).filter(Boolean);
  if (!w.rank && owners.includes(uuid)) w.rank = "owner";
  return w;
}

async function ownedItems(env, uuid) {
  const rows = await env.DB.prepare("SELECT item FROM owned WHERE uuid = ?").bind(uuid).all();
  return rows.results.map((r) => r.item);
}

/** Badges a player has earned, and progress towards the achievement ones. */
function badgeState(w, owned) {
  const capes = owned.filter((i) => i.startsWith("cape:")).length;
  const earned = ["beta"];
  const progress = {
    streak: { have: Math.min(w.best_streak, 7), need: 7 },
    veteran: { have: Math.min(Math.floor(w.play_ms / 3600000), 10), need: 10 },
    collector: { have: Math.min(capes, 5), need: 5 },
  };
  for (const [id, p] of Object.entries(progress)) if (p.have >= p.need) earned.push(id);
  if (owned.includes("badge:supporter")) earned.push("supporter");
  if (w.rank) earned.push(w.rank);
  if (w.rank === "owner") earned.push("dev");
  return { earned, progress };
}

const ledgerRow = (env, uuid, delta, reason, now) =>
  env.DB.prepare("INSERT INTO ledger (uuid, delta, reason, at) VALUES (?1, ?2, ?3, ?4)").bind(uuid, delta, reason, now);

/** Credits in-game time from one heartbeat and pays out full 10-minute blocks. */
async function creditPlaytime(env, uuid, inGame, now) {
  const w = await wallet(env, uuid);
  if (!inGame) {
    if (w.last_play) await env.DB.prepare("UPDATE wallets SET last_play = 0 WHERE uuid = ?").bind(uuid).run();
    return;
  }
  const gap = w.last_play ? now - w.last_play : 0;
  const credit = gap > 0 && gap <= MAX_BEAT_GAP_MS ? Math.min(gap, MAX_BEAT_CREDIT_MS) : 0;
  const pending = w.pending_ms + credit;
  const payouts = Math.floor(pending / PAYOUT_MS);
  const stmts = [
    env.DB.prepare("UPDATE wallets SET last_play = ?1, play_ms = play_ms + ?2, pending_ms = ?3, shards = shards + ?4 WHERE uuid = ?5")
      .bind(now, credit, pending - payouts * PAYOUT_MS, payouts * PAYOUT, uuid),
  ];
  if (payouts > 0) stmts.push(ledgerRow(env, uuid, payouts * PAYOUT, "Playtime", now));
  await env.DB.batch(stmts);
}

async function walletView(env, uuid, now) {
  const w = await wallet(env, uuid);
  const owned = await ownedItems(env, uuid);
  const ledger = await env.DB.prepare("SELECT delta, reason, at FROM ledger WHERE uuid = ? ORDER BY at DESC, id DESC LIMIT 30").bind(uuid).all();
  const today = dayIndex(now);
  const nextStreak = w.last_claim_day === today - 1 ? w.streak + 1 : 1;
  const claimed = w.milestones ? w.milestones.split(",") : [];
  const badges = badgeState(w, owned);
  return {
    shards: w.shards,
    streak: w.last_claim_day >= today - 1 ? w.streak : 0,
    bestStreak: w.best_streak,
    canClaim: w.last_claim_day !== today,
    nextClaimReward: STREAK_REWARDS[Math.min(nextStreak, 7) - 1],
    nextStreakDay: nextStreak,
    streakRewards: STREAK_REWARDS,
    playMs: w.play_ms,
    nextPayoutMs: PAYOUT_MS - w.pending_ms,
    milestones: MILESTONES.map((m) => ({ ...m, claimed: claimed.includes(m.id), reached: w.play_ms >= m.hours * 3600000 })),
    owned,
    betaFree: w.beta_free === 1 ? BETA_FREE : [],
    rank: w.rank || "",
    badges: badges.earned,
    badgeProgress: badges.progress,
    ledger: ledger.results,
  };
}

/** Buys a catalog item with Shards; shared by the mod (/api/store/buy) and the website (/api/web/buy). */
async function buyWithShards(env, uuid, body, now) {
  const id = String(body.item || "");
  const item = catalogItem(id);
  if (!item) return json({ error: "Unknown item" }, 400);
  const w = await wallet(env, uuid);
  if ((await ownedItems(env, uuid)).includes(id)) return json({ error: "You already own this" }, 409);
  const free = w.beta_free === 1 && BETA_FREE.includes(id);
  const price = free ? 0 : priceNow(id, now);
  // The client sends the price it showed; a rotation that flipped in between must not surprise anyone.
  if (body.price !== undefined && Number(body.price) !== price) return json({ error: "The price just changed, check it again" }, 409);
  const pay = free
    ? env.DB.prepare("UPDATE wallets SET beta_free = 0 WHERE uuid = ?1 AND beta_free = 1").bind(uuid)
    : env.DB.prepare("UPDATE wallets SET shards = shards - ?1 WHERE uuid = ?2 AND shards >= ?1").bind(price, uuid);
  const res = await pay.run();
  if (res.meta.changes !== 1) return json({ error: free ? "Free cape already used" : "Not enough shards" }, 402);
  await env.DB.batch([
    env.DB.prepare("INSERT OR IGNORE INTO owned (uuid, item, at) VALUES (?1, ?2, ?3)").bind(uuid, id, now),
    ledgerRow(env, uuid, -price, free ? `${item.name} (free beta cape)` : item.name, now),
  ]);
  return json({ bought: id, price, ...(await walletView(env, uuid, now)) });
}

// ---- website shop -----------------------------------------------------------------------------
// Real money: an order gets a code, the buyer pays by PayPal with the code in the note, and an admin
// (Discord login) marks it paid, which grants the items/Shards. Shards: a player links the website
// from the in-game menu (one-time code) and then buys with their wallet here too.
const EUR_BY_RARITY = { common: 49, uncommon: 99, rare: 149, legendary: 249 }; // euro cents
const SHARD_PACKS = [
  { id: "shards:500", name: "500 Shards", shards: 500, cents: 99 },
  { id: "shards:1500", name: "1,500 Shards", shards: 1500, cents: 249 },
  { id: "shards:4000", name: "4,000 Shards", shards: 4000, cents: 499 },
];
const BUNDLES = [
  { id: "bundle:starter", name: "Starter bundle", items: ["cape:frost", "cape:ember", "cape:tide"], shards: 300, cents: 99 },
  { id: "bundle:legendary", name: "Legendary bundle", items: ["cape:galaxy", "cape:samurai", "cape:blossom"], shards: 1000, cents: 599 },
];
const CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // 32 symbols, no 0/O/1/I
const WEB_SESSION_MS = 30 * DAY_MS;
const ADMIN_SESSION_MS = 7 * DAY_MS;
const LINK_MS = 10 * 60 * 1000;

/** What a product costs (euro cents) and what it grants; null for an unknown id. */
function product(id) {
  const pack = SHARD_PACKS.find((x) => x.id === id);
  if (pack) return { id, name: pack.name, kind: "shards", cents: pack.cents, items: [], shards: pack.shards };
  const b = BUNDLES.find((x) => x.id === id);
  if (b) return { id, name: b.name, kind: "bundle", cents: b.cents, items: b.items, shards: b.shards };
  const item = catalogItem(id);
  if (item) return { id, name: item.name, kind: id.split(":")[0], cents: EUR_BY_RARITY[item.rarity] || 99, items: [id], shards: 0 };
  return null;
}

function moneyCatalog(env) {
  return {
    currency: "EUR",
    paypal: env.PAYPAL_EMAIL || "",
    method: env.PAYPAL_METHOD || "",
    items: Object.fromEntries(CATALOG.map((c) => [c.id, EUR_BY_RARITY[c.rarity] || 99])),
    packs: SHARD_PACKS,
    bundles: BUNDLES.map((b) => ({ ...b, names: b.items.map((i) => (catalogItem(i) || { name: i }).name) })),
  };
}

let shopReady = false;
async function ensureShop(env) {
  if (shopReady) return;
  await ensureEconomy(env);
  await env.DB.batch([
    env.DB.prepare(
      `CREATE TABLE IF NOT EXISTS orders (
         code TEXT PRIMARY KEY, product TEXT NOT NULL, name TEXT NOT NULL, cents INTEGER NOT NULL,
         uuid TEXT NOT NULL, player TEXT NOT NULL, contact TEXT NOT NULL DEFAULT '', ip TEXT NOT NULL DEFAULT '',
         status TEXT NOT NULL DEFAULT 'pending', created INTEGER NOT NULL, done_at INTEGER NOT NULL DEFAULT 0, done_by TEXT NOT NULL DEFAULT ''
       )`
    ),
    env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_orders_created ON orders(created)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS link_codes (code TEXT PRIMARY KEY, uuid TEXT NOT NULL, name TEXT NOT NULL, exp INTEGER NOT NULL)"),
  ]);
  shopReady = true;
}

function randomCode(n) {
  return [...crypto.getRandomValues(new Uint8Array(n))].map((b) => CODE_ALPHABET[b % 32]).join("");
}

/** Signed cookie values. `k` names the kind so a mod token or another cookie can't stand in for this one. */
async function sign(env, data) {
  const body = b64url(enc.encode(JSON.stringify(data)));
  return `${body}.${b64url(await hmac(env.TOKEN_SECRET, body))}`;
}

async function unsign(env, token, kind) {
  const [body, sig] = String(token || "").split(".");
  if (!body || !sig || !safeEqual(sig, b64url(await hmac(env.TOKEN_SECRET, body)))) return null;
  try {
    const d = JSON.parse(atob(body.replace(/-/g, "+").replace(/_/g, "/")));
    return d.k === kind && d.e > Date.now() ? d : null;
  } catch {
    return null;
  }
}

function cookie(request, name) {
  for (const part of (request.headers.get("cookie") || "").split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === name) return v.join("=");
  }
  return null;
}

const setCookie = (name, value, ms) => `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${Math.floor(ms / 1000)}`;

/** Cookie-authenticated writes must come from our own pages. */
const sameOrigin = (request, url) => (request.headers.get("origin") || url.origin) === url.origin;

const adminIds = (env) => String(env.ADMIN_DISCORD_IDS || "").split(/[ ,]+/).filter(Boolean);

async function mojangProfile(name) {
  if (!/^[A-Za-z0-9_]{3,16}$/.test(name)) return null;
  const r = await fetch(`https://api.mojang.com/users/profiles/minecraft/${name}`);
  if (r.status !== 200) return null;
  const p = await r.json().catch(() => null);
  return p && p.id ? { uuid: String(p.id).toLowerCase(), name: p.name } : null;
}

/** Gives a paid order's items and Shards to the player. */
async function grantOrder(env, o, now) {
  const p = product(o.product);
  await wallet(env, o.uuid);
  const stmts = (p ? p.items : []).map((i) => env.DB.prepare("INSERT OR IGNORE INTO owned (uuid, item, at) VALUES (?1, ?2, ?3)").bind(o.uuid, i, now));
  const shards = p ? p.shards : 0;
  if (shards) stmts.push(env.DB.prepare("UPDATE wallets SET shards = shards + ?1 WHERE uuid = ?2").bind(shards, o.uuid));
  stmts.push(ledgerRow(env, o.uuid, shards, `${o.name} (order ${o.code})`, now));
  await env.DB.batch(stmts);
}

function redirect(location, cookies = []) {
  const h = new Headers({ location });
  for (const c of cookies) h.append("set-cookie", c);
  return new Response(null, { status: 302, headers: h });
}

/** Routes under /api/orders, /api/link, /api/web/ and /api/admin/; null when the path isn't one of them. */
async function shopRoutes(request, env, url) {
  const path = url.pathname;
  const method = request.method;
  const now = Date.now();

  if (path === "/api/orders" && method === "POST") {
    if (!sameOrigin(request, url)) return json({ error: "forbidden" }, 403);
    await ensureShop(env);
    const body = await request.json().catch(() => ({}));
    const p = product(String(body.product || ""));
    if (!p) return json({ error: "Unknown product" }, 400);
    const player = await mojangProfile(String(body.player || "").trim());
    if (!player) return json({ error: "That Minecraft name doesn't exist" }, 400);
    const owned = await ownedItems(env, player.uuid);
    if (!p.shards && p.items.every((i) => owned.includes(i))) return json({ error: `${player.name} already owns this` }, 409);
    // Rate limit per address; only a keyed hash of it is stored.
    const ip = hex(await hmac(env.TOKEN_SECRET, "ip:" + (request.headers.get("cf-connecting-ip") || ""))).slice(0, 16);
    const recent = await env.DB.prepare("SELECT COUNT(*) AS n FROM orders WHERE ip = ?1 AND created > ?2").bind(ip, now - 3600000).first();
    if (recent.n >= 5) return json({ error: "Too many orders, try again in an hour" }, 429);
    const code = "AERO-" + randomCode(6);
    const contact = String(body.contact || "").trim().slice(0, 64);
    await env.DB.prepare("INSERT INTO orders (code, product, name, cents, uuid, player, contact, ip, created) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)")
      .bind(code, p.id, p.name, p.cents, player.uuid, player.name, contact, ip, now)
      .run();
    return json({ code, product: p.name, cents: p.cents, player: player.name, paypal: env.PAYPAL_EMAIL || "", method: env.PAYPAL_METHOD || "" });
  }

  if (path.startsWith("/api/orders/") && method === "GET") {
    await ensureShop(env);
    const o = await env.DB.prepare("SELECT code, name, cents, player, status, created FROM orders WHERE code = ?")
      .bind(path.slice("/api/orders/".length).toUpperCase())
      .first();
    return o ? json(o) : json({ error: "not found" }, 404);
  }

  // In game: a one-time code (and a link with it) that logs the website into this player's wallet.
  if (path === "/api/link" && method === "POST") {
    const who = await readToken(env, request);
    if (!who) return json({ error: "unauthorized" }, 401);
    if (who.g) return json({ error: "Linking needs a verified Microsoft account" }, 403);
    await ensureShop(env);
    await env.DB.prepare("DELETE FROM link_codes WHERE exp < ?1 OR uuid = ?2").bind(now, who.u).run();
    const code = randomCode(8);
    await env.DB.prepare("INSERT INTO link_codes (code, uuid, name, exp) VALUES (?1, ?2, ?3, ?4)").bind(code, who.u, who.n, now + LINK_MS).run();
    return json({ code, url: `${url.origin}/store?link=${code}`, expiresIn: LINK_MS / 1000 });
  }

  if (path === "/api/web/login" && method === "POST") {
    if (!sameOrigin(request, url)) return json({ error: "forbidden" }, 403);
    await ensureShop(env);
    const body = await request.json().catch(() => ({}));
    const code = String(body.code || "").toUpperCase().replace(/[^A-Z0-9]/g, "");
    const row = await env.DB.prepare("DELETE FROM link_codes WHERE code = ?1 AND exp > ?2 RETURNING uuid, name").bind(code, now).first();
    if (!row) return json({ error: "Code not found or expired. Make a new one in game." }, 400);
    const session = await sign(env, { k: "web", u: row.uuid, n: row.name, e: now + WEB_SESSION_MS });
    return json({ name: row.name }, 200, { "set-cookie": setCookie("aero_web", session, WEB_SESSION_MS) });
  }

  if (path.startsWith("/api/web/")) {
    if (path === "/api/web/logout" && method === "POST") return json({ ok: true }, 200, { "set-cookie": setCookie("aero_web", "", 0) });
    const s = await unsign(env, cookie(request, "aero_web"), "web");
    if (!s) return json({ error: "Not linked" }, 401);
    if (path === "/api/web/me" && method === "GET") {
      const w = await wallet(env, s.u);
      return json({ name: s.n, shards: w.shards, owned: await ownedItems(env, s.u), betaFree: w.beta_free === 1 ? BETA_FREE : [] });
    }
    if (path === "/api/web/buy" && method === "POST") {
      if (!sameOrigin(request, url)) return json({ error: "forbidden" }, 403);
      return buyWithShards(env, s.u, await request.json().catch(() => ({})), now);
    }
    return json({ error: "not found" }, 404);
  }

  // Admin: Discord login, allowed ids in ADMIN_DISCORD_IDS.
  if (path === "/api/admin/login" && method === "GET") {
    if (!env.DISCORD_CLIENT_ID || !env.DISCORD_CLIENT_SECRET) return redirect(`${url.origin}/admin?error=setup`);
    const state = randomCode(16);
    const q = new URLSearchParams({
      client_id: env.DISCORD_CLIENT_ID,
      redirect_uri: `${url.origin}/api/admin/callback`,
      response_type: "code",
      scope: "identify",
      state,
    });
    return redirect(`https://discord.com/oauth2/authorize?${q}`, [setCookie("aero_st", await sign(env, { k: "st", s: state, e: now + 600000 }), 600000)]);
  }

  if (path === "/api/admin/callback" && method === "GET") {
    const st = await unsign(env, cookie(request, "aero_st"), "st");
    const clear = setCookie("aero_st", "", 0);
    if (!st || !safeEqual(st.s, url.searchParams.get("state") || "")) return redirect(`${url.origin}/admin?error=state`, [clear]);
    const tok = await fetch("https://discord.com/api/oauth2/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: env.DISCORD_CLIENT_ID,
        client_secret: env.DISCORD_CLIENT_SECRET,
        grant_type: "authorization_code",
        code: url.searchParams.get("code") || "",
        redirect_uri: `${url.origin}/api/admin/callback`,
      }),
    });
    if (!tok.ok) return redirect(`${url.origin}/admin?error=discord`, [clear]);
    const { access_token } = await tok.json();
    const me = await (await fetch("https://discord.com/api/users/@me", { headers: { authorization: `Bearer ${access_token}` } })).json();
    if (!me.id || !adminIds(env).includes(me.id)) return redirect(`${url.origin}/admin?denied=${encodeURIComponent(me.id || "")}`, [clear]);
    const session = await sign(env, { k: "adm", id: me.id, n: me.global_name || me.username, e: now + ADMIN_SESSION_MS });
    return redirect(`${url.origin}/admin`, [clear, setCookie("aero_adm", session, ADMIN_SESSION_MS)]);
  }

  if (path.startsWith("/api/admin/")) {
    if (path === "/api/admin/logout" && method === "POST") return json({ ok: true }, 200, { "set-cookie": setCookie("aero_adm", "", 0) });
    const a = await unsign(env, cookie(request, "aero_adm"), "adm");
    if (!a || !adminIds(env).includes(a.id)) return json({ error: "unauthorized" }, 401);
    await ensureShop(env);
    if (path === "/api/admin/me" && method === "GET") return json({ id: a.id, name: a.n });
    if (path === "/api/admin/orders" && method === "GET") {
      const rows = await env.DB.prepare(
        "SELECT code, product, name, cents, uuid, player, contact, status, created, done_at, done_by FROM orders ORDER BY created DESC LIMIT 300"
      ).all();
      return json({ orders: rows.results });
    }
    const m = path.match(/^\/api\/admin\/orders\/(AERO-[A-Z0-9]{6})\/(paid|cancel)$/);
    if (m && method === "POST") {
      if (!sameOrigin(request, url)) return json({ error: "forbidden" }, 403);
      const o = await env.DB.prepare("SELECT * FROM orders WHERE code = ?").bind(m[1]).first();
      if (!o) return json({ error: "not found" }, 404);
      const status = m[2] === "paid" ? "paid" : "cancelled";
      const res = await env.DB.prepare("UPDATE orders SET status = ?1, done_at = ?2, done_by = ?3 WHERE code = ?4 AND status = 'pending'")
        .bind(status, now, a.n, o.code)
        .run();
      if (res.meta.changes !== 1) return json({ error: `Order is already ${o.status}` }, 409);
      if (status === "paid") await grantOrder(env, o, now);
      return json({ ok: true, status });
    }
    return json({ error: "not found" }, 404);
  }
  return null;
}

const PRESET_MAX_BYTES = 32768;
const PRESET_LIMIT_PER_PLAYER = 10;

let presetsReady = false;
/** Shared config presets table (a full aero-client.json snapshot) is created on first use. */
async function ensurePresets(env) {
  if (presetsReady) return;
  await env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS presets (
       id INTEGER PRIMARY KEY AUTOINCREMENT,
       owner_uuid TEXT NOT NULL,
       owner_name TEXT NOT NULL,
       name TEXT NOT NULL,
       config TEXT NOT NULL,
       created_at INTEGER NOT NULL
     )`
  ).run();
  await env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_presets_owner ON presets(owner_uuid)").run();
  presetsReady = true;
}

/** Reads a PNG's IHDR width/height without decoding pixels, or null when it's not a PNG. */
function pngSize(bytes) {
  const sig = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
  if (bytes.length < 24) return null;
  for (let i = 0; i < 8; i++) if (bytes[i] !== sig[i]) return null;
  if (String.fromCharCode(bytes[12], bytes[13], bytes[14], bytes[15]) !== "IHDR") return null;
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return { width: dv.getUint32(16), height: dv.getUint32(20) };
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    try {
      // ---- public, aggregate only ----
      if (path === "/api/stats" && method === "GET") {
        return cached(request, ctx, 8, async () => {
          const now = Date.now();
          const online = await env.DB.prepare("SELECT COUNT(*) AS n FROM users WHERE last_seen > ?").bind(now - ONLINE_MS).first();
          const total = await env.DB.prepare("SELECT COUNT(*) AS n FROM users").first();
          let downloads = 0;
          try {
            await ensureDownloads(env);
            downloads = (await env.DB.prepare("SELECT COALESCE(SUM(n), 0) AS n FROM downloads").first()).n;
          } catch {}
          return json({ online: online.n, total: total.n, downloads, discord: env.DISCORD_URL });
        });
      }

      // Names of players who are online right now (opt-in: only players who share their profile send heartbeats).
      if (path === "/api/online" && method === "GET") {
        return cached(request, ctx, 8, async () => {
          const rows = await env.DB.prepare("SELECT name FROM users WHERE last_seen > ? ORDER BY last_seen DESC LIMIT 60")
            .bind(Date.now() - ONLINE_MS)
            .all();
          return json({ players: rows.results.map((r) => r.name) });
        });
      }

      if (path === "/api/version" && method === "GET") {
        return cached(request, ctx, 300, async () => {
          // The launcher lives in its own non-latest releases, so "latest" is only ever the mod.
          const [mod, launcher] = await Promise.all([latestRelease(env.MOD_REPO), launcherNow(env)]);
          const jar = mod?.assets.find((a) => a.name.toLowerCase().endsWith(".jar"));
          const modVersion = mod?.version ? await remember(env, "mod", mod.version) : await remember(env, "mod");
          return json(
            {
              mod: { version: modVersion, url: jar?.browser_download_url || `https://github.com/${env.MOD_REPO}/releases/latest/download/${env.MOD_ASSET}` },
              launcher: { version: launcher?.tag?.replace(/^launcher-/, "") || null, url: launcher?.url || null },
            },
            modVersion ? 200 : 503 // nothing known yet: not cached, so the next request asks GitHub again
          );
        });
      }

      // The launcher release is deliberately never GitHub's "latest" (see latestLauncherExe) - so unlike
      // the mod below, there's no rate-limit-proof fixed URL for it. Only a *successful* lookup is
      // cached (never the rate-limited fallback itself, or one failure would cache "give up" for everyone).
      if (path === "/download/launcher" && method === "GET") {
        const cacheKey = new Request(new URL("/download/launcher/asset", url).toString());
        const cache = caches.default;
        let downloadUrl = (await cache.match(cacheKey))?.headers.get("location");
        if (!downloadUrl) {
          const found = await launcherNow(env);
          if (!found) return Response.redirect(`https://github.com/${env.LAUNCHER_REPO}/releases`, 302);
          downloadUrl = found.url;
          ctx.waitUntil(
            cache.put(cacheKey, new Response(null, { headers: { location: downloadUrl, "cache-control": "max-age=300" } }))
          );
        }
        ctx.waitUntil(countDownload(env, "launcher"));
        return Response.redirect(downloadUrl, 302);
      }

      if (path === "/download/mod" && method === "GET") {
        const rel = await latestRelease(env.MOD_REPO);
        const asset = rel?.assets.find((a) => a.name.toLowerCase().endsWith(".jar"));
        if (rel?.failed || asset) ctx.waitUntil(countDownload(env, "mod"));
        if (rel?.failed) {
          // GitHub API unavailable: the fixed "latest" URL still resolves to the newest release asset.
          return Response.redirect(`https://github.com/${env.MOD_REPO}/releases/latest/download/${env.MOD_ASSET}`, 302);
        }
        // No release yet: send visitors back to the styled site with a notice instead of a bare error page.
        return asset
          ? Response.redirect(asset.browser_download_url, 302)
          : Response.redirect(`${url.origin}/?nodl=mod`, 302);
      }

      if (path === "/download/preview" && method === "GET") {
        const rel = await latestPreview(env.MOD_REPO);
        const asset = rel?.assets.find((a) => a.name.toLowerCase().endsWith(".jar"));
        if (asset) ctx.waitUntil(countDownload(env, "preview"));
        return asset
          ? Response.redirect(asset.browser_download_url, 302)
          : Response.redirect(`${url.origin}/?nodl=preview`, 302);
      }

      // ---- list used by the mod (same shape as the old users.json) ----
      if (path === "/api/users" && method === "GET") {
        return cached(request, ctx, 60, async () => {
          await ensureSchema(env);
          const rows = await env.DB.prepare(
            "SELECT uuid, name, badge, cosmetics FROM users WHERE verified = 1 AND last_seen > ? ORDER BY last_seen DESC LIMIT 5000"
          )
            .bind(Date.now() - ACTIVE_MS)
            .all();
          const users = rows.results.map((r) => {
            let cosmetics = {};
            try {
              cosmetics = JSON.parse(r.cosmetics);
            } catch {}
            return { name: r.name, uuid: dash(r.uuid), badge: r.badge, cosmetics };
          });
          return json({ users });
        });
      }

      // ---- authentication ----
      // Guests count in the totals and the online list, but are unverified: no cosmetics are served for them.
      if (path === "/api/auth/guest" && method === "POST") {
        const body = await request.json().catch(() => ({}));
        const name = String(body.name || "");
        const uuid = String(body.uuid || "").replace(/-/g, "").toLowerCase();
        if (!/^[A-Za-z0-9_]{1,16}$/.test(name) || !/^[0-9a-f]{32}$/.test(uuid)) return json({ error: "bad request" }, 400);
        return json({ token: await makeToken(env, uuid, name, true), uuid, guest: true, expiresIn: TOKEN_MS / 1000 });
      }

      if (path === "/api/auth/start" && method === "POST") {
        const ts = Date.now().toString(16);
        const nonce = hex(crypto.getRandomValues(new Uint8Array(8)));
        const sig = hex(await hmac(env.TOKEN_SECRET, `${ts}.${nonce}`)).slice(0, 16);
        return json({ serverId: `${ts}${nonce}${sig}` });
      }

      if (path === "/api/auth/finish" && method === "POST") {
        const body = await request.json().catch(() => ({}));
        const name = String(body.name || "");
        const serverId = String(body.serverId || "");
        if (!/^[A-Za-z0-9_]{1,16}$/.test(name) || !/^[0-9a-f]{28,}$/.test(serverId)) return json({ error: "bad request" }, 400);
        // serverId = <ts hex, variable length><16 hex nonce><16 hex signature>
        const sig = serverId.slice(-16);
        const nonce = serverId.slice(-32, -16);
        const ts = serverId.slice(0, -32);
        const expect = hex(await hmac(env.TOKEN_SECRET, `${ts}.${nonce}`)).slice(0, 16);
        if (!safeEqual(sig, expect) || Date.now() - parseInt(ts, 16) > NONCE_MS) return json({ error: "expired" }, 401);
        const r = await fetch(
          `https://sessionserver.mojang.com/session/minecraft/hasJoined?username=${encodeURIComponent(name)}&serverId=${serverId}`
        );
        if (r.status !== 200) return json({ error: "not verified" }, 401);
        const profile = await r.json();
        return json({ token: await makeToken(env, profile.id, profile.name), uuid: profile.id, expiresIn: TOKEN_MS / 1000 });
      }

      // ---- store (public) ----
      if (path === "/api/store" && method === "GET") {
        return cached(request, ctx, 60, async () => {
          const now = Date.now();
          const newestAdded = Math.max(...CATALOG.map((c) => c.added));
          const priced = (c) => ({ ...c, base: basePrice(c), price: priceNow(c.id, now) });
          return json({
            ...storeRotation(now),
            newest: CATALOG.filter((c) => c.added === newestAdded).map(priced),
            catalog: CATALOG.map(priced),
            locked: LOCKED_KINDS,
            money: moneyCatalog(env),
            payout: { every: PAYOUT_MS, shards: PAYOUT },
          });
        });
      }

      if (path.startsWith("/api/orders") || path === "/api/link" || path.startsWith("/api/web/") || path.startsWith("/api/admin/")) {
        const res = await shopRoutes(request, env, url);
        if (res) return res;
      }

      // ---- wallet, rewards, purchases (verified players only) ----
      if (path === "/api/wallet" || path.startsWith("/api/rewards/") || path === "/api/store/buy") {
        const who = await readToken(env, request);
        if (!who) return json({ error: "unauthorized" }, 401);
        if (who.g) return json({ error: "Shards need a verified Microsoft account" }, 403);
        const now = Date.now();
        if (path === "/api/wallet" && method === "GET") return json(await walletView(env, who.u, now));

        if (path === "/api/rewards/streak" && method === "POST") {
          const w = await wallet(env, who.u);
          const today = dayIndex(now);
          if (w.last_claim_day === today) return json({ error: "Already claimed today" }, 409);
          const streak = w.last_claim_day === today - 1 ? w.streak + 1 : 1;
          const reward = STREAK_REWARDS[Math.min(streak, 7) - 1];
          const res = await env.DB.prepare(
            "UPDATE wallets SET shards = shards + ?1, streak = ?2, best_streak = MAX(best_streak, ?2), last_claim_day = ?3 WHERE uuid = ?4 AND last_claim_day != ?3"
          )
            .bind(reward, streak, today, who.u)
            .run();
          if (res.meta.changes !== 1) return json({ error: "Already claimed today" }, 409);
          await ledgerRow(env, who.u, reward, `Day ${streak} streak`, now).run();
          return json({ reward, ...(await walletView(env, who.u, now)) });
        }

        if (path === "/api/rewards/milestone" && method === "POST") {
          const body = await request.json().catch(() => ({}));
          const m = MILESTONES.find((x) => x.id === body.id);
          if (!m) return json({ error: "Unknown milestone" }, 400);
          const w = await wallet(env, who.u);
          const claimed = w.milestones ? w.milestones.split(",") : [];
          if (claimed.includes(m.id)) return json({ error: "Already claimed" }, 409);
          if (w.play_ms < m.hours * 3600000) return json({ error: "Not reached yet" }, 403);
          const res = await env.DB.prepare("UPDATE wallets SET shards = shards + ?1, milestones = ?2 WHERE uuid = ?3 AND milestones = ?4")
            .bind(m.reward, [...claimed, m.id].join(","), who.u, w.milestones)
            .run();
          if (res.meta.changes !== 1) return json({ error: "Try again" }, 409);
          await ledgerRow(env, who.u, m.reward, `${m.hours}h milestone`, now).run();
          return json({ reward: m.reward, ...(await walletView(env, who.u, now)) });
        }

        if (path === "/api/store/buy" && method === "POST") {
          return buyWithShards(env, who.u, await request.json().catch(() => ({})), now);
        }
        return json({ error: "not found" }, 404);
      }


      // ---- authenticated ----
      if (path === "/api/heartbeat" && method === "POST") {
        const who = await readToken(env, request);
        if (!who) return json({ error: "unauthorized" }, 401);
        const raw = await request.text();
        if (raw.length > 2048) return json({ error: "too large" }, 413);
        const body = JSON.parse(raw || "{}");
        let badge = String(body.badge || "none");
        if (!ID_RE.test(badge)) badge = "none";
        const cosmetics = {};
        for (const k of COSMETIC_KINDS) {
          const v = body.cosmetics?.[k];
          if (typeof v === "string" && ID_RE.test(v) && v !== "none") cosmetics[k] = v;
        }
        const now = Date.now();
        await ensureSchema(env);
        const guest = who.g ? 1 : 0;
        if (guest) {
          badge = "none"; // nothing unverified is shown to other players
          for (const k of Object.keys(cosmetics)) delete cosmetics[k];
        } else {
          // Shards for in-game time, and only what the player actually owns/earned is shown to others.
          await creditPlaytime(env, who.u, body.inGame === true, now);
          const w = await wallet(env, who.u);
          const owned = await ownedItems(env, who.u);
          for (const k of LOCKED_KINDS) delete cosmetics[k];
          const cape = cosmetics.cape;
          if (cape && !cape.startsWith("custom_") && !owned.includes(`cape:${cape}`) && cape !== `rank_${w.rank}`) delete cosmetics.cape;
          if (badge !== "none" && !badgeState(w, owned).earned.includes(badge)) badge = "none";
        }
        // A verified player is never downgraded or overwritten by a guest entry with the same UUID.
        await env.DB.prepare(
          `INSERT INTO users (uuid, name, badge, cosmetics, first_seen, last_seen, verified) VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?6)
           ON CONFLICT(uuid) DO UPDATE SET
             name = CASE WHEN users.verified = 1 AND ?6 = 0 THEN users.name ELSE ?2 END,
             badge = CASE WHEN users.verified = 1 AND ?6 = 0 THEN users.badge ELSE ?3 END,
             cosmetics = CASE WHEN users.verified = 1 AND ?6 = 0 THEN users.cosmetics ELSE ?4 END,
             verified = MAX(users.verified, ?6),
             last_seen = ?5`
        )
          .bind(who.u, who.n, badge, JSON.stringify(cosmetics), now, guest ? 0 : 1)
          .run();
        return json({ ok: true });
      }

      // ---- custom capes: publish, browse, fetch, delete ----
      if (path === "/api/capes" && method === "GET") {
        return cached(request, ctx, 20, async () => {
          await ensureCapes(env);
          const rows = await env.DB.prepare(
            "SELECT id, owner_uuid, owner_name, name, created_at FROM capes ORDER BY created_at DESC LIMIT 500"
          ).all();
          const capes = rows.results.map((r) => ({
            id: r.id,
            name: r.name,
            owner: r.owner_name,
            ownerUuid: dash(r.owner_uuid),
            createdAt: r.created_at,
          }));
          return json({ capes });
        });
      }

      if (path === "/api/capes" && method === "POST") {
        const who = await readToken(env, request);
        if (!who) return json({ error: "unauthorized" }, 401);
        if (who.g) return json({ error: "Guests can't publish capes" }, 403);
        await ensureCapes(env);
        const count = await env.DB.prepare("SELECT COUNT(*) AS n FROM capes WHERE owner_uuid = ?").bind(who.u).first();
        if (count.n >= CAPE_LIMIT_PER_PLAYER) return json({ error: `Limit of ${CAPE_LIMIT_PER_PLAYER} published capes reached` }, 403);
        const name = (url.searchParams.get("name") || "Cape").replace(/[^\x20-\x7E]/g, "").trim().slice(0, 24) || "Cape";
        const buf = await request.arrayBuffer();
        if (buf.byteLength > CAPE_MAX_BYTES) return json({ error: "File too large (max 8 KB)" }, 413);
        const bytes = new Uint8Array(buf);
        const size = pngSize(bytes);
        if (!size || size.width !== 64 || size.height !== 32) return json({ error: "Cape must be a 64x32 PNG" }, 400);
        const now = Date.now();
        const res = await env.DB.prepare(
          "INSERT INTO capes (owner_uuid, owner_name, name, png, created_at) VALUES (?1, ?2, ?3, ?4, ?5)"
        )
          .bind(who.u, who.n, name, bytes, now)
          .run();
        return json({ id: res.meta.last_row_id, name });
      }

      if (path.startsWith("/api/capes/") && path.endsWith(".png") && method === "GET") {
        const id = parseInt(path.slice("/api/capes/".length, -4), 10);
        if (!Number.isInteger(id)) return json({ error: "bad id" }, 400);
        return cached(request, ctx, 604800, async () => {
          await ensureCapes(env);
          const row = await env.DB.prepare("SELECT png FROM capes WHERE id = ?").bind(id).first();
          if (!row) return json({ error: "not found" }, 404);
          return new Response(row.png, { headers: { "content-type": "image/png" } });
        });
      }

      if (path.startsWith("/api/capes/") && method === "DELETE") {
        const who = await readToken(env, request);
        if (!who) return json({ error: "unauthorized" }, 401);
        const id = parseInt(path.slice("/api/capes/".length), 10);
        if (!Number.isInteger(id)) return json({ error: "bad id" }, 400);
        await ensureCapes(env);
        const row = await env.DB.prepare("SELECT owner_uuid FROM capes WHERE id = ?").bind(id).first();
        if (!row) return json({ deleted: false });
        if (row.owner_uuid !== who.u) return json({ error: "not your cape" }, 403);
        await env.DB.prepare("DELETE FROM capes WHERE id = ?").bind(id).run();
        return json({ deleted: true });
      }

      // ---- shared presets: publish/browse/fetch/delete a full mod-config snapshot ----
      if (path === "/api/presets" && method === "GET") {
        return cached(request, ctx, 20, async () => {
          await ensurePresets(env);
          const rows = await env.DB.prepare(
            "SELECT id, owner_uuid, owner_name, name, created_at FROM presets ORDER BY created_at DESC LIMIT 500"
          ).all();
          const presets = rows.results.map((r) => ({
            id: r.id,
            name: r.name,
            owner: r.owner_name,
            ownerUuid: dash(r.owner_uuid),
            createdAt: r.created_at,
          }));
          return json({ presets });
        });
      }

      if (path === "/api/presets" && method === "POST") {
        const who = await readToken(env, request);
        if (!who) return json({ error: "unauthorized" }, 401);
        if (who.g) return json({ error: "Guests can't publish presets" }, 403);
        await ensurePresets(env);
        const count = await env.DB.prepare("SELECT COUNT(*) AS n FROM presets WHERE owner_uuid = ?").bind(who.u).first();
        if (count.n >= PRESET_LIMIT_PER_PLAYER) return json({ error: `Limit of ${PRESET_LIMIT_PER_PLAYER} published presets reached` }, 403);
        const name = (url.searchParams.get("name") || "Preset").replace(/[^\x20-\x7E]/g, "").trim().slice(0, 24) || "Preset";
        const text = await request.text();
        if (text.length > PRESET_MAX_BYTES) return json({ error: "Preset too large (max 32 KB)" }, 413);
        try {
          JSON.parse(text);
        } catch {
          return json({ error: "Preset must be valid JSON" }, 400);
        }
        const now = Date.now();
        const res = await env.DB.prepare(
          "INSERT INTO presets (owner_uuid, owner_name, name, config, created_at) VALUES (?1, ?2, ?3, ?4, ?5)"
        )
          .bind(who.u, who.n, name, text, now)
          .run();
        return json({ id: res.meta.last_row_id, name });
      }

      if (path.startsWith("/api/presets/") && path.endsWith(".json") && method === "GET") {
        const id = parseInt(path.slice("/api/presets/".length, -5), 10);
        if (!Number.isInteger(id)) return json({ error: "bad id" }, 400);
        return cached(request, ctx, 604800, async () => {
          await ensurePresets(env);
          const row = await env.DB.prepare("SELECT config FROM presets WHERE id = ?").bind(id).first();
          if (!row) return json({ error: "not found" }, 404);
          return new Response(row.config, { headers: { "content-type": "application/json" } });
        });
      }

      if (path.startsWith("/api/presets/") && method === "DELETE") {
        const who = await readToken(env, request);
        if (!who) return json({ error: "unauthorized" }, 401);
        const id = parseInt(path.slice("/api/presets/".length), 10);
        if (!Number.isInteger(id)) return json({ error: "bad id" }, 400);
        await ensurePresets(env);
        const row = await env.DB.prepare("SELECT owner_uuid FROM presets WHERE id = ?").bind(id).first();
        if (!row) return json({ deleted: false });
        if (row.owner_uuid !== who.u) return json({ error: "not your preset" }, 403);
        await env.DB.prepare("DELETE FROM presets WHERE id = ?").bind(id).run();
        return json({ deleted: true });
      }

      if (path === "/api/me" && method === "DELETE") {
        const who = await readToken(env, request);
        if (!who) return json({ error: "unauthorized" }, 401);
        await env.DB.prepare("DELETE FROM users WHERE uuid = ?").bind(who.u).run();
        return json({ deleted: true });
      }

      if (path.startsWith("/api/")) return json({ error: "not found" }, 404);
    } catch (e) {
      return json({ error: "server error" }, 500);
    }
    return env.ASSETS.fetch(request);
  },
};
