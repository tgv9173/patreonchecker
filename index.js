const express = require('express');
const axios = require('axios');
const querystring = require('querystring');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const http = require('http');
const path = require('path');
const fs = require('fs');
const multer = require('multer');

const { track, TRACK_HOME } = require('./analytics');
const { r2Configured, presignGet, listObjects } = require('./lib/r2');
const dbLib = require('./lib/db');
const {
  isNameMatch,
  findCommissionsForPatron,
  findCommissionsByUsername,
  getFreshCommissionRow,
  updateCommissionRow,
  flagRowChangesRequested,
  setRowStatusByLabel,
  appendCommissionSubmission,
  appendRequestSubmission
} = require('./sheets');

const app = express();
app.set('trust proxy', 1);

// Rejecting a wrong-type file must be an ERROR, not a silent drop: cb(null, false)
// omits the file and the submit still "succeeds", so the patron believes their
// reference was attached when it wasn't. Uses a real MulterError so the shared upload
// error handler below renders it; `invalidType` disambiguates from multer's own
// LIMIT_UNEXPECTED_FILE (which .array() also throws for too-many-files).
function imageTypeFilter(req, file, cb) {
  if (/^image\/(png|jpe?g|gif|webp)$/i.test(file.mimetype)) return cb(null, true);
  const err = new multer.MulterError('LIMIT_UNEXPECTED_FILE', file.fieldname);
  err.invalidType = true;
  cb(err);
}

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 8 * 1024 * 1024, files: 1 },
  fileFilter: imageTypeFilter
});

// Separate instance (not just a different .array()/.single() call on `upload` above) so
// its files:5 limit doesn't loosen the single-file cap the existing edit form relies on.
const REFERENCE_IMAGE_LIMIT = 5;
const uploadReferenceImages = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 8 * 1024 * 1024, files: REFERENCE_IMAGE_LIMIT },
  fileFilter: imageTypeFilter
});

async function uploadToCatbox(file) {
  const form = new FormData();
  form.append('reqtype', 'fileupload');
  form.append('fileToUpload', new Blob([file.buffer], { type: file.mimetype }), file.originalname || 'upload.jpg');
  const res = await fetch('https://catbox.moe/user/api.php', { method: 'POST', body: form });
  const text = (await res.text()).trim();
  if (!res.ok || !/^https?:\/\//.test(text)) {
    throw new Error(`catbox upload failed: ${res.status} ${text.slice(0, 200)}`);
  }
  return text;
}

// Uploads each file to catbox in turn and returns the URLs, in order. Uploads
// sequentially (not Promise.all) so one file's failure doesn't leave the others
// half-uploaded in an unpredictable order, and so catbox doesn't see a burst.
async function uploadReferenceImagesToCatbox(files) {
  const urls = [];
  for (const file of files || []) {
    urls.push(await uploadToCatbox(file));
  }
  return urls;
}


const MONTH_NAMES_LOWER = [
  'january', 'february', 'march', 'april', 'may', 'june',
  'july', 'august', 'september', 'october', 'november', 'december'
];

// Fire-and-forget creator notification to a Discord webhook (set
// DISCORD_NOTIFY_WEBHOOK on Render to enable). Never awaited on the request path and
// never allowed to fail a patron-facing action — it's telemetry for the creator, not
// part of the submission.
const DISCORD_NOTIFY_WEBHOOK = process.env.DISCORD_NOTIFY_WEBHOOK;
function notifyDiscord(text) {
  if (!DISCORD_NOTIFY_WEBHOOK) return;
  axios.post(DISCORD_NOTIFY_WEBHOOK, { content: text.slice(0, 1900) }, { timeout: 8000 })
    .catch(err => console.error('Discord notify failed:', err.message));
}

const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
// Must match Patreon developer portal "Redirect URIs" exactly (set on Render + in Patreon).
const REDIRECT_URI = process.env.REDIRECT_URI || 'https://patreon-checker.onrender.com/callback';
const ALLOWED_TIER_IDS = process.env.ALLOWED_TIER_IDS;
const SUCCESS_REDIRECT_URI = process.env.SUCCESS_REDIRECT_URI;
// When the R2 library is configured, oauth success lands on the gated library
// instead of the (legacy, monthly-rotated) Dropbox link. See /library routes.
const successTarget = () => (r2Configured() ? '/library' : SUCCESS_REDIRECT_URI);
// Deliberately separate from ALLOWED_TIER_IDS above: that one gates the Dropbox-folder
// link and may allow broader tiers, but only the commissioner tier actually gets a
// commission with their subscription, so /commissions/new checks this instead.
const COMMISSIONER_TIER_IDS = process.env.COMMISSIONER_TIER_IDS;

// Patreon's edge/WAF commonly rejects requests without a descriptive User-Agent (400 with empty body).
// Override via Render env if needed. https://www.patreondevelopers.com/t/status-400-https-www-patreon-com-api-oauth2-v2-identity/8836
const PATREON_API_USER_AGENT =
  process.env.PATREON_API_USER_AGENT ||
  'TGV9173-patreon-checker/1.0 (+https://patreon-checker.onrender.com)';
// Only count tiers from this campaign’s membership (recommended). Find ID in Patreon creator dashboard URL or API.
const PATREON_CAMPAIGN_ID = (process.env.PATREON_CAMPAIGN_ID || '').trim();
const PATREON_HTTP_TIMEOUT_MS = Number(process.env.PATREON_HTTP_TIMEOUT_MS || 45000);

const AUTH_CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour
const SESSION_SECRET = crypto.randomBytes(32); // rotates on restart — cache cookies become invalid, users re-authenticate
const patronCache = new Map(); // patreonUserId → { matched, expires }

// Stable secret for HMAC-signed OAuth state (survives restarts; set OAUTH_STATE_SECRET in Render env).
// Falls back to SESSION_SECRET so state mismatch can still happen on restart if the env var is absent —
// but that's the same as before. With the env var set, in-flight logins survive restarts.
const OAUTH_STATE_SECRET = (process.env.OAUTH_STATE_SECRET || '').trim() || SESSION_SECRET;

function makeOAuthState(intent) {
  const nonce = crypto.randomBytes(16).toString('hex');
  const payload = `${nonce}.${intent}`;
  const sig = crypto.createHmac('sha256', OAUTH_STATE_SECRET).update(payload).digest('base64url');
  return `${payload}.${sig}`;
}

// Returns the intent ('default' | 'commissions') if the HMAC is valid, null otherwise.
// No cookie needed — CSRF protection comes from the server secret, not a stored value.
function verifyOAuthState(state) {
  if (typeof state !== 'string') return null;
  const lastDot = state.lastIndexOf('.');
  if (lastDot < 0) return null;
  const payload = state.slice(0, lastDot);
  const sig = state.slice(lastDot + 1);
  const expected = crypto.createHmac('sha256', OAUTH_STATE_SECRET).update(payload).digest('base64url');
  try {
    if (!crypto.timingSafeEqual(Buffer.from(sig, 'base64url'), Buffer.from(expected, 'base64url'))) return null;
  } catch { return null; }
  const intent = payload.split('.')[1];
  // LOGIN_INTENTS (defined near the form routes) also covers 'commission-request'
  // and 'requests' — anything unrecognized degrades to the default folder-link flow.
  return LOGIN_INTENTS.includes(intent) ? intent : 'default';
}

function patronCookieSign(userId) {
  const expires = Date.now() + AUTH_CACHE_TTL_MS;
  const payload = `${userId}|${expires}`;
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
  return `${payload}.${sig}`;
}

function patronCookieVerify(value) {
  if (typeof value !== 'string') return null;
  const dot = value.lastIndexOf('.');
  if (dot < 0) return null;
  const payload = value.slice(0, dot);
  const sig = value.slice(dot + 1);
  const expected = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
  try {
    if (!crypto.timingSafeEqual(Buffer.from(sig, 'base64url'), Buffer.from(expected, 'base64url'))) return null;
  } catch { return null; }
  const [userId, expiresStr] = payload.split('|');
  if (!userId || Date.now() > Number(expiresStr)) return null;
  return userId;
}

const IDENTITY_COOKIE_TTL_MS = 24 * 60 * 60 * 1000; // 24h — re-login to refresh

function identityCookieSign(fullName) {
  const expires = Date.now() + IDENTITY_COOKIE_TTL_MS;
  const payload = `${Buffer.from(fullName, 'utf8').toString('base64url')}|${expires}`;
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
  return `${payload}.${sig}`;
}

function identityCookieVerify(value) {
  if (typeof value !== 'string') return null;
  const dot = value.lastIndexOf('.');
  if (dot < 0) return null;
  const payload = value.slice(0, dot);
  const sig = value.slice(dot + 1);
  const expected = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
  try {
    if (!crypto.timingSafeEqual(Buffer.from(sig, 'base64url'), Buffer.from(expected, 'base64url'))) return null;
  } catch { return null; }
  const [nameB64, expiresStr] = payload.split('|');
  if (!nameB64 || Date.now() > Number(expiresStr)) return null;
  try {
    return Buffer.from(nameB64, 'base64url').toString('utf8');
  } catch {
    return null;
  }
}

const EDIT_TOKEN_TTL_MS = 15 * 60 * 1000; // 15 minutes — plenty for filling out the edit form

// Ties an edit link to the exact row + the username it was matched under, so a leaked/guessed
// URL can't be used to edit someone else's row — the row's own username must still match on submit.
function editTokenSign({ month, rowNumber, username }) {
  const expires = Date.now() + EDIT_TOKEN_TTL_MS;
  const payload = [
    Buffer.from(month, 'utf8').toString('base64url'),
    rowNumber,
    Buffer.from(username, 'utf8').toString('base64url'),
    expires
  ].join('|');
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
  return `${payload}.${sig}`;
}

function editTokenVerify(value) {
  if (typeof value !== 'string') return null;
  const dot = value.lastIndexOf('.');
  if (dot < 0) return null;
  const payload = value.slice(0, dot);
  const sig = value.slice(dot + 1);
  const expected = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
  try {
    if (!crypto.timingSafeEqual(Buffer.from(sig, 'base64url'), Buffer.from(expected, 'base64url'))) return null;
  } catch { return null; }
  const [monthB64, rowNumberStr, usernameB64, expiresStr] = payload.split('|');
  if (!monthB64 || !usernameB64 || Date.now() > Number(expiresStr)) return null;
  try {
    return {
      month: Buffer.from(monthB64, 'base64url').toString('utf8'),
      rowNumber: Number(rowNumberStr),
      username: Buffer.from(usernameB64, 'base64url').toString('utf8')
    };
  } catch {
    return null;
  }
}

function identityCookieOptions() {
  return {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: IDENTITY_COOKIE_TTL_MS
  };
}

function getCachedPatron(userId) {
  const entry = patronCache.get(userId);
  if (!entry || Date.now() > entry.expires) {
    patronCache.delete(userId);
    return null;
  }
  return entry;
}

// Backoffs in ms between retry attempts: 2s, 8s, 20s, 40s (total ~70s across 5 attempts).
// Patreon's Cloudflare edge sometimes returns retry_after: 120; we can't wait that long in a
// live request, but spreading attempts over ~70s gives us multiple chances to hit a clear window.
const RETRY_BACKOFFS_MS = [2000, 8000, 20000, 40000];

function parseTierIds(raw) {
  return (raw || '')
    .split(',')
    .map(id => id.trim())
    .filter(id => id);
}

// Patreon API v2: only request relationship IDs — attributes on member/tier are unused.
// (Do not add memberships.campaign without the "campaigns" scope — it can 400.)
function extractPatreonMembership(userRes) {
  const memberships = userRes.data.included || [];
  let memberItems = memberships.filter(item => item.type === 'member');
  if (PATREON_CAMPAIGN_ID) {
    memberItems = memberItems.filter(
      m => m.relationships?.campaign?.data?.id === PATREON_CAMPAIGN_ID
    );
  }
  const userTierIds = memberItems.flatMap(item =>
    (item.relationships?.currently_entitled_tiers?.data || []).map(tier => tier.id)
  );
  return { memberItems, userTierIds };
}

function tierMatches(userTierIds, allowedTierIds) {
  return userTierIds.some(id => allowedTierIds.includes(id));
}

// ---------------------------------------------------------------------------
// Creator-side membership lookup (fix for the identity truncation bug).
//
// Problem: the /identity endpoint caps the `included` memberships array, so
// patrons with MANY pledges to other creators get their list cut before our
// campaign's row — extractPatreonMembership() then finds nothing and they're
// wrongly denied. Patreon offers no pagination on that include (confirmed on
// the dev forum, topics 11362/11400; the June-2026 504 variant was fixed
// server-side, the truncation was not).
//
// Fix: keep /identity minimal (it never truncates `data`), and check the
// membership where it can't be truncated — creator-side, via the campaign
// members endpoint with the Creator Access Token, which DOES paginate.
// Requires two env vars on Render:
//   PATREON_CAMPAIGN_ID          (already used by the user-side filter)
//   PATREON_CREATOR_ACCESS_TOKEN (Creator Access Token from the dev portal)
// Without the token the behaviour is unchanged (user-side check only).
// ---------------------------------------------------------------------------
const CREATOR_MEMBERS_CACHE_TTL_MS = 10 * 60 * 1000; // 10 min
const creatorMembersCache = { at: 0, map: new Map() }; // patreonUserId -> tier ids

async function getCreatorSideTierIds(patreonUserId) {
  const token = (process.env.PATREON_CREATOR_ACCESS_TOKEN || '').trim();
  if (!token || !PATREON_CAMPAIGN_ID || !patreonUserId) return null; // feature off
  if (Date.now() - creatorMembersCache.at < CREATOR_MEMBERS_CACHE_TTL_MS &&
      creatorMembersCache.map.size > 0) {
    return creatorMembersCache.map.get(patreonUserId) || [];
  }
  const map = new Map();
  let url = `https://www.patreon.com/api/oauth2/v2/campaigns/${PATREON_CAMPAIGN_ID}/members?` +
    querystring.stringify({
      include: 'user,currently_entitled_tiers',
      'fields[member]': 'patron_status',
      'page[count]': 200
    });
  let pages = 0;
  while (url && pages < 50) {
    const page = await patreonRequest('Patreon campaign members', () =>
      axios.get(url, {
        timeout: PATREON_HTTP_TIMEOUT_MS,
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: 'application/vnd.api+json',
          'User-Agent': PATREON_API_USER_AGENT
        }
      })
    );
    const users = new Map(
      (page.data.included || [])
        .filter(i => i.type === 'user')
        .map(i => [i.id, i])
    );
    for (const m of page.data.data || []) {
      const uid = m.relationships?.user?.data?.id;
      if (!uid || !users.has(uid)) continue;
      // Only members in good standing count (active paid, or free followers if
      // the tier list ever includes a free tier — patron_status null for declined).
      const status = m.attributes?.patron_status;
      if (status !== 'active_patron') continue;
      map.set(uid, (m.relationships?.currently_entitled_tiers?.data || []).map(t => t.id));
    }
    url = page.data.links?.next || null;
    pages += 1;
  }
  creatorMembersCache.at = Date.now();
  creatorMembersCache.map = map;
  return map.get(patreonUserId) || [];
}

/** Retries Patreon HTTP calls on timeouts / 502–504 (common when their edge is slow). */
async function patreonRequest(label, axiosCall) {
  const maxAttempts = RETRY_BACKOFFS_MS.length + 1;
  let lastErr;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await axiosCall();
    } catch (err) {
      lastErr = err;
      const ax = err.response;
      const bodyStr = typeof ax?.data === 'string' ? ax.data : '';
      const retry =
        attempt < maxAttempts &&
        (err.code === 'ECONNABORTED' ||
          err.code === 'ETIMEDOUT' ||
          err.code === 'ECONNRESET' ||
          err.code === 'EAI_AGAIN' ||
          ax?.status === 500 ||
          ax?.status === 502 ||
          ax?.status === 503 ||
          ax?.status === 504 ||
          ax?.status === 429 ||
          bodyStr.includes('timed out'));
      console.error(
        `${label} failed (attempt ${attempt}/${maxAttempts}):`,
        ax ? { status: ax.status, data: ax.data } : err.code || err.message
      );
      if (!retry) {
        // Tags which Patreon call failed so the /callback catch block can tell a dead
        // identity lookup (see the "too many memberships" note below) apart from a dead
        // token exchange (usually just an expired/reused code).
        err.patreonRequestLabel = label;
        throw err;
      }
      await new Promise(r => setTimeout(r, RETRY_BACKOFFS_MS[attempt - 1]));
    }
  }
  lastErr.patreonRequestLabel = label;
  throw lastErr;
}

const PUBLIC_DIR = path.join(__dirname, 'public');
const AVATAR_FILES = ['avatar.png', 'avatar.jpg', 'avatar.jpeg', 'avatar.webp'];

// Avatar: optional PROFILE_IMAGE_URL on Render overrides. Otherwise use the first file that exists:
// public/avatar.png | .jpg | .jpeg | .webp (commit the image in the repo).
function resolveLandingAvatarSrc() {
  const env = (process.env.PROFILE_IMAGE_URL || '').trim();
  if (env) return env;
  for (const name of AVATAR_FILES) {
    if (fs.existsSync(path.join(PUBLIC_DIR, name))) return `/${name}`;
  }
  return null;
}

const PATREON_PROFILE_URL =
  process.env.PATREON_PROFILE_URL || 'https://www.patreon.com/TGV9173';
const PIXIV_URL =
  (process.env.PIXIV_URL || 'https://www.pixiv.net/users/50533861').trim();
const DEVIANTART_URL =
  (process.env.DEVIANTART_URL || 'https://www.deviantart.com/tgv9173').trim();

function escapeHtmlAttr(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/</g, '&lt;');
}

// Reuses the same avatar image as the browser tab favicon — one less asset to maintain.
const FAVICON_HREF = resolveLandingAvatarSrc();
const FAVICON_LINK_TAG = FAVICON_HREF ? `<link rel="icon" href="${escapeHtmlAttr(FAVICON_HREF)}">` : '';

function loginRefererCookieOptions() {
  return {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production'
  };
}

// Store referer from /login in a cookie
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(PUBLIC_DIR));

// In-memory rate limit for the two submission forms: 4 submissions per rolling hour,
// keyed by verified identity AND by IP (whichever trips first). The request form is
// deliberately open to any Patreon account, and both forms relay images to catbox —
// without a cap the site is a free image-host proxy and the sheet can be spammed.
// In-memory is fine here: single Render instance, and a restart resetting counters
// only ever errs in the patron's favor.
const SUBMIT_LIMIT = 4;
const SUBMIT_WINDOW_MS = 60 * 60 * 1000;
const submitLog = new Map(); // key -> [timestamps]

function submitAllowed(keys) {
  const now = Date.now();
  if (submitLog.size > 5000) {
    for (const [k, times] of submitLog) {
      if (!times.some(t => now - t < SUBMIT_WINDOW_MS)) submitLog.delete(k);
    }
  }
  const blocked = keys.some(key => {
    const times = (submitLog.get(key) || []).filter(t => now - t < SUBMIT_WINDOW_MS);
    submitLog.set(key, times);
    return times.length >= SUBMIT_LIMIT;
  });
  if (blocked) return false;
  for (const key of keys) submitLog.get(key).push(now);
  return true;
}

function rateLimitKeys(req, fullName) {
  return [`id:${fullName.toLowerCase()}`, `ip:${req.ip}`];
}

function rateLimitedPage(backHref) {
  return commissionsPageShell({
    title: 'Too many submissions',
    bodyHtml: `
    <h1>Slow down a little</h1>
    <p>You have reached the limit of ${SUBMIT_LIMIT} submissions per hour. Please wait a bit and try again - your form content is not lost if you keep the tab open.</p>
    <div class="actions">
      <a class="btn btn-primary" href="${escapeHtmlAttr(backHref)}">Back to form</a>
      <a class="btn btn-secondary" href="/">Back to home</a>
    </div>`
  });
}

// Double-submit CSRF protection for the two authenticated-cookie POST forms below
// (commission request, wishlist request) — a plain session cookie alone doesn't stop
// another site from auto-submitting a form using it, so every such form carries a token
// that must match what's in the cookie.
function csrfTokenCookieOptions() {
  return { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production' };
}

// Cookie name is per-form ('commission' / 'request') so having both forms open in two
// tabs doesn't invalidate the older tab's token when the newer one issues its own.
function issueCsrfToken(res, formName) {
  const token = crypto.randomBytes(24).toString('hex');
  res.cookie(`csrf_token_${formName}`, token, csrfTokenCookieOptions());
  return token;
}

function verifyCsrfToken(req, formName) {
  const cookieToken = req.cookies[`csrf_token_${formName}`];
  const formToken = req.body?.csrfToken;
  if (!cookieToken || !formToken) return false;
  try {
    return crypto.timingSafeEqual(Buffer.from(cookieToken), Buffer.from(formToken));
  } catch {
    return false;
  }
}

app.get('/', (req, res) => {
  if (TRACK_HOME) track('page_home');

  const patreonHref = escapeHtmlAttr(PATREON_PROFILE_URL);
  const pixivHref = escapeHtmlAttr(PIXIV_URL);
  const deviantartHref = escapeHtmlAttr(DEVIANTART_URL);

  const avatarSrc = resolveLandingAvatarSrc();
  const avatarMarkup = avatarSrc
    ? `<img class="avatar" src="${escapeHtmlAttr(avatarSrc)}" width="168" height="168" alt="TGV9173">`
    : `<div class="avatar avatar-fallback" role="img" aria-label="TGV9173">TGV9173</div>`;

  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  ${FAVICON_LINK_TAG}
  <title>TGV9173 - patron tools</title>
  <style>
    :root { font-family: system-ui, sans-serif; line-height: 1.5; color: #1a1a1a; }
    body { margin: 0; min-height: 100vh; display: flex; flex-direction: column; align-items: center;
      justify-content: center; padding: 1.5rem; background: #f6f7f9; box-sizing: border-box; }
    main { width: 100%; max-width: 22rem; text-align: center; }
    .avatar {
      width: 168px; height: 168px; border-radius: 50%; object-fit: cover; margin: 0 auto 1rem;
      display: block; border: 3px solid #fff; box-shadow: 0 2px 12px rgba(0,0,0,0.08);
    }
    .avatar-fallback {
      background: linear-gradient(145deg, #6366f1 0%, #a855f7 100%);
      color: #fff; font-weight: 750; font-size: clamp(0.95rem, 4vw, 1.15rem);
      letter-spacing: 0.02em;
      display: flex; align-items: center; justify-content: center;
      text-shadow: 0 1px 2px rgba(0,0,0,0.15);
    }
    h1 { font-size: 1.35rem; font-weight: 650; margin: 0 0 0.35rem; }
    p.sub { margin: 0 0 1.75rem; font-size: 0.95rem; color: #444; }
    .actions { display: flex; flex-direction: column; gap: 0.75rem; }
    .social { display: flex; flex-wrap: wrap; gap: 0.75rem; justify-content: center; margin-top: 1.5rem; align-items: center; }
    a.icon-btn {
      width: 56px; height: 56px; border-radius: 50%;
      display: inline-flex; align-items: center; justify-content: center;
      text-decoration: none;
      transition: transform 0.15s ease, box-shadow 0.15s ease;
      box-shadow: 0 2px 8px rgba(0,0,0,0.12);
    }
    a.icon-btn:hover { transform: scale(1.06); box-shadow: 0 4px 14px rgba(0,0,0,0.18); }
    a.icon-btn:focus-visible { outline: 2px solid #2563eb; outline-offset: 3px; }
    a.icon-btn svg { width: 28px; height: 28px; display: block; }
    a.icon-btn.patreon { background: #FF424D; color: #fff; }
    a.icon-btn.pixiv { background: #0096FA; color: #fff; }
    a.icon-btn.deviantart { background: #05CC47; color: #fff; }
    a.btn {
      display: block; padding: 0.85rem 1rem; border-radius: 8px; text-decoration: none;
      font-weight: 600; font-size: 1rem; border: 2px solid transparent; transition: background 0.15s, border-color 0.15s;
    }
    a.btn:focus-visible { outline: 2px solid #2563eb; outline-offset: 2px; }
    a.btn-primary { background: #2563eb; color: #fff; }
    a.btn-primary:hover { background: #1d4ed8; }
    a.btn-secondary { background: #fff; color: #1a1a1a; border-color: #d1d5db; }
    a.btn-secondary:hover { background: #f3f4f6; border-color: #9ca3af; }
  </style>
</head>
<body>
  <main>
    ${avatarMarkup}
    <h1>TGV9173</h1>
    <p class="sub">My patron utilities: Dropbox folder after login, plus commission tools (beta).</p>
    <div class="actions">
      <a class="btn btn-primary" href="/login">Login and get folder link</a>
      <a class="btn btn-secondary" href="/commissions/new">Submit a commission (beta)</a>
      <a class="btn btn-secondary" href="/commissions">Commission tracking (beta)</a>
      <a class="btn btn-secondary" href="/requests/new">Submit a request (beta)</a>
    </div>
    <div class="social">
      <a class="icon-btn patreon" href="${patreonHref}" target="_blank" rel="noopener noreferrer" aria-label="TGV9173 on Patreon">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M22.957 7.21c-.004-3.064-2.391-5.576-5.191-6.482-3.478-1.125-8.064-.962-11.384.604C2.357 3.231 1.093 7.391 1.046 11.54c-.039 3.411.302 12.396 5.369 12.46 3.765.047 4.326-4.804 6.068-7.141 1.24-1.662 2.836-2.132 4.801-2.618 3.376-.836 5.678-3.501 5.673-7.031Z"/></svg>
      </a>
      <a class="icon-btn pixiv" href="${pixivHref}" target="_blank" rel="noopener noreferrer" aria-label="TGV9173 on Pixiv">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M4.935 0A4.924 4.924 0 0 0 0 4.935v14.13A4.924 4.924 0 0 0 4.935 24h14.13A4.924 4.924 0 0 0 24 19.065V4.935A4.924 4.924 0 0 0 19.065 0zm7.81 4.547c2.181 0 4.058.676 5.399 1.847a6.118 6.118 0 0 1 2.116 4.66c.005 1.854-.88 3.476-2.257 4.563-1.375 1.092-3.225 1.697-5.258 1.697-2.314 0-4.46-.842-4.46-.842v2.718c.397.116 1.048.365.635.779H5.79c-.41-.41.19-.65.644-.779V7.666c-1.053.81-1.593 1.51-1.868 2.031.32 1.02-.284.969-.284.969l-1.09-1.73s3.868-4.39 9.553-4.39zm-.19.971c-1.423-.003-3.184.473-4.27 1.244v8.646c.988.487 2.484.832 4.26.832h.01c1.596 0 2.98-.593 3.93-1.533.952-.948 1.486-2.183 1.492-3.683-.005-1.54-.504-2.864-1.42-3.86-.918-.992-2.274-1.645-4.002-1.646Z"/></svg>
      </a>
      <a class="icon-btn deviantart" href="${deviantartHref}" target="_blank" rel="noopener noreferrer" aria-label="TGV9173 on DeviantArt">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" aria-hidden="true"><path fill="currentColor" d="M19.207 4.794l.23-.43V0H15.07l-.436.44-2.058 3.925-.646.436H4.58v5.993h4.04l.36.436-4.175 7.98-.24.43V24H8.93l.436-.44 2.07-3.925.644-.436h7.35v-5.993h-4.05l-.36-.438 4.186-7.977z"/></svg>
      </a>
    </div>
  </main>
</body>
</html>`);
});

function commissionsPageShell({ title, bodyHtml, maxWidth = '26rem' }) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  ${FAVICON_LINK_TAG}
  <title>${escapeHtmlAttr(title)}</title>
  <style>
    :root { font-family: system-ui, sans-serif; line-height: 1.5; color: #1a1a1a; }
    body { margin: 0; min-height: 100vh; display: flex; flex-direction: column; align-items: center;
      justify-content: center; padding: 1.5rem; background: #f6f7f9; box-sizing: border-box; }
    main { width: 100%; max-width: ${maxWidth}; text-align: center; }
    h1 { font-size: 1.25rem; font-weight: 650; margin: 0 0 0.75rem; }
    p { margin: 0 0 1.25rem; color: #444; font-size: 0.95rem; }
    a { color: #2563eb; font-weight: 600; }
    a:focus-visible { outline: 2px solid #2563eb; outline-offset: 2px; border-radius: 4px; }
    .actions { display: flex; flex-direction: column; gap: 0.75rem; margin-top: 0.5rem; }
    a.btn { display: block; padding: 0.85rem 1rem; border-radius: 8px; text-decoration: none;
      font-weight: 600; font-size: 1rem; border: 2px solid transparent; }
    a.btn-primary { background: #2563eb; color: #fff; }
    a.btn-primary:hover { background: #1d4ed8; }
    a.btn-secondary { background: #fff; color: #1a1a1a; border-color: #d1d5db; }
    a.btn-secondary:hover { background: #f3f4f6; }
    .status-badge { display: inline-block; padding: 0.2rem 0.6rem; border-radius: 999px;
      font-size: 0.78rem; font-weight: 650; white-space: nowrap; }
    .status-not-started { background: #f3f4f6; color: #4b5563; border: 1px solid #d1d5db; }
    .status-preview-sent { background: #fdead2; color: #92400e; }
    .status-changes-requested { background: #fecaca; color: #991b1b; }
    .status-approved { background: #bbf7d0; color: #14532d; }
    .status-needs-regeneration { background: #fed7aa; color: #9a3412; }
    .status-ready-to-upload { background: #ccfbf1; color: #115e59; }
    .status-delivered { background: #bfdbfe; color: #1e3a8a; }
    .status-unknown { background: #f3f4f6; color: #4b5563; }
    p.beta-note { font-size: 0.8rem; color: #6b7280; margin-top: -0.5rem; }
    .filter-bar { display: flex; flex-wrap: wrap; gap: 0.4rem; margin: 0 0 1rem; }
    .filter-btn { font: inherit; cursor: pointer; padding: 0.3rem 0.7rem; border-radius: 999px;
      font-size: 0.78rem; font-weight: 650; border: 1px solid #d1d5db; background: #fff; color: #4b5563; }
    .filter-btn.active { background: #1a1a1a; color: #fff; border-color: #1a1a1a; }
    .table-scroll { width: 100%; overflow-x: auto; margin: 0 0 1.25rem; border: 1px solid #e5e7eb; border-radius: 10px; }
    table.commission-table { width: 100%; border-collapse: collapse; text-align: left; font-size: 0.85rem; background: #fff; }
    .commission-table th, .commission-table td { padding: 0.65rem 0.75rem; vertical-align: top; border-bottom: 1px solid #e5e7eb; }
    .commission-table thead th { font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.03em;
      color: #6b7280; background: #f9fafb; white-space: nowrap; }
    .commission-table tbody tr:last-child td { border-bottom: none; }
    .commission-table tbody tr.filtered-out { display: none; }
    .commission-table .character { font-weight: 650; overflow-wrap: anywhere; }
    .commission-table .outfit { color: #444; margin: 0.2rem 0 0; overflow-wrap: anywhere; }
    .commission-table .month { color: #6b7280; white-space: nowrap; }
    .commission-table .edit-link { font-weight: 650; white-space: nowrap; }
    .manual-search { text-align: left; display: flex; flex-direction: column; gap: 0.4rem; margin: 0 0 1.25rem; }
    .manual-search label { font-size: 0.85rem; font-weight: 600; color: #333; }
    .manual-search input[type="text"] { padding: 0.6rem 0.75rem; border-radius: 8px; border: 1px solid #d1d5db; font-size: 0.95rem; }
    .manual-search-details { text-align: left; margin: 0 0 1.25rem; }
    .manual-search-details summary { cursor: pointer; font-size: 0.85rem; font-weight: 600; color: #2563eb; margin-bottom: 0.75rem; }
    .manual-search-details .manual-search { margin-bottom: 0; }
    .edit-form { text-align: left; display: flex; flex-direction: column; gap: 0.3rem; margin-bottom: 1rem; }
    .edit-form label { font-size: 0.85rem; font-weight: 600; color: #333; margin-top: 0.5rem; }
    .edit-form input[type="text"], .edit-form textarea, .edit-form input[type="file"] {
      padding: 0.6rem 0.75rem; border-radius: 8px; border: 1px solid #d1d5db; font-size: 0.95rem;
      font-family: inherit; box-sizing: border-box; width: 100%;
    }
    .edit-form .actions { margin-top: 0.75rem; }
    .form-error { background: #fecaca; color: #991b1b; padding: 0.6rem 0.85rem; border-radius: 8px; font-size: 0.85rem; text-align: left; }
    .row-actions { white-space: nowrap; }
    .row-actions .approve-form { display: inline; margin-right: 0.5rem; }
    .btn-approve { background: #16a34a; color: #fff; border: none; border-radius: 7px; padding: 0.4rem 0.7rem;
      font-size: 0.8rem; font-weight: 600; cursor: pointer; font-family: inherit; }
    .btn-approve:hover { background: #15803d; }
    .dup-warn { background: #fef3c7; color: #92400e; border-radius: 8px; padding: 0.7rem 0.9rem;
      font-size: 0.85rem; text-align: left; margin-bottom: 0.75rem; }
    .field-help { font-size: 0.8rem; color: #6b7280; margin: 0.15rem 0 0.35rem; }
    .checkbox-group { display: flex; flex-direction: column; gap: 0.1rem; margin: 0.2rem 0 0.5rem; }
    .checkbox-group label { display: flex; align-items: center; gap: 0.5rem; font-size: 0.9rem;
      font-weight: 400; color: #1a1a1a; margin-top: 0.3rem; }
    .checkbox-group input[type="text"] { flex: 1; padding: 0.4rem 0.6rem; border-radius: 6px;
      border: 1px solid #d1d5db; font-size: 0.9rem; font-family: inherit; }
    .agree-check { display: flex; align-items: flex-start; gap: 0.5rem; margin-top: 1rem; font-size: 0.85rem; text-align: left; }
    .agree-check input { margin-top: 0.2rem; flex-shrink: 0; }
  </style>
</head>
<body>
  <main>
    ${bodyHtml}
  </main>
</body>
</html>`;
}

function statusBadgeClass(status) {
  const key = String(status || '').toLowerCase();
  if (key.includes('not started')) return 'status-not-started';
  if (key.includes('preview')) return 'status-preview-sent';
  if (key.includes('changes')) return 'status-changes-requested';
  if (key.includes('approved')) return 'status-approved';
  if (key.includes('regeneration')) return 'status-needs-regeneration';
  if (key.includes('ready to upload')) return 'status-ready-to-upload';
  if (key.includes('delivered')) return 'status-delivered';
  return 'status-unknown';
}

// Fallback search box, shown when the automatic Patreon-name match finds nothing.
// Stays behind Patreon login (this route already requires the commission_identity cookie) —
// otherwise anyone could type any username and read someone else's (often NSFW) request details.
function manualSearchFormHtml(prefillValue = '') {
  return `
    <form class="manual-search" method="GET" action="/commissions">
      <label for="manualUsername">Search by the Patreon username you submitted with</label>
      <input type="text" id="manualUsername" name="manualUsername" value="${escapeHtmlAttr(prefillValue)}" placeholder="your Patreon username" required>
      <button type="submit" class="btn btn-secondary">Search</button>
    </form>`;
}

function commissionRowHtml(c) {
  const token = editTokenSign({ month: c.month, rowNumber: c.rowNumber, username: c.username });
  const statusClass = statusBadgeClass(c.status);
  // Preview-sent rows get the approval pair: Approve closes the loop right here
  // instead of a Patreon DM round-trip; "Request changes" IS the existing edit flow
  // (editing a preview-sent row already flags it changes-requested), just labeled for
  // what it does at this stage.
  let actions = '';
  if (statusClass === 'status-preview-sent') {
    actions = `
          <form method="POST" action="/commissions/approve" class="approve-form">
            <input type="hidden" name="token" value="${escapeHtmlAttr(token)}">
            <button type="submit" class="btn-approve">Approve ✓</button>
          </form>
          <a class="edit-link" href="/commissions/edit?token=${encodeURIComponent(token)}">Request changes</a>`;
  } else if (c.editable) {
    actions = `<a class="edit-link" href="/commissions/edit?token=${encodeURIComponent(token)}">Edit</a>`;
  }
  return `
      <tr data-status="${statusClass}">
        <td>
          <div class="character">${escapeHtmlAttr(c.character || 'Untitled')}</div>
          <p class="outfit">${escapeHtmlAttr(c.outfit || '')}</p>
        </td>
        <td><span class="status-badge ${statusClass}">${escapeHtmlAttr(c.status)}</span></td>
        <td class="month">${escapeHtmlAttr(c.month)}</td>
        <td class="row-actions">${actions}</td>
      </tr>`;
}

const STATUS_FILTERS = [
  { key: 'all', label: 'All' },
  { key: 'status-not-started', label: 'Not started' },
  { key: 'status-preview-sent', label: 'Preview sent' },
  { key: 'status-changes-requested', label: 'Changes requested' },
  { key: 'status-approved', label: 'Approved' },
  { key: 'status-needs-regeneration', label: 'Need regeneration' },
  { key: 'status-ready-to-upload', label: 'Ready to upload' },
  { key: 'status-delivered', label: 'Delivered' }
];

// Client-side only — the table always renders every commission; filtering just hides rows.
// Keeps the page a plain server-rendered load with no extra request round-trip to filter.
function commissionTableHtml(commissions) {
  const rowsHtml = commissions.map(commissionRowHtml).join('');
  const filterButtonsHtml = STATUS_FILTERS.map((f, i) =>
    `<button type="button" class="filter-btn${i === 0 ? ' active' : ''}" data-filter="${f.key}">${escapeHtmlAttr(f.label)}</button>`
  ).join('');
  return `
    <div class="filter-bar" id="statusFilterBar">${filterButtonsHtml}</div>
    <div class="table-scroll">
      <table class="commission-table">
        <thead><tr><th>Commission</th><th>Status</th><th>Submitted</th><th></th></tr></thead>
        <tbody id="commissionTableBody">${rowsHtml}</tbody>
      </table>
    </div>
    <script>
      document.getElementById('statusFilterBar').addEventListener('click', function (e) {
        var btn = e.target.closest('.filter-btn');
        if (!btn) return;
        this.querySelectorAll('.filter-btn').forEach(function (b) { b.classList.remove('active'); });
        btn.classList.add('active');
        var filter = btn.dataset.filter;
        document.querySelectorAll('#commissionTableBody tr').forEach(function (row) {
          row.classList.toggle('filtered-out', filter !== 'all' && row.dataset.status !== filter);
        });
      });
    </script>`;
}

app.get('/commissions', async (req, res) => {
  const fullName = identityCookieVerify(req.cookies.commission_identity);

  if (!fullName) {
    track('page_commissions_logged_out');
    return res.send(commissionsPageShell({
      title: 'Commission tracking',
      bodyHtml: `
    <h1>Commission tracking</h1>
    <p>Log in with Patreon to see the status of your commission(s).</p>
    <div class="actions">
      <a class="btn btn-primary" href="/login?intent=commissions">Login to check status</a>
      <a class="btn btn-secondary" href="/">Back to home</a>
    </div>`
    }));
  }

  const manualUsername = typeof req.query.manualUsername === 'string' ? req.query.manualUsername.trim().slice(0, 200) : '';

  try {
    const commissions = manualUsername
      ? await findCommissionsByUsername(manualUsername)
      : await findCommissionsForPatron(fullName);
    track('page_commissions_viewed', { found: commissions.length, manualSearch: Boolean(manualUsername) });

    if (commissions.length === 0) {
      const notFoundBody = manualUsername
        ? `We couldn't find a commission under the username <strong>${escapeHtmlAttr(manualUsername)}</strong> either.`
        : `Your Patreon display name (<strong>${escapeHtmlAttr(fullName)}</strong>) doesn't match a commission - that's normal if you submitted with a different username.`;
      return res.send(commissionsPageShell({
        title: 'Commission tracking',
        bodyHtml: `
    <h1>No commission found</h1>
    <p>${notFoundBody} Enter the exact username you used when submitting your commission request:</p>
    ${manualSearchFormHtml(manualUsername)}
    <p>Still nothing? Message the creator directly on Patreon.</p>
    <div class="actions">
      <a class="btn btn-secondary" href="/">Back to home</a>
    </div>`
      }));
    }

    res.send(commissionsPageShell({
      title: 'Commission tracking',
      maxWidth: '40rem',
      bodyHtml: `
    <h1>Your commissions</h1>
    <p class="beta-note">Sorted by most recently submitted first. Commission tracking is in beta - let the creator know on Patreon if something looks off.</p>
    ${commissionTableHtml(commissions)}
    <details class="manual-search-details">
      <summary>Not seeing a commission? Search a different username</summary>
      ${manualSearchFormHtml(manualUsername)}
    </details>
    <div class="actions">
      <a class="btn btn-secondary" href="/">Back to home</a>
    </div>`
    }));
  } catch (err) {
    console.error('Commission lookup failed:', err.response?.data || err.message || err);
    track('page_commissions_lookup_failed');
    res.status(500).send(commissionsPageShell({
      title: 'Something went wrong',
      bodyHtml: `
    <h1>Something went wrong</h1>
    <p>We couldn't load commission data right now. Please try again in a moment.</p>
    <div class="actions">
      <a class="btn btn-primary" href="/commissions">Try again</a>
      <a class="btn btn-secondary" href="/">Back to home</a>
    </div>`
    }));
  }
});

function editFormPageHtml({ token, commission, error }) {
  const errorHtml = error ? `<p class="form-error">${escapeHtmlAttr(error)}</p>` : '';
  return commissionsPageShell({
    title: 'Edit commission',
    maxWidth: '30rem',
    bodyHtml: `
    <h1>Edit your commission</h1>
    <p class="month">${escapeHtmlAttr(commission.month)} - editing will flag this for the creator to re-review.</p>
    ${errorHtml}
    <form method="POST" action="/commissions/edit" enctype="multipart/form-data" class="edit-form">
      <input type="hidden" name="token" value="${escapeHtmlAttr(token)}">
      <label for="character">Character</label>
      <input type="text" id="character" name="character" value="${escapeHtmlAttr(commission.character)}" required>
      <label for="outfit">Outfit</label>
      <textarea id="outfit" name="outfit" rows="3">${escapeHtmlAttr(commission.outfit)}</textarea>
      <label for="maleType">Male character preference</label>
      <input type="text" id="maleType" name="maleType" value="${escapeHtmlAttr(commission.maleType)}">
      <label for="size">Size preference</label>
      <input type="text" id="size" name="size" value="${escapeHtmlAttr(commission.size)}">
      <label for="notes">Other requests</label>
      <textarea id="notes" name="notes" rows="4">${escapeHtmlAttr(commission.notes)}</textarea>
      <label for="image">Add a reference image (optional)</label>
      <input type="file" id="image" name="image" accept="image/png,image/jpeg,image/gif,image/webp">
      <div class="actions">
        <button type="submit" class="btn btn-primary">Save changes</button>
        <a class="btn btn-secondary" href="/commissions">Cancel</a>
      </div>
    </form>`
  });
}

app.get('/commissions/edit', async (req, res) => {
  const fullName = identityCookieVerify(req.cookies.commission_identity);
  if (!fullName) return res.redirect('/commissions');

  const decoded = editTokenVerify(req.query.token);
  if (!decoded) {
    return res.status(400).send(commissionsPageShell({
      title: 'Edit link expired',
      bodyHtml: `
    <h1>Edit link expired</h1>
    <p>This edit link is invalid or has expired. Go back and click Edit again.</p>
    <div class="actions"><a class="btn btn-secondary" href="/commissions">Back to commissions</a></div>`
    }));
  }

  const fresh = await getFreshCommissionRow(decoded.month, decoded.rowNumber);
  if (!fresh || fresh.username !== decoded.username || !fresh.editable) {
    return res.status(403).send(commissionsPageShell({
      title: "Can't edit this commission",
      bodyHtml: `
    <h1>Can't edit this commission</h1>
    <p>This commission is no longer editable (its status may have changed). Refresh your commission list to see the current status.</p>
    <div class="actions"><a class="btn btn-secondary" href="/commissions">Back to commissions</a></div>`
    }));
  }

  track('commission_edit_opened');
  res.send(editFormPageHtml({ token: req.query.token, commission: fresh }));
});

app.post('/commissions/edit', upload.single('image'), async (req, res) => {
  const fullName = identityCookieVerify(req.cookies.commission_identity);
  if (!fullName) return res.redirect('/commissions');

  const decoded = editTokenVerify(req.body.token);
  if (!decoded) {
    return res.status(400).send(commissionsPageShell({
      title: 'Edit link expired',
      bodyHtml: `
    <h1>Edit link expired</h1>
    <p>This edit link is invalid or has expired. Go back and click Edit again.</p>
    <div class="actions"><a class="btn btn-secondary" href="/commissions">Back to commissions</a></div>`
    }));
  }

  const fresh = await getFreshCommissionRow(decoded.month, decoded.rowNumber);
  if (!fresh || fresh.username !== decoded.username || !fresh.editable) {
    return res.status(403).send(commissionsPageShell({
      title: "Can't edit this commission",
      bodyHtml: `
    <h1>Can't edit this commission</h1>
    <p>This commission is no longer editable (its status may have changed). Refresh your commission list to see the current status.</p>
    <div class="actions"><a class="btn btn-secondary" href="/commissions">Back to commissions</a></div>`
    }));
  }

  const character = String(req.body.character || '').trim().slice(0, 2000);
  const outfit = String(req.body.outfit || '').trim().slice(0, 5000);
  const maleType = String(req.body.maleType || '').trim().slice(0, 2000);
  const size = String(req.body.size || '').trim().slice(0, 2000);
  let notes = String(req.body.notes || '').trim().slice(0, 5000);

  if (!character) {
    return res.status(400).send(editFormPageHtml({
      token: req.body.token,
      commission: { ...fresh, character, outfit, maleType, size, notes },
      error: 'Character is required.'
    }));
  }

  try {
    if (req.file) {
      const imageUrl = await uploadToCatbox(req.file);
      notes = notes ? `${notes}\n[Added reference image: ${imageUrl}]` : `[Added reference image: ${imageUrl}]`;
    }

    await updateCommissionRow(decoded.month, decoded.rowNumber, { character, outfit, maleType, size, notes });
    await flagRowChangesRequested(fresh.tabGid, decoded.rowNumber);
    notifyDiscord(`✏️ **${fresh.username}** requested changes on **${fresh.character}** (${decoded.month}).`);

    track('commission_edit_saved', { withImage: Boolean(req.file) });
    res.send(commissionsPageShell({
      title: 'Commission updated',
      bodyHtml: `
    <h1>Changes saved</h1>
    <p>Your commission has been updated and flagged for the creator to review.</p>
    <div class="actions"><a class="btn btn-primary" href="/commissions">Back to commissions</a></div>`
    }));
  } catch (err) {
    console.error('Commission edit failed:', err.response?.data || err.message || err);
    track('commission_edit_failed');
    res.status(500).send(editFormPageHtml({
      token: req.body.token,
      commission: { ...fresh, character, outfit, maleType, size, notes },
      error: 'Something went wrong saving your changes. Please try again.'
    }));
  }
});

// One-click preview approval from the tracking page. Same defense stack as the edit
// flow: signed token (month/row/username, TTL'd) + identity cookie must match the
// row's username + fresh re-read must still be in "preview sent" — so a stale tab
// can't approve a row whose status already moved on.
app.post('/commissions/approve', async (req, res) => {
  const fullName = identityCookieVerify(req.cookies.commission_identity);
  if (!fullName) return res.redirect('/commissions');
  const decoded = editTokenVerify(req.body.token);
  if (!decoded) {
    return res.status(403).send(commissionsPageShell({
      title: 'Link expired',
      bodyHtml: `
    <h1>Link expired</h1>
    <p>This approval link has expired. Refresh your commission list and try again.</p>
    <div class="actions"><a class="btn btn-primary" href="/commissions">Back to commissions</a></div>`
    }));
  }
  const fresh = await getFreshCommissionRow(decoded.month, decoded.rowNumber);
  const stillPreview = fresh && statusBadgeClass(fresh.status) === 'status-preview-sent';
  if (!fresh || fresh.username !== decoded.username || !isNameMatch(fullName, fresh.username) || !stillPreview) {
    return res.status(403).send(commissionsPageShell({
      title: "Can't approve this commission",
      bodyHtml: `
    <h1>Can't approve this commission</h1>
    <p>This commission is not awaiting approval (its status may have changed). Refresh your commission list to see the current status.</p>
    <div class="actions"><a class="btn btn-secondary" href="/commissions">Back to commissions</a></div>`
    }));
  }
  try {
    await setRowStatusByLabel(decoded.month, decoded.rowNumber, 'approved');
    track('commission_approved');
    notifyDiscord(`✅ **${fresh.username}** approved the preview for **${fresh.character}** (${decoded.month}).`);
    res.send(commissionsPageShell({
      title: 'Preview approved',
      bodyHtml: `
    <h1>Preview approved ✓</h1>
    <p>Thanks! Full generation for <strong>${escapeHtmlAttr(fresh.character)}</strong> will start soon.</p>
    <div class="actions"><a class="btn btn-primary" href="/commissions">Back to commissions</a></div>`
    }));
  } catch (err) {
    console.error('Approve failed:', err.message || err);
    track('commission_approve_failed');
    res.status(500).send(commissionsPageShell({
      title: 'Something went wrong',
      bodyHtml: `
    <h1>Something went wrong</h1>
    <p>Your approval could not be saved. Please try again.</p>
    <div class="actions"><a class="btn btn-primary" href="/commissions">Back to commissions</a></div>`
    }));
  }
});

// Mirrors the checkbox options on the live "commission form" Google Form exactly.
const MALE_TYPE_OPTIONS = ['white male', 'black male', 'ugly bastards'];
const SIZE_OPTIONS = ['Large (Default)', 'Medium/Average', 'Small', 'No preference'];

function checkboxGroupHtml({ name, options, selected = [], otherChecked = false, otherText = '' }) {
  const optionsHtml = options.map(opt => {
    const checked = selected.includes(opt) ? ' checked' : '';
    return `<label><input type="checkbox" name="${name}" value="${escapeHtmlAttr(opt)}"${checked}> ${escapeHtmlAttr(opt)}</label>`;
  }).join('');
  return `${optionsHtml}
    <label><input type="checkbox" name="${name}Other" value="1"${otherChecked ? ' checked' : ''}> Other:
      <input type="text" name="${name}OtherText" value="${escapeHtmlAttr(otherText)}"></label>`;
}

// Reads a `name` checkbox group (array if 2+ checked, plain string if exactly 1, absent
// if none) plus its paired Other checkbox+text, joined the same way the sheet already
// stores multi-select answers from the Google Form (comma-separated).
function readCheckboxGroup(body, name) {
  const raw = body[name];
  const selected = Array.isArray(raw) ? raw : (raw ? [raw] : []);
  const otherChecked = body[`${name}Other`] === '1';
  const otherText = String(body[`${name}OtherText`] || '').trim().slice(0, 500);
  const joined = [...selected, ...(otherChecked && otherText ? [otherText] : [])].join(', ');
  return { selected, otherChecked, otherText, joined };
}

function commissionRequestFormHtml({ fullName, csrfToken, values = {}, error }) {
  const errorHtml = error ? `<p class="form-error">${escapeHtmlAttr(error)}</p>` : '';
  return commissionsPageShell({
    title: 'Submit a commission',
    maxWidth: '32rem',
    bodyHtml: `
    <h1>Submit a commission</h1>
    <p>Submitting as <strong>${escapeHtmlAttr(fullName)}</strong> (detected from your Patreon login).</p>
    ${errorHtml}
    <form method="POST" action="/commissions/new" enctype="multipart/form-data" class="edit-form">
      <input type="hidden" name="csrfToken" value="${escapeHtmlAttr(csrfToken)}">

      <label for="character">What character do you want? *</label>
      <p class="field-help">Please specify the Character Name and the Series/Source Material. If there are multiple versions of this character, please specify exactly which one you want.</p>
      <textarea id="character" name="character" rows="2" required>${escapeHtmlAttr(values.character || '')}</textarea>

      <label for="outfit">What outfit do you want them to wear? *</label>
      <p class="field-help">Custom/alternate outfits are recommended over the default look — describe it in detail and include reference links (Pixiv or Booru) if you have any.</p>
      <textarea id="outfit" name="outfit" rows="3" required>${escapeHtmlAttr(values.outfit || '')}</textarea>

      <label for="images">Reference images (optional)</label>
      <p class="field-help">Upload up to ${REFERENCE_IMAGE_LIMIT} images (PNG, JPEG, GIF, or WEBP, 8MB max each) instead of or alongside pasting links above.</p>
      <input type="file" id="images" name="images" accept="image/png,image/jpeg,image/gif,image/webp" multiple>

      <label>What type of male character do you prefer? *</label>
      <p class="field-help">Male characters are generic, not specific named characters. For gangbang scenes the different male types can't be controlled individually. Lesbian and bestiality content isn't currently offered.</p>
      <div class="checkbox-group">
        ${checkboxGroupHtml({ name: 'maleType', options: MALE_TYPE_OPTIONS, selected: values.maleTypeSelected, otherChecked: values.maleTypeOtherChecked, otherText: values.maleTypeOtherText })}
      </div>

      <label>What size of penis would you prefer? (Optional)</label>
      <p class="field-help">AI can be inconsistent with exact sizing. For specific genitalia requests (uncircumcised/smegma, condoms, pubic hair, etc.), use Other.</p>
      <div class="checkbox-group">
        ${checkboxGroupHtml({ name: 'size', options: SIZE_OPTIONS, selected: values.sizeSelected, otherChecked: values.sizeOtherChecked, otherText: values.sizeOtherText })}
      </div>

      <label for="notes">Any other specific requests? (Optional)</label>
      <p class="field-help">Lighting, time of day, facial expressions, body proportions, etc. The standard poses included in every set can't be changed or removed, but extra poses can be requested here (include reference image links).</p>
      <textarea id="notes" name="notes" rows="3">${escapeHtmlAttr(values.notes || '')}</textarea>

      <label class="agree-check">
        <input type="checkbox" name="agree" value="1" required>
        <span>❗ I have read and agree to the commission rules ❗ — by checking this box I confirm I've read the latest guidelines and understand that failure to follow them may result in my commission being declined. <a href="https://www.patreon.com/posts/132896155" target="_blank" rel="noopener noreferrer">Read the full rules here</a>.</span>
      </label>

      <div class="actions">
        <button type="submit" class="btn btn-primary">Submit commission</button>
        <a class="btn btn-secondary" href="/">Cancel</a>
      </div>
    </form>`
  });
}

app.get('/commissions/new', async (req, res) => {
  const fullName = identityCookieVerify(req.cookies.commissioner_identity);
  if (!fullName) {
    track('page_commission_request_logged_out');
    return res.send(commissionsPageShell({
      title: 'Submit a commission',
      bodyHtml: `
    <h1>Submit a commission</h1>
    <p>Log in with your commissioner-tier Patreon account to submit a new commission request.</p>
    <div class="actions">
      <a class="btn btn-primary" href="/login?intent=commission-request">Login to submit a commission</a>
      <a class="btn btn-secondary" href="/">Back to home</a>
    </div>`
    }));
  }
  // Duplicate guard: one commission per month is the normal case, and a second row is
  // usually an accident (double-click, "did it go through?" resubmit). Warn with an
  // explicit escape hatch rather than blocking — multi-set patrons are a real thing.
  if (req.query.anyway !== '1') {
    try {
      const existing = await findCommissionsForPatron(fullName);
      const currentMonthRow = existing.find(c => statusBadgeClass(c.status) !== 'status-delivered'
        && c.month.toLowerCase().includes(MONTH_NAMES_LOWER[new Date().getMonth()]));
      if (currentMonthRow) {
        track('page_commission_request_duplicate_warned');
        return res.send(commissionsPageShell({
          title: 'You already have a commission this month',
          bodyHtml: `
    <h1>Already submitted this month</h1>
    <div class="dup-warn">You already have a commission in the ${escapeHtmlAttr(currentMonthRow.month)} tab:
      <strong>${escapeHtmlAttr(currentMonthRow.character || 'Untitled')}</strong>
      (status: ${escapeHtmlAttr(currentMonthRow.status)}).</div>
    <p>If you want to change that commission, edit it instead of submitting a new one. Only submit another if you genuinely have more than one commission slot.</p>
    <div class="actions">
      <a class="btn btn-primary" href="/commissions">View / edit my commission</a>
      <a class="btn btn-secondary" href="/commissions/new?anyway=1">Submit another anyway</a>
    </div>`
        }));
      }
    } catch (err) {
      // The guard is best-effort — a sheet hiccup must not block the form itself.
      console.error('Duplicate check failed (continuing to form):', err.message || err);
    }
  }
  track('page_commission_request_viewed');
  res.send(commissionRequestFormHtml({ fullName, csrfToken: issueCsrfToken(res, 'commission'), values: {}, error: null }));
});

app.post('/commissions/new', uploadReferenceImages.array('images', REFERENCE_IMAGE_LIMIT), async (req, res) => {
  const fullName = identityCookieVerify(req.cookies.commissioner_identity);
  if (!fullName) return res.redirect('/commissions/new');

  if (!submitAllowed(rateLimitKeys(req, fullName))) {
    track('commission_request_rate_limited');
    return res.status(429).send(rateLimitedPage('/commissions/new'));
  }

  if (!verifyCsrfToken(req, 'commission')) {
    return res.status(400).send(commissionsPageShell({
      title: 'Session expired',
      bodyHtml: `
    <h1>Session expired</h1>
    <p>Your form session expired. Please go back and try again.</p>
    <div class="actions"><a class="btn btn-primary" href="/commissions/new">Back to form</a></div>`
    }));
  }

  const character = String(req.body.character || '').trim().slice(0, 2000);
  const outfit = String(req.body.outfit || '').trim().slice(0, 5000);
  let notes = String(req.body.notes || '').trim().slice(0, 5000);
  const agreed = req.body.agree === '1';
  const maleType = readCheckboxGroup(req.body, 'maleType');
  const size = readCheckboxGroup(req.body, 'size');

  const values = {
    character, outfit, notes,
    maleTypeSelected: maleType.selected, maleTypeOtherChecked: maleType.otherChecked, maleTypeOtherText: maleType.otherText,
    sizeSelected: size.selected, sizeOtherChecked: size.otherChecked, sizeOtherText: size.otherText
  };

  const fail = (status, error) =>
    res.status(status).send(commissionRequestFormHtml({ fullName, csrfToken: issueCsrfToken(res, 'commission'), values, error }));

  if (!agreed) return fail(400, 'You must agree to the commission rules to submit.');
  if (!character) return fail(400, 'Character is required.');
  if (!outfit) return fail(400, 'Outfit is required.');
  if (!maleType.joined) return fail(400, 'Please select at least one male character preference.');

  try {
    if (req.files?.length) {
      const imageUrls = await uploadReferenceImagesToCatbox(req.files);
      const imageLines = imageUrls.map(url => `[Reference image: ${url}]`).join('\n');
      notes = notes ? `${notes}\n${imageLines}` : imageLines;
    }

    const { month } = await appendCommissionSubmission({
      username: fullName, character, outfit, maleType: maleType.joined, size: size.joined, notes
    });
    track('commission_request_submitted', { month, imageCount: req.files?.length || 0 });
    notifyDiscord(`📝 New commission from **${fullName}**: **${character.slice(0, 120)}** — ${outfit.slice(0, 180)} (${month} tab)`);
    res.send(commissionsPageShell({
      title: 'Commission submitted',
      bodyHtml: `
    <h1>Commission submitted!</h1>
    <p>Your commission request has been added to the ${escapeHtmlAttr(month)} tab. You can check its status any time on the commission tracking page.</p>
    <div class="actions">
      <a class="btn btn-primary" href="/commissions">View commission status</a>
      <a class="btn btn-secondary" href="/">Back to home</a>
    </div>`
    }));
  } catch (err) {
    console.error('Commission submission failed:', err.response?.data || err.message || err);
    track('commission_request_failed');
    fail(500, 'Something went wrong submitting your commission. Please try again.');
  }
});

function requestFormHtml({ fullName, csrfToken, values = {}, error }) {
  const errorHtml = error ? `<p class="form-error">${escapeHtmlAttr(error)}</p>` : '';
  const tier = values.tier || '';
  return commissionsPageShell({
    title: 'Submit a request',
    maxWidth: '32rem',
    bodyHtml: `
    <h1>Submit a request</h1>
    <p>Submitting as <strong>${escapeHtmlAttr(fullName)}</strong>.</p>
    <p class="field-help">This is for requests, not commissions — ideas submitted here aren't guaranteed to be made. If you want the custom set that comes with your subscription, use "Submit a commission" instead.</p>
    ${errorHtml}
    <form method="POST" action="/requests/new" enctype="multipart/form-data" class="edit-form">
      <input type="hidden" name="csrfToken" value="${escapeHtmlAttr(csrfToken)}">

      <label>What tier are you subscribed to on Patreon? *</label>
      <div class="checkbox-group">
        <label><input type="radio" name="tier" value="Supporter (5 $)"${tier === 'Supporter (5 $)' ? ' checked' : ''} required> Supporter (5 $)</label>
        <label><input type="radio" name="tier" value="Commissioner (11 $)"${tier === 'Commissioner (11 $)' ? ' checked' : ''}> Commissioner (11 $)</label>
      </div>

      <label for="character">What character/licence you'd want to see more of?</label>
      <p class="field-help">If there are multiple versions of the character, please specify which one.</p>
      <textarea id="character" name="character" rows="2">${escapeHtmlAttr(values.character || '')}</textarea>

      <label for="outfit">Is there any kind of outfit you'd want to see more of?</label>
      <p class="field-help">Describe in detail and provide an image reference if you have one.</p>
      <textarea id="outfit" name="outfit" rows="3">${escapeHtmlAttr(values.outfit || '')}</textarea>

      <label for="images">Reference images (optional)</label>
      <p class="field-help">Upload up to ${REFERENCE_IMAGE_LIMIT} images (PNG, JPEG, GIF, or WEBP, 8MB max each).</p>
      <input type="file" id="images" name="images" accept="image/png,image/jpeg,image/gif,image/webp" multiple>

      <label for="notes">Is there anything else you'd want to see more of, or any feedback?</label>
      <textarea id="notes" name="notes" rows="3">${escapeHtmlAttr(values.notes || '')}</textarea>

      <label class="agree-check">
        <input type="checkbox" name="agree" value="1" required>
        <span>By checking this box, I understand that this is a request form, not a submission form, and that TGV9173 is not forced to follow any of the ideas I submitted.</span>
      </label>

      <div class="actions">
        <button type="submit" class="btn btn-primary">Submit request</button>
        <a class="btn btn-secondary" href="/">Cancel</a>
      </div>
    </form>`
  });
}

app.get('/requests/new', (req, res) => {
  const fullName = identityCookieVerify(req.cookies.commission_identity);
  if (!fullName) {
    track('page_request_form_logged_out');
    return res.send(commissionsPageShell({
      title: 'Submit a request',
      bodyHtml: `
    <h1>Submit a request</h1>
    <p>Log in with Patreon to submit a character/outfit request or general feedback.</p>
    <div class="actions">
      <a class="btn btn-primary" href="/login?intent=requests">Login to submit a request</a>
      <a class="btn btn-secondary" href="/">Back to home</a>
    </div>`
    }));
  }
  track('page_request_form_viewed');
  res.send(requestFormHtml({ fullName, csrfToken: issueCsrfToken(res, 'request'), values: {}, error: null }));
});

app.post('/requests/new', uploadReferenceImages.array('images', REFERENCE_IMAGE_LIMIT), async (req, res) => {
  const fullName = identityCookieVerify(req.cookies.commission_identity);
  if (!fullName) return res.redirect('/requests/new');

  if (!submitAllowed(rateLimitKeys(req, fullName))) {
    track('request_rate_limited');
    return res.status(429).send(rateLimitedPage('/requests/new'));
  }

  if (!verifyCsrfToken(req, 'request')) {
    return res.status(400).send(commissionsPageShell({
      title: 'Session expired',
      bodyHtml: `
    <h1>Session expired</h1>
    <p>Your form session expired. Please go back and try again.</p>
    <div class="actions"><a class="btn btn-primary" href="/requests/new">Back to form</a></div>`
    }));
  }

  const tier = String(req.body.tier || '').trim().slice(0, 100);
  const character = String(req.body.character || '').trim().slice(0, 2000);
  const outfit = String(req.body.outfit || '').trim().slice(0, 5000);
  let notes = String(req.body.notes || '').trim().slice(0, 5000);
  const agreed = req.body.agree === '1';
  const values = { tier, character, outfit, notes };

  const fail = (status, error) =>
    res.status(status).send(requestFormHtml({ fullName, csrfToken: issueCsrfToken(res, 'request'), values, error }));

  if (!agreed) return fail(400, 'You must agree to the terms to submit.');
  if (!tier) return fail(400, 'Please select your Patreon tier.');

  try {
    if (req.files?.length) {
      const imageUrls = await uploadReferenceImagesToCatbox(req.files);
      const imageLines = imageUrls.map(url => `[Reference image: ${url}]`).join('\n');
      notes = notes ? `${notes}\n${imageLines}` : imageLines;
    }

    await appendRequestSubmission({ username: fullName, tier, character, outfit, notes });
    track('request_submitted', { imageCount: req.files?.length || 0 });
    notifyDiscord(`💡 New request from **${fullName}** (${tier}): ${(character || outfit || notes || 'see sheet').slice(0, 200)}`);
    res.send(commissionsPageShell({
      title: 'Request submitted',
      bodyHtml: `
    <h1>Request submitted!</h1>
    <p>Thanks — your request has been sent to the creator.</p>
    <div class="actions"><a class="btn btn-secondary" href="/">Back to home</a></div>`
    }));
  } catch (err) {
    console.error('Request submission failed:', err.response?.data || err.message || err);
    track('request_submission_failed');
    fail(500, 'Something went wrong submitting your request. Please try again.');
  }
});

const LOGIN_INTENTS = ['commissions', 'commission-request', 'requests'];

// ---------------------------------------------------------------------------
// R2-backed library (replaces the monthly Dropbox link once R2_* env is set).
// Access is the same patron_verified cookie the OAuth flow already sets, so a
// lapsed subscriber loses access the moment their cached cookie expires (1h),
// without any monthly link rotation. Download URLs are 15-min presigned R2
// URLs generated on click — no long-lived public link exists anywhere.
// ---------------------------------------------------------------------------

// --- Library extras: likes, search, series/tags -----------------------------

// Heart toggle button; wired by LIKE_JS on the client.
function likeBtn(kind, key, liked, count) {
  return `<button type="button" class="like${liked ? ' liked' : ''}" ` +
    `data-kind="${kind}" data-key="${escapeHtmlAttr(key)}" ` +
    `onclick="toggleLike(this)" title="Like">♥ <span class="n">${count}</span></button>`;
}

const LIB_CSS = `
  .filterbar { display: flex; flex-wrap: wrap; gap: .4rem; margin: 0 0 1rem;
    align-items: center; position: sticky; top: 0; background: #f6f7f9;
    padding: .5rem 0; z-index: 10; }
  .filterbar input[type="search"] { flex: 1 1 12rem; padding: .45rem .7rem;
    border: 1px solid #d0d5dd; border-radius: .5rem; font-size: .95rem; }
  .filterbar select, .filterbar button { padding: .45rem .6rem; font-size: .9rem;
    border: 1px solid #d0d5dd; border-radius: .5rem; background: #fff; max-width: 11rem; }
  .filterbar button { background: #175cd3; color: #fff; border-color: #175cd3; cursor: pointer; }
  .filterbar .clear { font-size: .85rem; color: #b42318; white-space: nowrap; }
  .set-list { display: flex; flex-direction: column; }
  .set-row { display: flex; align-items: center; gap: .5rem; padding: .35rem .2rem;
    border-bottom: 1px solid #eaecf0; min-height: 2.4rem; }
  .set-row:hover { background: #eef2f6; }
  .set-link { flex: 1; display: flex; align-items: center; gap: .6rem;
    min-width: 0; color: #1a1a1a; }
  .thumb { width: 48px; height: 48px; object-fit: cover; border-radius: 6px;
    flex-shrink: 0; background: #e4e7ec; }
  .month-row .set-name { font-weight: 600; }
  .set-name { font-weight: 500; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .set-series { color: #667085; font-size: .8rem; flex-shrink: 0; }
  .set-date { color: #98a2b3; font-size: .75rem; flex-shrink: 0; margin-left: auto; }
  .set-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
    gap: .8rem; margin-top: .6rem; }
  .set-card { position: relative; background: #fff; border-radius: .6rem;
    overflow: hidden; box-shadow: 0 1px 4px rgba(0,0,0,.08); }
  .set-card .card-link { display: block; color: #1a1a1a; }
  .set-card img { width: 100%; aspect-ratio: 3/4; object-fit: cover; display: block;
    background: #e4e7ec; }
  .set-card .no-thumb { display: block; width: 100%; aspect-ratio: 3/4; background: #e4e7ec; }
  .set-card .card-name { display: block; padding: .45rem .6rem 0; font-weight: 500;
    font-size: .85rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .set-card .card-series { display: block; padding: 0 .6rem; color: #667085;
    font-size: .75rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .set-card .card-date { display: block; padding: 0 .6rem .5rem; color: #98a2b3; font-size: .72rem; }
  .set-card .like { position: absolute; top: .3rem; right: .3rem;
    background: rgba(255,255,255,.85); border-radius: 2rem; }
  .like { border: 0; background: none; cursor: pointer; color: #98a2b3;
    font-size: .95rem; padding: .2rem .3rem; flex-shrink: 0; }
  .like.liked, .like:hover { color: #e0245e; }
  .muted { font-weight: 400; }
`;

const LIKE_JS = `<script>
async function toggleLike(btn) {
  try {
    const r = await fetch('/library/like', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ kind: btn.dataset.kind, key: btn.dataset.key })
    });
    if (!r.ok) return;
    const d = await r.json();
    btn.classList.toggle('liked', d.liked);
    btn.querySelector('.n').textContent = d.count;
  } catch (e) { /* network hiccup — leave the UI as-is */ }
}
</script>`;

function libraryPage({ title, body, headExtra = '' }) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  ${FAVICON_LINK_TAG}
  <title>${escapeHtmlAttr(title)} - TGV9173</title>
  <style>
    :root { font-family: system-ui, sans-serif; line-height: 1.5; color: #1a1a1a; }
    body { margin: 0; padding: 1.5rem; background: #f6f7f9; }
    main { max-width: 56rem; margin: 0 auto; }
    h1 { font-size: 1.25rem; }
    a { color: #175cd3; text-decoration: none; }
    .sets { display: grid; grid-template-columns: repeat(auto-fill, minmax(13rem, 1fr)); gap: .75rem; }
    .set { background: #fff; border-radius: .5rem; padding: .8rem 1rem;
      box-shadow: 0 1px 4px rgba(0,0,0,.07); display: block; }
    .set .count { color: #667085; font-size: .85rem; }
    .files { columns: 2 20rem; }
    .files a { display: block; padding: .15rem 0; overflow-wrap: anywhere; }
    .muted { color: #667085; font-size: .9rem; }
    ${headExtra}
  </style>
</head>
<body><main>${body}</main></body>
</html>`;
}

// Full-screen gallery for a set: thumbnail grid + GLightbox (MIT) for
// swipe / pinch-zoom on mobile. Slides are presigned R2 URLs, so image
// bytes flow straight from Cloudflare to the patron's browser.
function galleryPage({ title, setKey, slides, setLiked, setLikeCount, likedImages, imageLikeCounts }) {
  const cards = slides.map(s => {
    const liked = likedImages.has(s.key);
    const count = imageLikeCounts.get(s.key) || 0;
    return `<div class="row">` +
      `<a href="${escapeHtmlAttr(s.url)}" class="glightbox rowlink" data-gallery="set">` +
      `<img class="t" src="${escapeHtmlAttr(s.url)}" loading="lazy" alt="${escapeHtmlAttr(s.name)}">` +
      `<span class="name">${escapeHtmlAttr(s.name)}</span></a>` +
      likeBtn('image', s.key, liked, count) +
      `<a class="dl" href="${escapeHtmlAttr(s.dl)}" title="Download">⬇</a>` +
      `</div>`;
  }).join('\n');
  const slidesJson = JSON.stringify(
    slides.map(s => ({ key: s.key, dl: s.dl, liked: likedImages.has(s.key), n: imageLikeCounts.get(s.key) || 0 }))
  ).replace(/</g, '\\u003c');
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtmlAttr(title)}</title>
  <link rel="stylesheet" href="/vendor/glightbox/css/glightbox.min.css">
  <style>
    body { margin: 0; font-family: system-ui, sans-serif; background: #111; color: #eee; }
    header { padding: .8rem 1rem; display: flex; align-items: center; gap: 1rem; flex-wrap: wrap; }
    h1 { font-size: 1.1rem; margin: 0; flex: 1; }
    a.back { color: #9ecbff; text-decoration: none; font-size: .9rem; }
    a.zip { color: #ffd479; text-decoration: none; font-size: .9rem; }
    .list { display: flex; flex-direction: column; padding: 0 .4rem; }
    .row { display: flex; align-items: center; gap: .6rem; padding: .3rem .2rem;
      border-bottom: 1px solid #222; }
    .rowlink { flex: 1; display: flex; align-items: center; gap: .6rem; min-width: 0; }
    .rowlink img.t { width: 52px; height: 52px; flex-shrink: 0; border-radius: 6px;
      object-fit: cover; display: block; background: #222; }
    .row .name { flex: 1; font-size: .82rem; color: #aaa; overflow: hidden;
      text-overflow: ellipsis; white-space: nowrap; }
    .like { border: 0; background: none; cursor: pointer; color: #98a2b3; font-size: .95rem; padding: .25rem .3rem; }
    .like.liked, .like:hover { color: #e0245e; }
    a.dl { color: #9ecbff; text-decoration: none; font-size: 1rem; padding: .25rem .3rem; }
    /* viewer overlay actions */
    #lbActions { position: fixed; left: 50%; bottom: 1.2rem; transform: translateX(-50%);
      display: none; gap: .8rem; z-index: 1000000; }
    #lbActions button, #lbActions a { border: 0; border-radius: 2rem; padding: .55rem 1.1rem;
      font-size: 1rem; cursor: pointer; text-decoration: none;
      background: rgba(30,30,30,.85); color: #eee; backdrop-filter: blur(4px); }
    #lbActions button.liked { color: #e0245e; }
  </style>
</head>
<body>
  <header>
    <a class="back" href="/library">← Library</a>
    <h1>${title}</h1>
    ${likeBtn('set', setKey, setLiked, setLikeCount)}
    <a class="zip" href="/library/zip?prefix=${encodeURIComponent(setKey + '/')}">⬇ all (.zip)</a>
  </header>
  <div class="list">${cards}</div>
  <div id="lbActions">
    <button id="lbLike" type="button">♥ <span class="n">0</span></button>
    <a id="lbDl" href="#" title="Download">⬇</a>
  </div>
  <script src="/vendor/glightbox/js/glightbox.min.js"></script>
  <script>
    const SLIDES = ${slidesJson};
    const lb = GLightbox({ selector: '.glightbox', touchNavigation: true, zoomable: true, loop: true });
    const actions = document.getElementById('lbActions');
    const likeBtnEl = document.getElementById('lbLike');
    const dlEl = document.getElementById('lbDl');
    function currentSlide() { return SLIDES[lb.getActiveSlideIndex()]; }
    function refreshActions() {
      const s = currentSlide();
      if (!s) return;
      likeBtnEl.classList.toggle('liked', s.liked);
      likeBtnEl.querySelector('.n').textContent = s.n;
      dlEl.href = s.dl;
    }
    lb.on('open', () => { actions.style.display = 'flex'; refreshActions(); });
    lb.on('close', () => { actions.style.display = 'none'; });
    lb.on('slide_changed', refreshActions);
    likeBtnEl.addEventListener('click', async () => {
      const s = currentSlide();
      if (!s) return;
      try {
        const r = await fetch('/library/like', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ kind: 'image', key: s.key })
        });
        if (!r.ok) return;
        const d = await r.json();
        s.liked = d.liked; s.n = d.count;
        refreshActions();
      } catch (e) {}
    });
  </script>
  ${LIKE_JS}
</body>
</html>`;
}

// Dev-only shortcut for UI testing (phone on zerotier, etc.): sets a valid
// patron_verified cookie without the Patreon OAuth round-trip. Enabled ONLY
// when DEV_BYPASS=1 is set in the environment — never set it in production.
if (process.env.DEV_BYPASS === '1') {
  app.get('/dev/fake-login', (req, res) => {
    res.cookie('patron_verified', patronCookieSign('dev-user'), {
      httpOnly: true, sameSite: 'lax',
      secure: false, maxAge: AUTH_CACHE_TTL_MS
    });
    res.redirect('/library');
  });
  console.warn('⚠️  DEV_BYPASS=1 — /dev/fake-login is ENABLED, do not expose this build publicly');
}

app.get('/library', async (req, res) => {
  const patronId0 = patronCookieVerify(req.cookies.patron_verified);
  if (!patronId0) {
    track('library_denied_no_cookie');
    return res.redirect('/login');
  }
  if (ALIST_URL) {
    // AList serves the library UI; the catch-all proxy below enforces auth.
    return res.redirect('/sets');
  }
  if (!r2Configured()) {
    return res.status(501).send(errorPage({
      title: 'Not configured',
      body: 'The library is not hosted here yet.'
    }));
  }
  const patronId = patronCookieVerify(req.cookies.patron_verified);
  if (!patronId) {
    track('library_denied_no_cookie');
    return res.redirect('/login');
  }
  const prefix = String(req.query.prefix || '');
  // Path traversal guard: prefixes must stay inside the bucket root, no '..'.
  if (prefix.includes('..') || prefix.startsWith('/')) {
    return res.status(400).send(errorPage({ title: 'Invalid path', body: 'Invalid library path.' }));
  }
  try {
    // Paginated full listing of a prefix (all keys, any depth).
    const listAll = async (p) => {
      let keys = [], tok;
      do {
        const r = await listObjects({ prefix: p, delimiter: '', maxKeys: 1000, continuationToken: tok });
        keys = keys.concat(r.keys);
        tok = r.nextToken;
      } while (tok);
      return keys;
    };

    const meta = dbLib.allMeta();
    const likeCount = dbLib.likeCounts('set');
    const myLikes = dbLib.likedSet(patronId, 'set');
    const q = String(req.query.q || '').trim().toLowerCase();
    const tagF = String(req.query.tag || '').trim().toLowerCase();
    const seriesF = String(req.query.series || '').trim();
    const sort = String(req.query.sort || 'recent');
    const filtersActive = Boolean(q || tagF || seriesF);

    // Series/tag option lists with per-value set counts.
    const seriesCount = new Map();
    const tagCount = new Map();
    for (const m of meta.values()) {
      if (m.series) seriesCount.set(m.series, (seriesCount.get(m.series) || 0) + 1);
      for (const t of m.tags) tagCount.set(t, (tagCount.get(t) || 0) + 1);
    }
    const optsWithCount = (countMap, cur) => [...countMap.keys()].sort()
      .map(v => `<option value="${escapeHtmlAttr(v)}"${v === cur ? ' selected' : ''}>` +
        `${escapeHtmlAttr(v)} (${countMap.get(v)})</option>`).join('');
    const matchesFilters = (s) => {
      const m = s.meta || { series: null, tags: [] };
      if (q && !(s.short.toLowerCase().includes(q) ||
          (m.series || '').toLowerCase().includes(q) || m.tags.some(t => t.includes(q)))) return false;
      if (tagF && !m.tags.includes(tagF)) return false;
      if (seriesF && m.series !== seriesF) return false;
      return true;
    };
    const sorter = (a, b) =>
      sort === 'likes' ? (likeCount.get(b.key) || 0) - (likeCount.get(a.key) || 0) || a.short.localeCompare(b.short)
      : sort === 'name' ? a.short.localeCompare(b.short)
      : String(b.lastModified || '').localeCompare(String(a.lastModified || ''));
    const filterBar = () => {
      const activePills = [
        q && `q="${escapeHtmlAttr(String(req.query.q))}"`,
        seriesF && `series: ${escapeHtmlAttr(seriesF)}`,
        tagF && `tag: ${escapeHtmlAttr(tagF)}`
      ].filter(Boolean);
      return `<form method="get" action="/library" class="filterbar">` +
        `<input type="search" name="q" value="${escapeHtmlAttr(String(req.query.q || ''))}" placeholder="Search…">` +
        `<select name="series"><option value="">All series</option>${optsWithCount(seriesCount, seriesF)}</select>` +
        `<select name="tag"><option value="">All tags</option>${optsWithCount(tagCount, tagF)}</select>` +
        `<select name="sort">` +
        `<option value="recent"${sort === 'recent' ? ' selected' : ''}>Recent</option>` +
        `<option value="name"${sort === 'name' ? ' selected' : ''}>Name</option>` +
        `<option value="likes"${sort === 'likes' ? ' selected' : ''}>Most liked</option>` +
        `</select>` +
        `<button type="submit">Filter</button>` +
        (activePills.length ? `<a class="clear" href="/library">✕ ${activePills.join(' · ')}</a>` : '') +
        `</form>`;
    };
    const setCard = (s) => {
      const thumb = s.cover
        ? `<img loading="lazy" src="${escapeHtmlAttr(presignGet(s.cover, 3600))}" alt="">`
        : `<span class="no-thumb"></span>`;
      return `<div class="set-card">` +
        `<a class="card-link" href="/library?prefix=${encodeURIComponent(s.key + '/')}">` +
        thumb +
        `<span class="card-name">${escapeHtmlAttr(s.short)}</span>` +
        (s.meta && s.meta.series ? `<span class="card-series">${escapeHtmlAttr(s.meta.series)}</span>` : '') +
        (s.lastModified ? `<span class="card-date">${escapeHtmlAttr(s.lastModified.slice(0, 10))}</span>` : '') +
        `</a>` +
        likeBtn('set', s.key, myLikes.has(s.key), likeCount.get(s.key) || 0) +
        `</div>`;
    };

    if (!prefix) {
      const { prefixes: folders, keys: rootKeys } = await listObjects({});
      if (!folders.length && !rootKeys.length) {
        return res.send(libraryPage({
          title: 'Library',
          body: `<h1>Library</h1><p class="muted">The library is empty for now — check back later.</p>`
        }));
      }
      track('library_browse', { patronId, prefix: '(root)' });
      if (filtersActive) {
        // Global search across every scanned/synced set.
        let sets = [...meta.entries()].map(([short, m]) => ({
          key: m.month ? `${m.month}/${short}` : short,
          short, meta: m, cover: m.coverKey, lastModified: m.lastModified
        })).filter(matchesFilters);
        sets.sort(sorter);
        return res.send(libraryPage({
          title: 'Library',
          headExtra: LIB_CSS,
          body: `<h1>Library <span class="muted">(${sets.length} sets)</span></h1>` +
            filterBar() +
            `<div class="set-grid">${sets.map(setCard).join('\n') || '<p class="muted">No set matches.</p>'}</div>` +
            LIKE_JS
        }));
      }
      // Month folders (YYYY-MM), newest first; anything else is a loose set.
      const months = folders.filter(f => /^\d{4}-\d{2}\/$/.test(f)).sort().reverse();
      const loose = folders.filter(f => !/^\d{4}-\d{2}\/$/.test(f));
      const monthRows = months.map(m =>
        `<div class="set-row month-row">` +
        `<a class="set-link" href="/library?prefix=${encodeURIComponent(m)}">` +
        `<span class="set-name">📁 ${escapeHtmlAttr(m.replace(/\/$/, ''))}</span>` +
        `</a></div>`).join('\n');
      const looseRows = loose.map(f => {
        const name = f.replace(/\/$/, '');
        return setCard({ key: name, short: name, meta: meta.get(name), cover: meta.get(name)?.coverKey, lastModified: meta.get(name)?.lastModified });
      }).join('\n');
      return res.send(libraryPage({
        title: 'Library',
        headExtra: LIB_CSS,
        body: `<h1>Library</h1>` + filterBar() +
          `<div class="set-list">${monthRows}</div>` +
          (looseRows ? `<div class="set-grid">${looseRows}</div>` : '') +
          LIKE_JS
      }));
    }

    track('library_browse', { patronId, prefix });
    if (/^\d{4}-\d{2}\/$/.test(prefix)) {
      // Folder of sets (a month): group keys by set, newest sets first.
      const allKeys = await listAll(prefix);
      const bySet = new Map();
      for (const k of allKeys) {
        const rel = k.key.slice(prefix.length);
        if (!rel.includes('/')) continue;
        const setName = rel.split('/')[0];
        let s = bySet.get(setName);
        const inPreview = rel.split('/').includes('preview');
        if (!s) { s = { key: prefix + setName, short: setName, cover: inPreview ? null : k.key, lastModified: k.lastModified }; bySet.set(setName, s); }
        // Cover: prefer flat (non-preview) images, smallest key first.
        if (!inPreview && (!s.cover || k.key < s.cover)) s.cover = k.key;
        if (!s.cover && k.key < (s.coverFallback || '￿')) s.coverFallback = k.key;
        if (k.lastModified > s.lastModified) s.lastModified = k.lastModified;
      }
      for (const s of bySet.values()) s.cover = s.cover || s.coverFallback;
      let sets = [...bySet.values()];
      for (const s of sets) {
        s.meta = meta.get(s.short);
        dbLib.upsertScan(s.key, prefix.replace(/\/$/, ''), s.cover, s.lastModified);
      }
      sets = sets.filter(matchesFilters);
      sets.sort(sorter);
      const backLink = `<p><a class="clear" href="/library">← All months</a></p>`;
      return res.send(libraryPage({
        title: prefix.replace(/\/$/, ''),
        headExtra: LIB_CSS,
        body: `<h1>📁 ${escapeHtmlAttr(prefix.replace(/\/$/, ''))} <span class="muted">(${sets.length} sets)</span></h1>` +
          filterBar() + backLink +
          `<div class="set-grid">${sets.map(setCard).join('\n') || '<p class="muted">No set here yet.</p>'}</div>` +
          LIKE_JS
      }));
    }

    // A set: gallery view. Image files only, excluding preview/ subfolders
    // (those hold small duplicate JPGs used for client previews).
    const allKeys = await listAll(prefix);
    const slides = allKeys
      .filter(k => !k.key.endsWith('/') && /\.(png|jpe?g|webp|gif)$/i.test(k.key))
      .filter(k => !k.key.slice(prefix.length).split('/').includes('preview'))
      .map(k => ({
        name: k.key.slice(prefix.length),
        key: k.key,
        url: presignGet(k.key, 3600),
        dl: presignGet(k.key, 3600, { download: true })
      }));
    const setKey = prefix.replace(/\/$/, '');
    return res.send(galleryPage({
      title: escapeHtmlAttr(setKey.split('/').pop()),
      setKey,
      slides,
      setLiked: dbLib.likedSet(patronId, 'set').has(setKey),
      setLikeCount: dbLib.likeCounts('set').get(setKey) || 0,
      likedImages: dbLib.likedSet(patronId, 'image'),
      imageLikeCounts: dbLib.likeCounts('image')
    }));
  } catch (err) {
    console.error('R2 list failed:', err.response ? { status: err.response.status, data: String(err.response.data).slice(0, 300) } : err.message);
    track('library_error');
    return res.status(502).send(errorPage({
      title: 'Storage error',
      body: 'The library storage did not answer correctly. Please try again in a moment.'
    }));
  }
});

app.get('/library/file', async (req, res) => {
  if (!r2Configured()) return res.status(501).end();
  const patronId = patronCookieVerify(req.cookies.patron_verified);
  if (!patronId) return res.redirect('/login');
  const key = String(req.query.key || '');
  if (!key || key.includes('..') || key.startsWith('/')) {
    return res.status(400).send(errorPage({ title: 'Invalid path', body: 'Invalid file path.' }));
  }
  const download = req.query.download === '1';
  track('library_download', { patronId, key });
  res.redirect(302, presignGet(key, 900, { download }));
});

// Toggle a like on a set or an image. Body: { kind: 'set'|'image', key }.
app.post('/library/like', express.json(), (req, res) => {
  const patronId = patronCookieVerify(req.cookies.patron_verified);
  if (!patronId) return res.status(401).json({ error: 'unauthorized' });
  const { kind, key } = req.body || {};
  try {
    const result = dbLib.toggleLike(String(patronId), String(kind), String(key));
    track('library_like', { patronId, kind, liked: result.liked });
    res.json(result);
  } catch {
    res.status(400).json({ error: 'bad request' });
  }
});

// Stream a whole set as a zip. Files are pulled from R2 on the fly with
// presigned URLs and piped straight into the archive (no disk buffering).
// Note: a 200-image set is a few hundred MB and takes minutes — the
// connection stays open and streams progressively.
app.get('/library/zip', async (req, res) => {
  if (!r2Configured()) return res.status(501).end();
  const patronId = patronCookieVerify(req.cookies.patron_verified);
  if (!patronId) return res.redirect('/login');
  const prefix = String(req.query.prefix || '');
  if (!prefix || prefix.includes('..') || prefix.startsWith('/')) {
    return res.status(400).send(errorPage({ title: 'Invalid path', body: 'Invalid set path.' }));
  }
  const setName = prefix.replace(/\/$/, '') || 'set';
  try {
    const { keys } = await listObjects({ prefix, delimiter: '' });
    const files = keys.filter(k =>
      !k.key.endsWith('/') && !k.key.slice(prefix.length).split('/').includes('preview'));
    if (!files.length) {
      return res.status(404).send(errorPage({ title: 'Empty set', body: 'No files in this set.' }));
    }
    track('library_zip', { patronId, prefix, files: files.length });
    const archiver = require('archiver');
    const https = require('https');
    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition',
      `attachment; filename*=UTF-8''${encodeURIComponent(setName)}.zip`);
    const archive = archiver('zip', { store: true });
    archive.on('error', err => { console.error('zip error:', err.message); res.destroy(err); });
    archive.pipe(res);
    for (const f of files) {
      const url = presignGet(f.key, 600);
      const stream = await new Promise((resolve, reject) => {
        https.get(url, r => {
          if (r.statusCode !== 200) return reject(new Error(`R2 ${r.statusCode} on ${f.key}`));
          resolve(r);
        }).on('error', reject);
      });
      archive.append(stream, { name: f.key.slice(prefix.length) });
      await new Promise((resolve, reject) => {
        stream.on('end', resolve);
        stream.on('error', reject);
      });
    }
    await archive.finalize();
  } catch (err) {
    console.error('zip failed:', err.message);
    if (!res.headersSent) {
      res.status(502).send(errorPage({ title: 'Zip failed', body: 'Could not build the archive. Try again.' }));
    } else {
      res.destroy();
    }
  }
});

app.get('/login', (req, res) => {
  const referer = req.get('Referer') || 'No referer';
  const intent = LOGIN_INTENTS.includes(req.query.intent) ? req.query.intent : 'default';
  track('login_started', { referer: referer === 'No referer' ? undefined : referer.slice(0, 500), intent });
  // State is HMAC-signed — verified on return without any cookie, so it survives mobile tab suspension,
  // cookie-blocking proxies, and server restarts (given OAUTH_STATE_SECRET env var is set).
  const state = makeOAuthState(intent);
  res.cookie('login_referer', referer, loginRefererCookieOptions());
  const params = querystring.stringify({
    response_type: 'code',
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    scope: 'identity identity.memberships',
    state
  });
  res.redirect(`https://www.patreon.com/oauth2/authorize?${params}`);
});

function errorPage({ status, title, body, retryHref, messageHref, messageLabel }) {
  // When a "message the creator" CTA is present it's the recommended action, so it takes the
  // primary button style and Try again (less likely to help) steps down to secondary.
  const retryMarkup = retryHref
    ? `<a class="btn ${messageHref ? 'btn-secondary' : 'btn-primary'}" href="${escapeHtmlAttr(retryHref)}">Try again</a>`
    : '';
  const messageMarkup = messageHref
    ? `<a class="btn btn-primary" href="${escapeHtmlAttr(messageHref)}" target="_blank" rel="noopener noreferrer">${escapeHtmlAttr(messageLabel || 'Message me on Patreon')}</a>`
    : '';
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  ${FAVICON_LINK_TAG}
  <title>${escapeHtmlAttr(title)}</title>
  <style>
    :root { font-family: system-ui, sans-serif; line-height: 1.5; color: #1a1a1a; }
    body { margin: 0; min-height: 100vh; display: flex; flex-direction: column; align-items: center;
      justify-content: center; padding: 1.5rem; background: #f6f7f9; box-sizing: border-box; }
    main { width: 100%; max-width: 26rem; text-align: center; }
    h1 { font-size: 1.2rem; font-weight: 650; margin: 0 0 0.6rem; }
    p { margin: 0 0 1.4rem; color: #444; font-size: 0.95rem; }
    .actions { display: flex; flex-direction: column; gap: 0.75rem; }
    a.btn { display: block; padding: 0.85rem 1rem; border-radius: 8px; text-decoration: none;
      font-weight: 600; font-size: 1rem; border: 2px solid transparent; }
    a.btn-primary { background: #2563eb; color: #fff; }
    a.btn-primary:hover { background: #1d4ed8; }
    a.btn-secondary { background: #fff; color: #1a1a1a; border-color: #d1d5db; }
    a.btn-secondary:hover { background: #f3f4f6; }
  </style>
</head>
<body>
  <main>
    <h1>${escapeHtmlAttr(title)}</h1>
    <p>${body}</p>
    <div class="actions">
      ${messageMarkup}
      ${retryMarkup}
      <a class="btn btn-secondary" href="/">Back to home</a>
    </div>
  </main>
</body>
</html>`;
}

app.get('/callback', async (req, res) => {
  const oauthError = req.query.error;
  const oauthDescription = req.query.error_description;
  const code = req.query.code;
  const returnedState = req.query.state;
  const loginReferer = req.cookies.login_referer || 'No referer';

  if (oauthError) {
    console.error('OAuth denied or error:', oauthError, oauthDescription || '');
    track('oauth_patron_cancelled_or_error', {
      oauthError,
      oauthDescription: oauthDescription ? oauthDescription.slice(0, 300) : undefined
    });
    res.clearCookie('login_referer', loginRefererCookieOptions());
    res.clearCookie('oauth_state', loginRefererCookieOptions());
    return res.status(400).send(
      errorPage({
        title: 'Login cancelled',
        body: `Patreon reported: <strong>${escapeHtmlAttr(oauthError)}</strong>. Please try again.`,
        retryHref: '/login'
      })
    );
  }

  const intent = verifyOAuthState(returnedState);
  if (!intent) {
    track('oauth_state_mismatch', { noState: !returnedState, invalidHmac: Boolean(returnedState) });
    res.clearCookie('login_referer', loginRefererCookieOptions());
    return res.status(400).send(
      errorPage({
        title: 'Session expired',
        body: 'Your login session has expired. Please start the login flow again.',
        retryHref: '/login'
      })
    );
  }

  if (!code) {
    track('oauth_missing_code');
    res.clearCookie('login_referer', loginRefererCookieOptions());
    return res.status(400).send(
      errorPage({
        title: 'Missing authorization code',
        body: 'The authorization code is missing. Please start the login flow again.',
        retryHref: '/login'
      })
    );
  }

  try {
    const tokenRes = await patreonRequest('Patreon token exchange', () =>
      axios.post(
        'https://www.patreon.com/api/oauth2/token',
        querystring.stringify({
          code,
          grant_type: 'authorization_code',
          client_id: CLIENT_ID,
          client_secret: CLIENT_SECRET,
          redirect_uri: REDIRECT_URI
        }),
        {
          timeout: PATREON_HTTP_TIMEOUT_MS,
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': PATREON_API_USER_AGENT
          }
        }
      )
    );

    const accessToken = tokenRes.data.access_token;

    // Check HMAC-signed cache cookie — lets returning users bypass the identity API call
    // (token exchange above already proved Patreon authorized them; we're only caching the tier result)
    // Skipped for commissions/commission-request: both need full_name regardless of the cached tier result.
    const cachedUserId = intent === 'default' ? patronCookieVerify(req.cookies.patron_verified) : null;
    if (cachedUserId) {
      const cached = getCachedPatron(cachedUserId);
      if (cached) {
        res.clearCookie('login_referer', loginRefererCookieOptions());
        if (cached.matched) {
          if (!successTarget()) {
            track('oauth_server_misconfigured', { missingEnv: 'SUCCESS_REDIRECT_URI' });
            return res.status(500).send(
              errorPage({ title: 'Server configuration error', body: 'Missing success redirect. Please contact the creator.' })
            );
          }
          track('oauth_success', { patreonUserId: cachedUserId, cached: true });
          return res.redirect(successTarget());
        } else {
          track('oauth_tier_denied', { patreonUserId: cachedUserId, cached: true });
          return res.status(403).send(
            errorPage({
              title: 'Access denied',
              body: 'Your Patreon account is not subscribed to a required tier. If you believe this is a mistake, make sure your payment is up to date on Patreon and try again.',
              retryHref: '/login'
            })
          );
        }
      }
    }

    // Patreon API v2: only request relationship IDs — attributes on member/tier are unused.
    // (Do not add memberships.campaign without the "campaigns" scope — it can 400.)
    const identityQuery = querystring.stringify({
      include: 'memberships,memberships.currently_entitled_tiers',
      'fields[user]': 'full_name',
      'fields[member]': 'patron_status',
      'fields[tier]': 'title'
    });

    const userRes = await patreonRequest('Patreon identity', () =>
      axios.get(`https://www.patreon.com/api/oauth2/v2/identity?${identityQuery}`, {
        timeout: PATREON_HTTP_TIMEOUT_MS,
        headers: {
          Authorization: `Bearer ${accessToken}`,
          Accept: 'application/vnd.api+json',
          'User-Agent': PATREON_API_USER_AGENT
        }
      })
    );

    // Commission tracking and the request form both just need proof of Patreon
    // identity, not a tier match — sign the name into a cookie and hand off. The
    // 'requests' intent exists so a login started FROM the request form lands back on
    // it, instead of dumping the user on the tracking page to navigate back by hand.
    if (intent === 'commissions' || intent === 'requests') {
      const fullName = userRes.data?.data?.attributes?.full_name;
      res.clearCookie('login_referer', loginRefererCookieOptions());
      if (!fullName) {
        track('oauth_commissions_missing_name');
        return res.status(500).send(
          errorPage({ title: 'Login error', body: 'Patreon did not return a name for your account. Please try again.', retryHref: `/login?intent=${intent}` })
        );
      }
      res.cookie('commission_identity', identityCookieSign(fullName), identityCookieOptions());
      track(intent === 'requests' ? 'oauth_requests_success' : 'oauth_commissions_success');
      return res.redirect(intent === 'requests' ? '/requests/new' : '/commissions');
    }

    // Submitting a new paid commission needs BOTH proof of identity (to attribute the
    // row) and a real tier check (a public URL isn't gated the way "shared only in the
    // commissioner-tier Patreon chat" was) — checked against COMMISSIONER_TIER_IDS,
    // deliberately a separate env var from ALLOWED_TIER_IDS since that one may allow
    // broader tiers than just the one commissions are actually included with.
    if (intent === 'commission-request') {
      const fullName = userRes.data?.data?.attributes?.full_name;
      res.clearCookie('login_referer', loginRefererCookieOptions());
      if (!fullName) {
        track('oauth_commission_request_missing_name');
        return res.status(500).send(
          errorPage({ title: 'Login error', body: 'Patreon did not return a name for your account. Please try again.', retryHref: '/login?intent=commission-request' })
        );
      }
      const commissionerTierIds = parseTierIds(process.env.COMMISSIONER_TIER_IDS);
      const { userTierIds } = extractPatreonMembership(userRes);
      let matched = tierMatches(userTierIds, commissionerTierIds);
      // Creator-side rescue for the identity truncation bug (see default flow).
      if (!matched) {
        const crUserId = userRes.data?.data?.id;
        try {
          const creatorTierIds = await getCreatorSideTierIds(crUserId);
          if (creatorTierIds !== null) {
            matched = tierMatches(creatorTierIds, commissionerTierIds);
            if (matched) track('oauth_commission_request_rescued_creator_side', { patreonUserId: crUserId });
          }
        } catch (err) {
          console.error('Creator-side member lookup failed (commission-request):',
            err.response ? { status: err.response.status, data: err.response.data } : err.message);
        }
      }
      if (!matched) {
        console.error('Commission-request tier check failed. User tier IDs:', userTierIds, 'Allowed COMMISSIONER_TIER_IDS:', commissionerTierIds);
        track('oauth_commission_request_tier_denied', { entitledTierCount: userTierIds.length });
        return res.status(403).send(
          errorPage({
            title: 'Access denied',
            body: 'Submitting a new commission request requires the commissioner tier on Patreon. If you believe this is a mistake, make sure your payment is up to date on Patreon and try again.',
            retryHref: '/login?intent=commission-request'
          })
        );
      }
      const signedIdentity = identityCookieSign(fullName);
      res.cookie('commissioner_identity', signedIdentity, identityCookieOptions());
      // Also sign them in for identity-only commission tracking — a verified commissioner
      // is automatically eligible for that lower-stakes check too, saving a second login
      // when they click through to view the commission they just submitted.
      res.cookie('commission_identity', signedIdentity, identityCookieOptions());
      track('oauth_commission_request_success');
      return res.redirect('/commissions/new');
    }

    const allowedTierIds = parseTierIds(process.env.ALLOWED_TIER_IDS);
    const { memberItems, userTierIds } = extractPatreonMembership(userRes);
    if (PATREON_CAMPAIGN_ID && memberItems.length === 0) {
      console.error(
        'Tier check: no member row for PATREON_CAMPAIGN_ID',
        PATREON_CAMPAIGN_ID,
        '(wrong ID, patron not in this campaign, or identity include truncated)'
      );
    }
    let matched = tierMatches(userTierIds, allowedTierIds);
    const patreonUserId = userRes.data?.data?.id;

    // Creator-side rescue: when the user-side identity include was truncated
    // (patrons with many pledges), check the membership via the campaign
    // members endpoint instead — it paginates, so nothing is lost.
    if (!matched && patreonUserId) {
      try {
        const creatorTierIds = await getCreatorSideTierIds(patreonUserId);
        if (creatorTierIds !== null) {
          matched = tierMatches(creatorTierIds, allowedTierIds);
          if (matched) {
            track('oauth_tier_rescued_creator_side', { patreonUserId });
          } else {
            console.error('Creator-side check: user', patreonUserId,
              'not an active patron of campaign', PATREON_CAMPAIGN_ID);
          }
        }
      } catch (err) {
        console.error('Creator-side member lookup failed (falling back to user-side result):',
          err.response ? { status: err.response.status, data: err.response.data } : err.message);
      }
    }

    // Per-user whitelist for patrons whose accounts trigger Patreon's identity API 504 bug
    // (large pledge history causes currently_entitled_tiers to time out — Patreon bug June 2026).
    // Set PATREON_ALLOWED_USER_IDS=id1,id2 in Render env to bypass the tier check for specific users.
    const allowedUserIds = (process.env.PATREON_ALLOWED_USER_IDS || '')
      .split(',').map(id => id.trim()).filter(Boolean);
    if (patreonUserId && allowedUserIds.includes(patreonUserId)) {
      patronCache.set(patreonUserId, { matched: true, expires: Date.now() + AUTH_CACHE_TTL_MS });
      res.cookie('patron_verified', patronCookieSign(patreonUserId), {
        httpOnly: true, sameSite: 'lax',
        secure: process.env.NODE_ENV === 'production', maxAge: AUTH_CACHE_TTL_MS
      });
      track('oauth_success', { patreonUserId, whitelisted: true });
      res.clearCookie('login_referer', loginRefererCookieOptions());
      return res.redirect(successTarget());
    }

    // Cache the result and set signed cookie for future logins within 1 hour
    if (patreonUserId) {
      patronCache.set(patreonUserId, { matched, expires: Date.now() + AUTH_CACHE_TTL_MS });
      res.cookie('patron_verified', patronCookieSign(patreonUserId), {
        httpOnly: true,
        sameSite: 'lax',
        secure: process.env.NODE_ENV === 'production',
        maxAge: AUTH_CACHE_TTL_MS
      });
    }

    if (matched) {
      if (!successTarget()) {
        console.error('SUCCESS_REDIRECT_URI is not set');
        track('oauth_server_misconfigured', { missingEnv: 'SUCCESS_REDIRECT_URI' });
        res.clearCookie('login_referer', loginRefererCookieOptions());
        return res.status(500).send(
          errorPage({ title: 'Server configuration error', body: 'Missing success redirect. Please contact the creator.' })
        );
      }
      track('oauth_success', { patreonUserId });
      res.clearCookie('login_referer', loginRefererCookieOptions());
      res.redirect(successTarget());
    } else {
      console.error(
        'Access denied: tier mismatch. User tier IDs:',
        userTierIds,
        'Allowed ALLOWED_TIER_IDS:',
        allowedTierIds
      );
      console.error('Referer from /login on access denial:', loginReferer);
      track('oauth_tier_denied', {
        patreonUserId,
        entitledTierCount: userTierIds.length,
        campaignFilterActive: Boolean(PATREON_CAMPAIGN_ID)
      });
      res.clearCookie('login_referer', loginRefererCookieOptions());
      return res.status(403).send(
        errorPage({
          title: 'Access denied',
          body: 'Your Patreon account is not subscribed to a required tier. If you believe this is a mistake, make sure your payment is up to date on Patreon and try again.',
          retryHref: '/login'
        })
      );
    }

  } catch (err) {
    const ax = err.response;
    const data = ax?.data;
    const oauthErr = typeof data === 'object' && data && data.error;

    console.error(
      'OAuth error:',
      ax ? { status: ax.status, data } : err.code || err.message || err
    );
    console.error('Referer from /login on OAuth failure:', loginReferer);
    res.clearCookie('login_referer', loginRefererCookieOptions());

    if (oauthErr === 'invalid_grant') {
      track('oauth_invalid_grant');
      return res.status(400).send(
        errorPage({
          title: 'Login link expired',
          body: 'This authorization code has already been used or has expired. Do not refresh the Patreon return page. Please start the login flow again.',
          retryHref: '/login'
        })
      );
    }

    const isPatreonOverloaded = ax?.status === 504 || ax?.status === 503 || ax?.status === 502;

    // Known Patreon-side bug: the identity endpoint (which pulls in every membership via
    // include=memberships) can just stop responding for accounts subscribed to a lot of
    // creators, instead of returning a normal error. Retrying won't fix it — it's on
    // Patreon's end — so point the patron at a manual workaround instead of "try again".
    if (err.patreonRequestLabel === 'Patreon identity') {
      track('oauth_identity_unresponsive', {
        httpStatus: ax?.status,
        networkCode: err.code || undefined
      });
      return res.status(502).send(
        errorPage({
          title: "Couldn't verify your Patreon account",
          body: `This looks like a known Patreon bug: if you're subscribed to a lot of creators, Patreon's servers sometimes fail to respond at all when we check your account. It isn't something wrong with your payment or this site, and retrying usually won't help.<br><br>Please send me a DM on Patreon so I can check your account manually. And if you'd like to help get this fixed for everyone, reporting it to Patreon support helps too.`,
          retryHref: '/login',
          messageHref: PATREON_PROFILE_URL,
          messageLabel: 'Message me on Patreon'
        })
      );
    }

    track('oauth_request_failed', {
      httpStatus: ax?.status,
      patreonOAuthError: oauthErr || undefined,
      networkCode: err.code || undefined
    });
    return res.status(500).send(
      errorPage({
        title: isPatreonOverloaded ? 'Patreon servers are busy' : 'Authentication error',
        body: isPatreonOverloaded
          ? 'Patreon\'s servers are currently overloaded and could not verify your tier after several retries. Your Patreon account is fine — please wait 2–3 minutes and try again.'
          : 'Patreon returned an error while verifying your account. Please try again.',
        retryHref: '/login'
      })
    );
  }
});

// Multer throws synchronously (file too large, wrong mimetype, too many files) before the
// route handler runs — catch it here so uploads fail with a normal error page instead of a
// raw stack trace. Three different forms use multer now, so the "back" link and analytics
// event depend on which path the upload came from.
const UPLOAD_ROUTE_INFO = {
  '/commissions/edit': { backHref: req => `/commissions/edit?token=${encodeURIComponent(req.body?.token || req.query?.token || '')}`, backLabel: 'Back to edit form', event: 'commission_edit_upload_rejected' },
  '/commissions/new': { backHref: () => '/commissions/new', backLabel: 'Back to form', event: 'commission_request_upload_rejected' },
  '/requests/new': { backHref: () => '/requests/new', backLabel: 'Back to form', event: 'request_upload_rejected' }
};

app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError || err?.message?.includes('multipart')) {
    console.error('Upload error:', err.message);
    const routeInfo = UPLOAD_ROUTE_INFO[req.path] || UPLOAD_ROUTE_INFO['/commissions/edit'];
    track(routeInfo.event, { code: err.code });

    let message = 'That file could not be uploaded - please use a PNG, JPEG, GIF, or WEBP image.';
    if (err.code === 'LIMIT_FILE_SIZE') message = 'That image is too large (8MB max).';
    else if (err.invalidType) message = 'One of the files is not a supported image type - please use PNG, JPEG, GIF, or WEBP.';
    else if (err.code === 'LIMIT_FILE_COUNT' || err.code === 'LIMIT_UNEXPECTED_FILE') message = `Too many images - ${REFERENCE_IMAGE_LIMIT} max.`;

    return res.status(400).send(commissionsPageShell({
      title: 'Upload failed',
      bodyHtml: `
    <h1>Upload failed</h1>
    <p>${message}</p>
    <div class="actions">
      <a class="btn btn-primary" href="${escapeHtmlAttr(routeInfo.backHref(req))}">${escapeHtmlAttr(routeInfo.backLabel)}</a>
      <a class="btn btn-secondary" href="/commissions">Back to commissions</a>
    </div>`
    }));
  }
  next(err);
});

const port = process.env.PORT || 3000;
// Static vendor assets for the gallery viewer (GLightbox, MIT).
app.use('/vendor/glightbox', express.static(
  path.join(__dirname, 'node_modules', 'glightbox', 'dist'),
  { maxAge: '7d', immutable: true }
));

// --- AList proxy (optional) -------------------------------------------------
// When ALIST_URL is set (e.g. http://127.0.0.1:5244), every request that did
// not match a route above is proxied to the AList instance serving the R2
// bucket UI. AList's SPA uses absolute paths (/api, /d, /p, /assets), so this
// must be a catch-all — auth (patron cookie) is enforced here, before any
// byte reaches AList.
const ALIST_URL = process.env.ALIST_URL || '';
if (ALIST_URL) {
  const alistTarget = new URL(ALIST_URL);
  app.use((req, res) => {
    const patronId = patronCookieVerify(req.cookies.patron_verified);
    if (!patronId) {
      track('alist_proxy_denied_no_cookie');
      if (req.method !== 'GET') return res.status(401).end();
      return res.redirect('/login');
    }
    const proxy = http.request({
      hostname: alistTarget.hostname,
      port: alistTarget.port,
      path: req.originalUrl,
      method: req.method,
      headers: { ...req.headers, host: alistTarget.host }
    }, (pres) => {
      res.writeHead(pres.statusCode, pres.headers);
      pres.pipe(res);
    });
    proxy.on('error', (err) => {
      console.error('AList proxy error:', err.message);
      if (!res.headersSent) res.status(502).end('Library UI unreachable.');
    });
    req.pipe(proxy);
  });
  console.log(`📚 AList proxy enabled → ${ALIST_URL}`);
}

app.listen(port, () => console.log(`✅ Server running on port ${port}`));
