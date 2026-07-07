const express = require('express');
const axios = require('axios');
const querystring = require('querystring');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const multer = require('multer');

const { track, TRACK_HOME } = require('./analytics');
const {
  findCommissionsForPatron,
  findCommissionsByUsername,
  getFreshCommissionRow,
  updateCommissionRow,
  flagRowChangesRequested
} = require('./sheets');

const app = express();
app.set('trust proxy', 1);

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 8 * 1024 * 1024, files: 1 },
  fileFilter: (req, file, cb) => {
    cb(null, /^image\/(png|jpe?g|gif|webp)$/i.test(file.mimetype));
  }
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

const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
// Must match Patreon developer portal "Redirect URIs" exactly (set on Render + in Patreon).
const REDIRECT_URI = process.env.REDIRECT_URI || 'https://patreon-checker.onrender.com/callback';
const ALLOWED_TIER_IDS = process.env.ALLOWED_TIER_IDS;
const SUCCESS_REDIRECT_URI = process.env.SUCCESS_REDIRECT_URI;

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
  return intent === 'commissions' ? 'commissions' : 'default';
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
      if (!retry) throw err;
      await new Promise(r => setTimeout(r, RETRY_BACKOFFS_MS[attempt - 1]));
    }
  }
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
app.use(express.static(PUBLIC_DIR));

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
    <p class="sub">My patron utilities: Dropbox folder after login, plus commission tracking (beta).</p>
    <div class="actions">
      <a class="btn btn-primary" href="/login">Login and get folder link</a>
      <a class="btn btn-secondary" href="/commissions">Commission tracking (beta)</a>
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
  const editLink = c.editable
    ? `<a class="edit-link" href="/commissions/edit?token=${encodeURIComponent(editTokenSign({ month: c.month, rowNumber: c.rowNumber, username: c.username }))}">Edit</a>`
    : '';
  const statusClass = statusBadgeClass(c.status);
  return `
      <tr data-status="${statusClass}">
        <td>
          <div class="character">${escapeHtmlAttr(c.character || 'Untitled')}</div>
          <p class="outfit">${escapeHtmlAttr(c.outfit || '')}</p>
        </td>
        <td><span class="status-badge ${statusClass}">${escapeHtmlAttr(c.status)}</span></td>
        <td class="month">${escapeHtmlAttr(c.month)}</td>
        <td>${editLink}</td>
      </tr>`;
}

const STATUS_FILTERS = [
  { key: 'all', label: 'All' },
  { key: 'status-not-started', label: 'Not started' },
  { key: 'status-preview-sent', label: 'Preview sent' },
  { key: 'status-changes-requested', label: 'Changes requested' },
  { key: 'status-approved', label: 'Approved' },
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

app.get('/login', (req, res) => {
  const referer = req.get('Referer') || 'No referer';
  const intent = req.query.intent === 'commissions' ? 'commissions' : 'default';
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

function errorPage({ status, title, body, retryHref }) {
  const retryMarkup = retryHref
    ? `<a class="btn btn-primary" href="${escapeHtmlAttr(retryHref)}">Try again</a>`
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
    // Skipped for the commissions intent: that flow needs full_name regardless of the cached tier result.
    const cachedUserId = intent === 'default' ? patronCookieVerify(req.cookies.patron_verified) : null;
    if (cachedUserId) {
      const cached = getCachedPatron(cachedUserId);
      if (cached) {
        res.clearCookie('login_referer', loginRefererCookieOptions());
        if (cached.matched) {
          if (!SUCCESS_REDIRECT_URI) {
            track('oauth_server_misconfigured', { missingEnv: 'SUCCESS_REDIRECT_URI' });
            return res.status(500).send(
              errorPage({ title: 'Server configuration error', body: 'Missing success redirect. Please contact the creator.' })
            );
          }
          track('oauth_success', { patreonUserId: cachedUserId, cached: true });
          return res.redirect(SUCCESS_REDIRECT_URI);
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

    // Patreon API v2: omit "memberships.currently_entitled_tiers" from include — fetching the full
    // tier objects causes 504s for patrons with large pledge histories (Patreon bug, June 2026).
    // Tier IDs are still present in member.relationships.currently_entitled_tiers.data per JSON:API spec.
    // (Do not add memberships.campaign without the "campaigns" scope — it can 400.)
    const identityQuery = querystring.stringify({
      include: 'memberships',
      'fields[user]': 'full_name',
      'fields[member]': 'patron_status'
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

    // Commission tracking just needs proof of Patreon identity, not a tier match —
    // sign the name into a cookie and hand off to /commissions immediately.
    if (intent === 'commissions') {
      const fullName = userRes.data?.data?.attributes?.full_name;
      res.clearCookie('login_referer', loginRefererCookieOptions());
      if (!fullName) {
        track('oauth_commissions_missing_name');
        return res.status(500).send(
          errorPage({ title: 'Login error', body: 'Patreon did not return a name for your account. Please try again.', retryHref: '/login?intent=commissions' })
        );
      }
      res.cookie('commission_identity', identityCookieSign(fullName), identityCookieOptions());
      track('oauth_commissions_success');
      return res.redirect('/commissions');
    }

    const allowedTierIds = (process.env.ALLOWED_TIER_IDS || '')
      .split(',')
      .map(id => id.trim())
      .filter(id => id);

    const memberships = userRes.data.included || [];
    let memberItems = memberships.filter(item => item.type === 'member');
    if (PATREON_CAMPAIGN_ID) {
      memberItems = memberItems.filter(
        m => m.relationships?.campaign?.data?.id === PATREON_CAMPAIGN_ID
      );
      if (memberItems.length === 0) {
        console.error(
          'Tier check: no member row for PATREON_CAMPAIGN_ID',
          PATREON_CAMPAIGN_ID,
          '(wrong ID or patron not in this campaign)'
        );
      }
    }
    const userTierIds = memberItems.flatMap(item =>
      (item.relationships?.currently_entitled_tiers?.data || []).map(tier => tier.id)
    );

    const matched = userTierIds.some(id => allowedTierIds.includes(id));
    const patreonUserId = userRes.data?.data?.id;

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
      if (!SUCCESS_REDIRECT_URI) {
        console.error('SUCCESS_REDIRECT_URI is not set');
        track('oauth_server_misconfigured', { missingEnv: 'SUCCESS_REDIRECT_URI' });
        res.clearCookie('login_referer', loginRefererCookieOptions());
        return res.status(500).send(
          errorPage({ title: 'Server configuration error', body: 'Missing success redirect. Please contact the creator.' })
        );
      }
      track('oauth_success', { patreonUserId });
      res.clearCookie('login_referer', loginRefererCookieOptions());
      res.redirect(SUCCESS_REDIRECT_URI);
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

// Multer throws synchronously (file too large, wrong mimetype) before the route handler runs —
// catch it here so uploads fail with a normal error page instead of a raw stack trace.
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError || err?.message?.includes('multipart')) {
    console.error('Upload error:', err.message);
    track('commission_edit_upload_rejected', { code: err.code });
    const token = req.body?.token || req.query?.token || '';
    return res.status(400).send(commissionsPageShell({
      title: 'Upload failed',
      bodyHtml: `
    <h1>Upload failed</h1>
    <p>${err.code === 'LIMIT_FILE_SIZE' ? 'That image is too large (8MB max).' : 'That file could not be uploaded - please use a PNG, JPEG, GIF, or WEBP image.'}</p>
    <div class="actions">
      <a class="btn btn-primary" href="/commissions/edit?token=${encodeURIComponent(token)}">Back to edit form</a>
      <a class="btn btn-secondary" href="/commissions">Back to commissions</a>
    </div>`
    }));
  }
  next(err);
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`✅ Server running on port ${port}`));
