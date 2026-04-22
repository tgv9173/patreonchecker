const express = require('express');
const axios = require('axios');
const querystring = require('querystring');
const cookieParser = require('cookie-parser');
const path = require('path');
const fs = require('fs');

const app = express();
app.set('trust proxy', 1);

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

/** Retries Patreon HTTP calls on timeouts / 502–504 (common when their edge is slow). */
async function patreonRequest(label, axiosCall) {
  const maxAttempts = 3;
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
          ax?.status === 504 ||
          ax?.status === 503 ||
          ax?.status === 502 ||
          bodyStr.includes('timed out'));
      console.error(
        `${label} failed (attempt ${attempt}/${maxAttempts}):`,
        ax ? { status: ax.status, data: ax.data } : err.code || err.message
      );
      if (!retry) throw err;
      await new Promise(r => setTimeout(r, 450 * attempt));
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
  <title>TGV9173 — patron tools</title>
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
    <p class="sub">My patron utilities: Dropbox folder after login, plus commission tracking when it's ready.</p>
    <div class="actions">
      <a class="btn btn-primary" href="/login">Login and get folder link</a>
      <a class="btn btn-secondary" href="/commissions">Commission tracking</a>
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

app.get('/commissions', (req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Commission tracking</title>
  <style>
    :root { font-family: system-ui, sans-serif; line-height: 1.5; color: #1a1a1a; }
    body { margin: 0; min-height: 100vh; display: flex; flex-direction: column; align-items: center;
      justify-content: center; padding: 1.5rem; background: #f6f7f9; box-sizing: border-box; }
    main { width: 100%; max-width: 24rem; text-align: center; }
    h1 { font-size: 1.25rem; font-weight: 650; margin: 0 0 0.75rem; }
    p { margin: 0 0 1.25rem; color: #444; font-size: 0.95rem; }
    a { color: #2563eb; font-weight: 600; }
    a:focus-visible { outline: 2px solid #2563eb; outline-offset: 2px; border-radius: 4px; }
  </style>
</head>
<body>
  <main>
    <h1>Commission tracking</h1>
    <p>This page is still in progress. Check back soon.</p>
    <p><a href="/">Back to home</a></p>
  </main>
</body>
</html>`);
});

app.get('/login', (req, res) => {
  const referer = req.get('Referer') || 'No referer';
  res.cookie('login_referer', referer, loginRefererCookieOptions());
  const params = querystring.stringify({
    response_type: 'code',
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    scope: 'identity identity.memberships'
  });
  res.redirect(`https://www.patreon.com/oauth2/authorize?${params}`);
});

app.get('/callback', async (req, res) => {
  const oauthError = req.query.error;
  const oauthDescription = req.query.error_description;
  const code = req.query.code;
  const loginReferer = req.cookies.login_referer || 'No referer';

  if (oauthError) {
    console.error('OAuth denied or error:', oauthError, oauthDescription || '');
    res.clearCookie('login_referer', loginRefererCookieOptions());
    return res.status(400).send(
      `Login was not completed (${oauthError}). Please try again from your creator's link.`
    );
  }
  if (!code) {
    res.clearCookie('login_referer', loginRefererCookieOptions());
    return res.status(400).send('Missing authorization code. Please start login again.');
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

    // Patreon API v2: every resource needs explicit fields[...]. (Do not add memberships.campaign here
    // without the "campaigns" OAuth scope — it can 400. Member resources still include campaign id in relationships.)
    const identityQuery = querystring.stringify({
      include: 'memberships,memberships.currently_entitled_tiers',
      'fields[user]': 'full_name,image_url,url,vanity',
      'fields[member]':
        'patron_status,currently_entitled_amount_cents,last_charge_status,last_charge_date,pledge_relationship_start',
      'fields[tier]': 'title,amount_cents'
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

    if (matched) {
      if (!SUCCESS_REDIRECT_URI) {
        console.error('SUCCESS_REDIRECT_URI is not set');
        res.clearCookie('login_referer', loginRefererCookieOptions());
        return res.status(500).send('Server configuration error: missing success redirect.');
      }
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
      res.clearCookie('login_referer', loginRefererCookieOptions());
      res.status(403).send('❌ Access denied: You are not subscribed to the required tier.');
      return;
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
      return res.status(400).send(
        'This login link expired or was already used (do not refresh the Patreon return page). ' +
          'Go back to the site home and click “Login and get folder link” once.'
      );
    }

    res.status(500).send('⚠️ An error occurred during authentication.');
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`✅ Server running on port ${port}`));
