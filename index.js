const express = require('express');
const axios = require('axios');
const querystring = require('querystring');
const cookieParser = require('cookie-parser');

const app = express();

const CLIENT_ID = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const REDIRECT_URI = 'https://patreon-checker.onrender.com/callback'; // Ensure this matches Patreon settings
const ALLOWED_TIER_IDS = process.env.ALLOWED_TIER_IDS; // Your Patreon tier ID
const SUCCESS_REDIRECT_URI = process.env.SUCCESS_REDIRECT_URI; // Link to redirect if tier matches

// Store referer from /login in a cookie
app.use(cookieParser());

app.get('/', (req, res) => {
  res.send('<a href="/login">Login with Patreon</a>');
});

app.get('/login', (req, res) => {
  const referer = req.get('Referer') || 'No referer';
  res.cookie('login_referer', referer, { httpOnly: true, sameSite: 'lax' });
  const params = querystring.stringify({
    response_type: 'code',
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI, // Ensure this matches Patreon settings
    scope: 'identity identity.memberships'
  });
  res.redirect(`https://www.patreon.com/oauth2/authorize?${params}`);
});

app.get('/callback', async (req, res) => {
  const code = req.query.code;
  // Get referer from cookie set in /login
  const loginReferer = req.cookies.login_referer || 'No referer';
  try {
    const tokenRes = await axios.post('https://www.patreon.com/api/oauth2/token', querystring.stringify({
      code,
      grant_type: 'authorization_code',
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      redirect_uri: REDIRECT_URI // Ensure this matches Patreon settings
    }));

    const accessToken = tokenRes.data.access_token;

    // Fetch identity + memberships
    const userRes = await axios.get(
      'https://www.patreon.com/api/oauth2/v2/identity?include=memberships.currently_entitled_tiers,memberships',
      {
        headers: { Authorization: `Bearer ${accessToken}` }
      }
    );

    const allowedTierIds = (process.env.ALLOWED_TIER_IDS || '')
      .split(',')
      .map(id => id.trim())
      .filter(id => id);

    const memberships = userRes.data.included || [];
    const userTierIds = memberships
      .filter(item => item.type === 'member' && item.relationships?.currently_entitled_tiers?.data)
      .flatMap(item => item.relationships.currently_entitled_tiers.data.map(tier => tier.id));

    const matched = userTierIds.some(id => allowedTierIds.includes(id));

    if (matched) {
      res.clearCookie('login_referer');
      res.redirect(SUCCESS_REDIRECT_URI);
    } else {
      console.error('Access denied: Not subscribed to required tier.');
      console.error('Referer from /login on access denial:', loginReferer);
      res.clearCookie('login_referer');
      res.status(403).send('❌ Access denied: You are not subscribed to the required tier.');
      return;
    }

  } catch (err) {
    console.error('OAuth error:', err.response ? err.response.data : err);
    console.error('Referer from /login on OAuth failure:', loginReferer);
    res.clearCookie('login_referer');
    res.status(500).send('⚠️ An error occurred during authentication.');
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`✅ Server running on port ${port}`));
