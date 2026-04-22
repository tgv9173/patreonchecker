const axios = require('axios');

const WEBHOOK_URL = (process.env.ANALYTICS_WEBHOOK_URL || '').trim();

/**
 * Non-blocking usage metrics. Logs one JSON line per event (grep "[analytics]" in Render logs).
 * Optionally POST the same payload to ANALYTICS_WEBHOOK_URL (Zapier, Make, custom endpoint).
 * Never pass tokens, secrets, or full Patreon profiles — only ids/counts you explicitly add.
 */
function track(event, props = {}) {
  const payload = {
    ts: new Date().toISOString(),
    event,
    ...trimProps(props)
  };
  console.log(`[analytics] ${JSON.stringify(payload)}`);

  if (!WEBHOOK_URL) return;

  setImmediate(() => {
    axios
      .post(WEBHOOK_URL, payload, {
        timeout: 8000,
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        validateStatus: () => true
      })
      .catch(() => {});
  });
}

function trimProps(props) {
  const out = {};
  for (const [k, v] of Object.entries(props)) {
    if (v === undefined || v === null) continue;
    if (typeof v === 'string') {
      out[k] = v.length > 800 ? `${v.slice(0, 800)}…` : v;
    } else {
      out[k] = v;
    }
  }
  return out;
}

const TRACK_HOME = process.env.ANALYTICS_TRACK_HOME === 'true';

module.exports = { track, TRACK_HOME };
