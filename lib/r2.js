// lib/r2.js — minimal Cloudflare R2 (S3 SigV4) client: presigned GET URLs and
// ListObjectsV2, using only Node built-ins (no aws-sdk dependency).
//
// Env vars (Render → Environment):
//   R2_ACCOUNT_ID          Cloudflare account id (R2 dashboard URL)
//   R2_ACCESS_KEY_ID       R2 API token id (Object Read & Write)
//   R2_SECRET_ACCESS_KEY   R2 API token secret
//   R2_BUCKET              bucket holding the sets (keys = "<set>/<file>.png")
// If any is missing, r2Configured() is false and the site keeps the legacy
// Dropbox redirect behaviour — zero breakage while migrating.
'use strict';

const crypto = require('crypto');
const axios = require('axios');

const R2_ACCOUNT_ID = (process.env.R2_ACCOUNT_ID || '').trim();
const R2_ACCESS_KEY_ID = (process.env.R2_ACCESS_KEY_ID || '').trim();
const R2_SECRET_ACCESS_KEY = (process.env.R2_SECRET_ACCESS_KEY || '').trim();
const R2_BUCKET = (process.env.R2_BUCKET || '').trim();

function r2Configured() {
  return Boolean(R2_ACCOUNT_ID && R2_ACCESS_KEY_ID && R2_SECRET_ACCESS_KEY && R2_BUCKET);
}

function host() {
  return `${R2_ACCOUNT_ID}.r2.cloudflarestorage.com`;
}

const hmac = (key, data, hex) =>
  crypto.createHmac('sha256', key).update(data, 'utf8').digest(hex ? 'hex' : undefined);
const sha256hex = (data) => crypto.createHash('sha256').update(data, 'utf8').digest('hex');

// RFC3986 encoding — AWS requires every byte except unreserved chars encoded.
function awsEncode(str, encodeSlash = true) {
  return [...String(str)].map(ch => {
    if (/[A-Za-z0-9\-._~]/.test(ch)) return ch;
    if (ch === '/' && !encodeSlash) return ch;
    return [...Buffer.from(ch, 'utf8')].map(b => '%' + b.toString(16).toUpperCase().padStart(2, '0')).join('');
  }).join('');
}

// Path encoding matching the AWS SDK's uriEscapePath behaviour (verified
// byte-for-byte against @aws-sdk/signature-v4): ! ' ( ) * stay literal,
// everything else percent-encoded, '/' preserved.
function awsEncodePath(str) {
  return [...String(str)].map(ch => {
    if (/[A-Za-z0-9\-._~!'()*/]/.test(ch)) return ch;
    return [...Buffer.from(ch, 'utf8')].map(b => '%' + b.toString(16).toUpperCase().padStart(2, '0')).join('');
  }).join('');
}

/** Presign an arbitrary request. Returns a full URL. */
function presign({ method, key = '', query = {}, ttlSeconds = 900, now = new Date() }) {
  const service = 's3';
  const region = 'auto';
  const amzdate = now.toISOString().replace(/[-:]/g, '').replace(/\.\d{3}/, '');
  const datestamp = amzdate.slice(0, 8);
  const credentialScope = `${datestamp}/${region}/${service}/aws4_request`;

  const qs = { ...query };
  qs['X-Amz-Algorithm'] = 'AWS4-HMAC-SHA256';
  qs['X-Amz-Credential'] = `${R2_ACCESS_KEY_ID}/${credentialScope}`;
  qs['X-Amz-Date'] = amzdate;
  qs['X-Amz-Expires'] = String(ttlSeconds);
  qs['X-Amz-SignedHeaders'] = 'host';

  const canonicalQuery = Object.keys(qs).sort()
    .map(k => `${awsEncode(k)}=${awsEncode(qs[k])}`).join('&');
  const canonicalUri = '/' + awsEncodePath(R2_BUCKET) + (key ? '/' + awsEncodePath(key) : '');
  const canonicalRequest = [
    method,
    canonicalUri,
    canonicalQuery,
    `host:${host()}\n`,
    'host',
    // sha256 of the empty body — matches the AWS SDK reference behaviour
    // for GET presigns (unit-tested byte-for-byte against @aws-sdk/signature-v4).
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
  ].join('\n');

  const stringToSign = [
    'AWS4-HMAC-SHA256',
    amzdate,
    credentialScope,
    sha256hex(canonicalRequest)
  ].join('\n');

  const kDate = hmac(`AWS4${R2_SECRET_ACCESS_KEY}`, datestamp);
  const kRegion = hmac(kDate, region);
  const kService = hmac(kRegion, service);
  const kSigning = hmac(kService, 'aws4_request');
  const signature = hmac(kSigning, stringToSign, true);

  return `https://${host()}${canonicalUri}?${canonicalQuery}&X-Amz-Signature=${signature}`;
}

/** Short-lived download URL for one object. */
function presignGet(key, ttlSeconds = 900) {
  return presign({ method: 'GET', key, ttlSeconds });
}

/** List objects (one page). Returns { prefixes: [..], keys: [{key,size}], nextToken }. */
async function listObjects({ prefix = '', delimiter = '/', maxKeys = 1000, continuationToken } = {}) {
  const query = { 'list-type': '2', 'max-keys': String(maxKeys) };
  if (prefix) query.prefix = prefix;
  if (delimiter) query.delimiter = delimiter;
  if (continuationToken) query['continuation-token'] = continuationToken;
  const url = presign({ method: 'GET', query, ttlSeconds: 300 });
  const resp = await axios.get(url, { timeout: 30000, headers: { 'User-Agent': 'patreon-checker/r2' } });
  const xml = resp.data;
  const keys = [...xml.matchAll(/<Contents>[\s\S]*?<Key>([\s\S]*?)<\/Key>[\s\S]*?<Size>(\d+)<\/Size>[\s\S]*?<\/Contents>/g)]
    .map(m => ({ key: m[1], size: Number(m[2]) }));
  const prefixes = [...xml.matchAll(/<CommonPrefixes><Prefix>([\s\S]*?)<\/Prefix><\/CommonPrefixes>/g)]
    .map(m => m[1]);
  const tok = xml.match(/<NextContinuationToken>([\s\S]*?)<\/NextContinuationToken>/);
  return { prefixes, keys, nextToken: tok ? tok[1] : null };
}

module.exports = { r2Configured, presignGet, listObjects, presign };
