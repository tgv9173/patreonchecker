// lib/db.js — small SQLite store for the library: per-patron likes and
// per-set metadata (series + tags) powering search and the Patreon-like
// series/tag organisation.
'use strict';

const path = require('path');
const Database = require('better-sqlite3');

const DB_PATH = process.env.LIBRARY_DB_PATH ||
  path.join(__dirname, '..', 'data', 'library.db');

require('fs').mkdirSync(path.dirname(DB_PATH), { recursive: true });
const db = new Database(DB_PATH);

db.exec(`
CREATE TABLE IF NOT EXISTS likes (
  patron_id  TEXT NOT NULL,
  kind       TEXT NOT NULL CHECK (kind IN ('set','image')),
  object_key TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (patron_id, kind, object_key)
);
CREATE TABLE IF NOT EXISTS set_meta (
  set_key TEXT PRIMARY KEY,   -- R2 prefix without trailing slash, e.g. "airi_gyaru"
  series  TEXT,               -- character name, e.g. "Akizuki Airi"
  tags    TEXT NOT NULL DEFAULT '[]'  -- JSON array of lowercase tags
);
`);

const stmts = {
  likeGet: db.prepare('SELECT 1 AS x FROM likes WHERE patron_id=? AND kind=? AND object_key=?'),
  likeAdd: db.prepare('INSERT OR IGNORE INTO likes (patron_id, kind, object_key) VALUES (?,?,?)'),
  likeDel: db.prepare('DELETE FROM likes WHERE patron_id=? AND kind=? AND object_key=?'),
  likeCount: db.prepare('SELECT COUNT(*) AS n FROM likes WHERE kind=? AND object_key=?'),
  likeCounts: db.prepare('SELECT object_key, COUNT(*) AS n FROM likes WHERE kind=? GROUP BY object_key'),
  likedByPatron: db.prepare('SELECT object_key FROM likes WHERE patron_id=? AND kind=?'),
  topLiked: db.prepare(`SELECT object_key, COUNT(*) AS n FROM likes
    WHERE kind=? GROUP BY object_key ORDER BY n DESC LIMIT ?`),
  metaGet: db.prepare('SELECT * FROM set_meta WHERE set_key=?'),
  metaAll: db.prepare('SELECT * FROM set_meta'),
  metaUpsert: db.prepare(`INSERT INTO set_meta (set_key, series, tags) VALUES (?,?,?)
    ON CONFLICT(set_key) DO UPDATE SET series=excluded.series, tags=excluded.tags`),
};

/** Toggle a like. Returns { liked, count }. */
function toggleLike(patronId, kind, key) {
  if (!['set', 'image'].includes(kind) || typeof key !== 'string' || !key) {
    throw new Error('bad like target');
  }
  const tx = db.transaction(() => {
    if (stmts.likeGet.get(patronId, kind, key)) {
      stmts.likeDel.run(patronId, kind, key);
      return false;
    }
    stmts.likeAdd.run(patronId, kind, key);
    return true;
  });
  const liked = tx();
  return { liked, count: stmts.likeCount.get(kind, key).n };
}

function likeCounts(kind) {
  const m = new Map();
  for (const r of stmts.likeCounts.all(kind)) m.set(r.object_key, r.n);
  return m;
}

function likedSet(patronId, kind) {
  return new Set(stmts.likedByPatron.all(patronId, kind).map(r => r.object_key));
}

function getMeta(setKey) {
  const r = stmts.metaGet.get(setKey);
  return r ? { series: r.series, tags: JSON.parse(r.tags) } : { series: null, tags: [] };
}

function allMeta() {
  const m = new Map();
  for (const r of stmts.metaAll.all()) m.set(r.set_key, { series: r.series, tags: JSON.parse(r.tags) });
  return m;
}

function upsertMeta(setKey, series, tags) {
  stmts.metaUpsert.run(setKey, series || null, JSON.stringify(tags || []));
}

module.exports = { toggleLike, likeCounts, likedSet, getMeta, allMeta, upsertMeta };
