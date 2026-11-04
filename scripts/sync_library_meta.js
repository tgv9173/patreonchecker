#!/usr/bin/env node
// scripts/sync_library_meta.js — fill the library DB's series/tags from the
// generation specs (~/.generation_automation/specs/*_spec.json), so the
// /library search and series/tag organisation mirror the Patreon taxonomy.
//
//   node scripts/sync_library_meta.js            # sync from specs
//   SPECS_DIR=/other/dir node scripts/sync_library_meta.js
//
// Series = character name (first part of character_tag, title-cased).
// Tags   = copyright (rest of character_tag) + cleaned style_tags tokens.
'use strict';

const fs = require('fs');
const path = require('path');
const dbLib = require('../lib/db');
const { r2Configured, listObjects } = require('../lib/r2');

const SPECS_DIR = process.env.SPECS_DIR ||
  path.join(process.env.HOME, '.generation_automation', 'specs');

function titleCase(s) {
  return s.replace(/\w\S*/g, w => w[0].toUpperCase() + w.slice(1));
}

// "(gyaru:1.2), kogal, makeup" -> ["gyaru", "kogal", "makeup"]
function cleanTags(raw) {
  return String(raw || '')
    .split(',')
    .map(t => t.replace(/[()]/g, '').replace(/:\d+(\.\d+)?/g, '').trim().toLowerCase())
    .filter(t => t && t.length > 1 && !t.includes(' '));
}

// "(Kai'sa:1.3)" / "mordred \(fate\)" -> "Kai'Sa" / "Mordred (Fate)"
function cleanSeries(raw) {
  let s = String(raw || '').trim();
  // strip weight suffixes "(name:1.3)" -> "(name)" then unwrap single outer parens
  s = s.replace(/:\d+(\.\d+)?/g, '');
  s = s.replace(/\\\(/g, '(').replace(/\\\)/g, ')');
  s = s.replace(/^\((.*)\)$/, '$1');
  return titleCase(s.replace(/_/g, ' ').trim());
}

async function main() {
  const files = fs.readdirSync(SPECS_DIR).filter(f => f.endsWith('_spec.json'));
  let synced = 0;
  for (const f of files) {
    let spec;
    try { spec = JSON.parse(fs.readFileSync(path.join(SPECS_DIR, f), 'utf8')); }
    catch { continue; }
    const setKey = f.replace(/_spec\.json$/, '');
    const [charPart, ...copyParts] = String(spec.character_tag || '').split(',').map(s => s.trim());
    const series = charPart ? cleanSeries(charPart) : null;
    const tags = new Set([...copyParts.map(t => t.toLowerCase()), ...cleanTags(spec.style_tags)]);
    dbLib.upsertMeta(setKey, series, [...tags]);
    synced++;
  }
  console.log(`synced ${synced} specs from ${SPECS_DIR}`);

  // Register R2 sets that have no spec (empty meta — they stay searchable by name).
  // Month folders (YYYY-MM/) are not sets; skip them.
  if (r2Configured()) {
    const { prefixes } = await listObjects({});
    const meta = dbLib.allMeta();
    let added = 0;
    for (const p of prefixes) {
      if (/^\d{4}-\d{2}\/$/.test(p)) continue;
      const key = p.replace(/\/$/, '');
      if (!meta.has(key)) { dbLib.upsertMeta(key, null, []); added++; }
    }
    console.log(`registered ${added} R2 sets without spec`);
  }
}

main().catch(e => { console.error(e); process.exit(1); });
