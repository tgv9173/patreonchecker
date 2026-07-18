const { google } = require('googleapis');

const SHEET_ID = process.env.COMMISSION_SHEET_ID;
const CACHE_TTL_MS = 60 * 1000; // avoid hammering the Sheets API on repeated visits
// Legend labels are full sentences (e.g. "Not started - available to pick up"), so this
// is a substring check, not an exact match against the array.
const EDITABLE_STATUSES = ['not started', 'preview sent'];
function isEditableStatus(statusLabel) {
  const lower = statusLabel.toLowerCase();
  return EDITABLE_STATUSES.some(s => lower.includes(s));
}

// Internal-only production stage between generation and delivery — never shown to patrons.
const HIDDEN_STATUSES = ['waiting for manual cleanup'];
function isHiddenStatus(statusLabel) {
  const lower = statusLabel.toLowerCase();
  return HIDDEN_STATUSES.some(s => lower.includes(s));
}

let authClient = null;
let cache = { data: null, expires: 0 };

function getCredentials() {
  const raw = (process.env.GOOGLE_SERVICE_ACCOUNT_JSON || '').trim();
  if (!raw) throw new Error('GOOGLE_SERVICE_ACCOUNT_JSON is not set');
  return JSON.parse(raw);
}

async function getSheetsClient() {
  if (!authClient) {
    authClient = new google.auth.GoogleAuth({
      credentials: getCredentials(),
      // Read-write: editing a commission needs more than .readonly.
      // The sheet must be shared with the service account email as Editor, not just Viewer.
      scopes: ['https://www.googleapis.com/auth/spreadsheets']
    });
  }
  const client = await authClient.getClient();
  return google.sheets({ version: 'v4', auth: client });
}

function normalizeName(value) {
  return String(value || '').trim().toLowerCase().replace(/[^a-z0-9]/g, '');
}

// Sheet timestamps are "DD/MM/YYYY HH:MM:SS" — plain string comparison sorts them
// wrong (e.g. "31/01/2026" > "01/02/2026" lexicographically despite being earlier).
function parseSheetTimestamp(raw) {
  const m = /^(\d{1,2})\/(\d{1,2})\/(\d{4})\s+(\d{1,2}):(\d{2}):(\d{2})$/.exec(String(raw || '').trim());
  if (!m) return 0;
  const [, d, mo, y, h, mi, s] = m.map(Number);
  return new Date(y, mo - 1, d, h, mi, s).getTime();
}

// Exact match only. Substring matching (e.g. "rose" inside "roseharlot") was a real
// privacy bug in production: it let one patron's login pull up a different patron's
// (often NSFW) commission details just because their names happened to overlap.
function isNameMatch(patreonFullName, sheetUsername) {
  const a = normalizeName(patreonFullName);
  const b = normalizeName(sheetUsername);
  if (!a || !b) return false;
  return a === b;
}

function colorDistance(c1, c2) {
  const dr = (c1.red || 0) - (c2.red || 0);
  const dg = (c1.green || 0) - (c2.green || 0);
  const db = (c1.blue || 0) - (c2.blue || 0);
  return Math.sqrt(dr * dr + dg * dg + db * db);
}

// White/no-fill cells come back with an empty backgroundColor object from the API.
const WHITE = { red: 1, green: 1, blue: 1 };

function matchStatusEntry(legend, cellColor) {
  const color = cellColor && Object.keys(cellColor).length ? cellColor : WHITE;
  let best = null;
  let bestDist = Infinity;
  for (const entry of legend) {
    const d = colorDistance(entry.color, color);
    if (d < bestDist) {
      bestDist = d;
      best = entry;
    }
  }
  return best;
}

async function getStatusLegend(sheets) {
  const resp = await sheets.spreadsheets.get({
    spreadsheetId: SHEET_ID,
    ranges: ["'Legend'!A3:B10"],
    includeGridData: true,
    fields: 'sheets.data.rowData.values(formattedValue,userEnteredFormat.backgroundColor)'
  });
  const rows = resp.data.sheets?.[0]?.data?.[0]?.rowData || [];
  const legend = [];
  for (const row of rows) {
    const colorCell = row.values?.[0];
    const labelCell = row.values?.[1];
    if (!labelCell?.formattedValue) continue;
    legend.push({
      color: colorCell?.userEnteredFormat?.backgroundColor || WHITE,
      label: labelCell.formattedValue
    });
  }
  return legend;
}

function findLegendEntry(legend, labelSubstring) {
  return legend.find(e => e.label.toLowerCase().includes(labelSubstring));
}

async function getTabGids(sheets) {
  const meta = await sheets.spreadsheets.get({
    spreadsheetId: SHEET_ID,
    fields: 'sheets.properties'
  });
  const map = new Map();
  for (const s of meta.data.sheets || []) {
    map.set(s.properties.title, s.properties.sheetId);
  }
  return map;
}

const MONTH_NAMES = [
  'January', 'February', 'March', 'April', 'May', 'June',
  'July', 'August', 'September', 'October', 'November', 'December'
];

// Formats in Europe/Paris explicitly, NOT server-local time: Render runs UTC, while the
// Google Form writes sheet-locale (Paris) timestamps into the same tabs. Mixing the two
// made site-submitted rows sort ~1-2h off against form rows around midnight.
const SHEET_TIMEZONE = 'Europe/Paris';
function formatSheetTimestamp(date = new Date()) {
  const parts = Object.fromEntries(
    new Intl.DateTimeFormat('en-GB', {
      timeZone: SHEET_TIMEZONE,
      day: '2-digit', month: '2-digit', year: 'numeric',
      hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false
    }).formatToParts(date).map(p => [p.type, p.value])
  );
  return `${parts.day}/${parts.month}/${parts.year} ${parts.hour}:${parts.minute}:${parts.second}`;
}

function currentYearInSheetTimezone(date = new Date()) {
  return Number(new Intl.DateTimeFormat('en-GB', { timeZone: SHEET_TIMEZONE, year: 'numeric' }).format(date));
}

// The Google Form for each month is titled e.g. "July 2026 commission form", but the
// sheet tab it feeds is just "July commissions" (no year — tabs get reused/renamed
// yearly). New tabs we create follow that same current convention.
function currentMonthTabName(date = new Date()) {
  return `${MONTH_NAMES[date.getMonth()]} commissions`;
}

// Finds this month's commission tab, or creates it by duplicating the most recently
// created commission tab (inheriting its header row, column widths, and formatting),
// then stripping its old data so the copy starts empty.
async function findOrCreateCurrentMonthTab(sheets) {
  const tabGids = await getTabGids(sheets);
  const wantedName = currentMonthTabName();
  const monthName = wantedName.replace(/ commissions$/, '');
  // Case-insensitive and tolerant of the older singular "commission" spelling used on
  // some past tabs — but new tabs are always created with the current plural form.
  const existingTitle = [...tabGids.keys()].find(t =>
    new RegExp(`^${monthName}\\s+commissions?$`, 'i').test(t)
  );
  if (existingTitle) {
    // Year-rollover guard: tab names carry no year, so next January a stale "January
    // commissions" tab from LAST year would be silently reused and new submissions
    // would append under year-old rows. Detect staleness from the tab's last data-row
    // timestamp; if it's from a previous year, rename the old tab out of the way
    // (matching the user's manual yearly-renaming convention) and fall through to
    // creating a fresh one.
    const gid = tabGids.get(existingTitle);
    const lastRows = await sheets.spreadsheets.values.get({
      spreadsheetId: SHEET_ID,
      range: `'${existingTitle}'!A2:A1000`
    });
    const stamps = (lastRows.data.values || []).flat().filter(v => v && v.trim());
    const lastStamp = stamps.length ? parseSheetTimestamp(stamps[stamps.length - 1]) : null;
    const currentYear = currentYearInSheetTimezone();
    if (!lastStamp || new Date(lastStamp).getFullYear() >= currentYear) {
      return { title: existingTitle, gid };
    }
    const staleYear = new Date(lastStamp).getFullYear();
    await sheets.spreadsheets.batchUpdate({
      spreadsheetId: SHEET_ID,
      requestBody: {
        requests: [{
          updateSheetProperties: {
            properties: { sheetId: gid, title: `${existingTitle} ${staleYear}` },
            fields: 'title'
          }
        }]
      }
    });
    invalidateCache();
    // fall through to the duplicate-a-template path below, which creates the new tab
  }

  // Tabs read left-to-right newest-first in this sheet, so the first commission-tab
  // match (excluding Legend) is the most recent one to use as a duplication template.
  const sourceTitle = [...tabGids.keys()].find(
    t => /commission/i.test(t) && t.toLowerCase() !== 'legend'
  );
  if (!sourceTitle) {
    throw new Error('No existing commission tab found to use as a template for the new month.');
  }

  const dupResp = await sheets.spreadsheets.batchUpdate({
    spreadsheetId: SHEET_ID,
    requestBody: {
      requests: [{
        duplicateSheet: {
          sourceSheetId: tabGids.get(sourceTitle),
          insertSheetIndex: 0,
          newSheetName: wantedName
        }
      }]
    }
  });
  const newGid = dupResp.data.replies[0].duplicateSheet.properties.sheetId;

  // Strip the copied data (keep only the header row) and reset the data rows' color to
  // "Not started" so leftover status colors from the source month's real submissions
  // don't make the empty duplicate misread as some other status.
  const legend = await getStatusLegend(sheets);
  const notStartedEntry = findLegendEntry(legend, 'not started');
  const notStartedColor = notStartedEntry ? notStartedEntry.color : WHITE;

  await sheets.spreadsheets.values.clear({
    spreadsheetId: SHEET_ID,
    range: `'${wantedName}'!A2:H1000`
  });
  await sheets.spreadsheets.batchUpdate({
    spreadsheetId: SHEET_ID,
    requestBody: {
      requests: [{
        repeatCell: {
          range: { sheetId: newGid, startRowIndex: 1, endRowIndex: 1000, startColumnIndex: 0, endColumnIndex: 8 },
          cell: { userEnteredFormat: { backgroundColor: notStartedColor } },
          fields: 'userEnteredFormat.backgroundColor'
        }
      }]
    }
  });

  invalidateCache();
  return { title: wantedName, gid: newGid };
}

const AGREEMENT_TEXT = 'I agree to the terms and conditions';

// Mirrors what the Google Form writes: same 8 columns, same "not started" (uncolored)
// starting state. Column B (the agreement text) isn't read by fetchAllCommissions, but
// we still write it for consistency with every existing row in the sheet.
async function appendCommissionSubmission({ username, character, outfit, maleType, size, notes }) {
  const sheets = await getSheetsClient();
  const { title, gid } = await findOrCreateCurrentMonthTab(sheets);

  const appendResp = await sheets.spreadsheets.values.append({
    spreadsheetId: SHEET_ID,
    range: `'${title}'!A1:H1`,
    valueInputOption: 'RAW',
    insertDataOption: 'INSERT_ROWS',
    requestBody: {
      values: [[
        formatSheetTimestamp(),
        AGREEMENT_TEXT,
        username,
        character,
        outfit,
        maleType || '',
        size || '',
        notes || ''
      ]]
    }
  });

  // append() only writes values, never formatting — explicitly color the new row so it
  // reads as "Not started" regardless of whatever was left over on that row before.
  const updatedRange = appendResp.data.updates?.updatedRange || '';
  const rowMatch = /![A-Z]+(\d+):/.exec(updatedRange);
  if (rowMatch) {
    const rowIndex = Number(rowMatch[1]) - 1; // 0-indexed for the API
    const legend = await getStatusLegend(sheets);
    const notStartedEntry = findLegendEntry(legend, 'not started');
    await sheets.spreadsheets.batchUpdate({
      spreadsheetId: SHEET_ID,
      requestBody: {
        requests: [{
          repeatCell: {
            range: { sheetId: gid, startRowIndex: rowIndex, endRowIndex: rowIndex + 1, startColumnIndex: 0, endColumnIndex: 8 },
            cell: { userEnteredFormat: { backgroundColor: notStartedEntry ? notStartedEntry.color : WHITE } },
            fields: 'userEnteredFormat.backgroundColor'
          }
        }]
      }
    });
  }

  invalidateCache();
  return { month: title };
}

// The request form (character/outfit wishlist) isn't part of the commission tracker —
// it's low-stakes feedback, not a paid submission — so it just gets its own tab in the
// same spreadsheet rather than a whole tracked-status pipeline. Created once, on first use.
const REQUESTS_TAB_TITLE = 'Website requests';
const REQUESTS_HEADER = ['Timestamp', 'Patreon username', 'Tier', 'Character/licence', 'Outfit ideas', 'Other feedback'];

async function ensureRequestsTab(sheets) {
  const tabGids = await getTabGids(sheets);
  if (tabGids.has(REQUESTS_TAB_TITLE)) return tabGids.get(REQUESTS_TAB_TITLE);

  const createResp = await sheets.spreadsheets.batchUpdate({
    spreadsheetId: SHEET_ID,
    requestBody: {
      requests: [{ addSheet: { properties: { title: REQUESTS_TAB_TITLE } } }]
    }
  });
  const gid = createResp.data.replies[0].addSheet.properties.sheetId;
  await sheets.spreadsheets.values.update({
    spreadsheetId: SHEET_ID,
    range: `'${REQUESTS_TAB_TITLE}'!A1:F1`,
    valueInputOption: 'RAW',
    requestBody: { values: [REQUESTS_HEADER] }
  });
  return gid;
}

async function appendRequestSubmission({ username, tier, character, outfit, notes }) {
  const sheets = await getSheetsClient();
  await ensureRequestsTab(sheets);
  await sheets.spreadsheets.values.append({
    spreadsheetId: SHEET_ID,
    range: `'${REQUESTS_TAB_TITLE}'!A1:F1`,
    valueInputOption: 'RAW',
    insertDataOption: 'INSERT_ROWS',
    requestBody: {
      values: [[formatSheetTimestamp(), username, tier || '', character || '', outfit || '', notes || '']]
    }
  });
}

async function fetchAllCommissions() {
  const sheets = await getSheetsClient();

  const tabGids = await getTabGids(sheets);
  const tabTitles = [...tabGids.keys()].filter(
    t => /commission/i.test(t) && t.toLowerCase() !== 'legend'
  );

  if (tabTitles.length === 0) return [];

  const legend = await getStatusLegend(sheets);

  const dataResp = await sheets.spreadsheets.get({
    spreadsheetId: SHEET_ID,
    ranges: tabTitles.map(t => `'${t}'!A1:H1000`),
    includeGridData: true,
    fields: 'sheets(properties.title,data.rowData.values(formattedValue,userEnteredFormat.backgroundColor))'
  });

  const results = [];
  for (const sheet of dataResp.data.sheets || []) {
    const monthLabel = sheet.properties.title;
    const rows = sheet.data?.[0]?.rowData || [];
    // Row 0 is the header row (form field labels) — data starts at row 1.
    for (let i = 1; i < rows.length; i++) {
      const row = rows[i];
      if (!row?.values) continue;
      const cellAt = idx => row.values[idx]?.formattedValue || '';
      const username = cellAt(2); // column C
      const character = cellAt(3); // column D
      if (!username && !character) continue; // skip blank rows
      const statusColor = row.values[0]?.userEnteredFormat?.backgroundColor;
      const statusEntry = matchStatusEntry(legend, statusColor);
      const statusLabel = statusEntry ? statusEntry.label : 'Unknown';
      results.push({
        month: monthLabel,
        tabGid: tabGids.get(monthLabel),
        rowNumber: i + 1, // 1-indexed sheet row (rowData is 0-indexed from A1)
        timestamp: cellAt(0), // column A
        username,
        character,
        outfit: cellAt(4), // column E
        maleType: cellAt(5), // column F
        size: cellAt(6), // column G
        notes: cellAt(7), // column H
        status: statusLabel,
        editable: isEditableStatus(statusLabel),
        hidden: isHiddenStatus(statusLabel)
      });
    }
  }
  return results;
}

async function getAllCommissionsCached({ fresh = false } = {}) {
  if (!fresh && cache.data && Date.now() < cache.expires) return cache.data;
  const data = await fetchAllCommissions();
  cache = { data, expires: Date.now() + CACHE_TTL_MS };
  return data;
}

function invalidateCache() {
  cache = { data: null, expires: 0 };
}

async function findCommissionsForPatron(fullName) {
  const all = await getAllCommissionsCached();
  const matches = all.filter(row => isNameMatch(fullName, row.username) && !row.hidden);
  matches.sort((a, b) => parseSheetTimestamp(b.timestamp) - parseSheetTimestamp(a.timestamp));
  return matches;
}

async function findCommissionsByUsername(username) {
  const all = await getAllCommissionsCached();
  const needle = normalizeName(username);
  const matches = all.filter(row => normalizeName(row.username) === needle && !row.hidden);
  matches.sort((a, b) => parseSheetTimestamp(b.timestamp) - parseSheetTimestamp(a.timestamp));
  return matches;
}

// Re-reads a single row fresh (bypassing cache) right before an edit, so a stale page
// can't be used to edit a row that's since moved out of an editable status.
async function getFreshCommissionRow(month, rowNumber) {
  const all = await getAllCommissionsCached({ fresh: true });
  return all.find(r => r.month === month && r.rowNumber === rowNumber) || null;
}

async function updateCommissionRow(month, rowNumber, fields) {
  const sheets = await getSheetsClient();
  const values = [[
    fields.character ?? '',
    fields.outfit ?? '',
    fields.maleType ?? '',
    fields.size ?? '',
    fields.notes ?? ''
  ]];
  await sheets.spreadsheets.values.update({
    spreadsheetId: SHEET_ID,
    range: `'${month}'!D${rowNumber}:H${rowNumber}`,
    valueInputOption: 'RAW',
    requestBody: { values }
  });
  invalidateCache();
}

// Generic status recolor by legend label — same mechanics as
// flagRowChangesRequested below but reusable for the approve flow (and any future
// status transition): the row's color IS its status, resolved from the Legend tab.
async function setRowStatusByLabel(month, rowNumber, legendLabel) {
  const sheets = await getSheetsClient();
  const tabGids = await getTabGids(sheets);
  const tabGid = tabGids.get(month);
  if (tabGid === undefined) throw new Error(`setRowStatusByLabel: unknown tab '${month}'`);
  const legend = await getStatusLegend(sheets);
  const entry = findLegendEntry(legend, legendLabel);
  if (!entry) throw new Error(`setRowStatusByLabel: no legend entry matching '${legendLabel}'`);
  await sheets.spreadsheets.batchUpdate({
    spreadsheetId: SHEET_ID,
    requestBody: {
      requests: [{
        repeatCell: {
          range: {
            sheetId: tabGid,
            startRowIndex: rowNumber - 1,
            endRowIndex: rowNumber,
            startColumnIndex: 0,
            endColumnIndex: 8
          },
          cell: { userEnteredFormat: { backgroundColor: entry.color } },
          fields: 'userEnteredFormat.backgroundColor'
        }
      }]
    }
  });
  invalidateCache();
}

async function flagRowChangesRequested(tabGid, rowNumber) {
  const sheets = await getSheetsClient();
  const legend = await getStatusLegend(sheets);
  const entry = findLegendEntry(legend, 'changes requested');
  const color = entry ? entry.color : { red: 1, green: 0, blue: 0 };

  await sheets.spreadsheets.batchUpdate({
    spreadsheetId: SHEET_ID,
    requestBody: {
      requests: [{
        repeatCell: {
          range: {
            sheetId: tabGid,
            startRowIndex: rowNumber - 1,
            endRowIndex: rowNumber,
            startColumnIndex: 0,
            endColumnIndex: 8
          },
          cell: { userEnteredFormat: { backgroundColor: color } },
          fields: 'userEnteredFormat.backgroundColor'
        }
      }]
    }
  });
  invalidateCache();
}

module.exports = {
  isNameMatch,
  findCommissionsForPatron,
  findCommissionsByUsername,
  getFreshCommissionRow,
  updateCommissionRow,
  flagRowChangesRequested,
  setRowStatusByLabel,
  appendCommissionSubmission,
  appendRequestSubmission
};
