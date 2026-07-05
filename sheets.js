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

function isNameMatch(patreonFullName, sheetUsername) {
  const a = normalizeName(patreonFullName);
  const b = normalizeName(sheetUsername);
  if (!a || !b) return false;
  return a === b || a.includes(b) || b.includes(a);
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
    ranges: ["'Legend'!A3:B7"],
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
        editable: isEditableStatus(statusLabel)
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
  const matches = all.filter(row => isNameMatch(fullName, row.username));
  matches.sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || ''));
  return matches;
}

async function findCommissionsByUsername(username) {
  const all = await getAllCommissionsCached();
  const needle = normalizeName(username);
  const matches = all.filter(row => normalizeName(row.username) === needle);
  matches.sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || ''));
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
  findCommissionsForPatron,
  findCommissionsByUsername,
  getFreshCommissionRow,
  updateCommissionRow,
  flagRowChangesRequested
};
