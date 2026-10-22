// Z-QEA GUARDIAN — standalone GitHub App service (Node >= 18, ZERO dependencies).
//
// What it does: on every pull_request (opened / synchronize / reopened) in the
// installed repositories, it verifies every Z-QEA receipt among the changed
// JSON files and reports an INTEGRAL/BROKEN verdict as a Check Run
// ("Z-QEA Guardian" in the Checks tab). No YAML needed by users — install
// the app and the checks appear. That is the difference vs. the Actions.
//
// Environment:
//   GUARDIAN_WEBHOOK_SECRET   webhook secret (GitHub App settings)
//   GUARDIAN_APP_ID           GitHub App id (numeric)
//   GUARDIAN_PRIVATE_KEY      the app's .pem (newlines as \n or real newlines)
//   PORT                      default 3000
//
// Security scope (house style): the SHA3-256 seal proves INTEGRITY of the
// receipt. This app reports exactly that — nothing about authorship.
// Every webhook is HMAC-verified (timing-safe); unsigned requests get 401.
'use strict';
const http = require('http');
const crypto = require('crypto');
const { verifyReceiptText } = require('./verify.js');

const PORT = process.env.PORT || 3000;
const WEBHOOK_SECRET = process.env.GUARDIAN_WEBHOOK_SECRET || '';
const APP_ID = process.env.GUARDIAN_APP_ID || '';
const PRIVATE_KEY = (process.env.GUARDIAN_PRIVATE_KEY || '').replace(/\\n/g, '\n');

const API = 'https://api.github.com';

function appJwt() {
  const b64 = o => Buffer.from(JSON.stringify(o)).toString('base64url');
  const now = Math.floor(Date.now() / 1000);
  const head = b64({ alg: 'RS256', typ: 'JWT' });
  const body = b64({ iat: now - 60, exp: now + 540, iss: APP_ID });
  const signer = crypto.createSign('RSA-SHA256');
  signer.update(head + '.' + body);
  return head + '.' + body + '.' + signer.sign(PRIVATE_KEY, 'base64url');
}

async function gh(path, token, opts = {}) {
  const res = await fetch(API + path, {
    method: opts.method || 'GET',
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': 'zqea-guardian',
      ...(opts.body ? { 'Content-Type': 'application/json' } : {})
    },
    body: opts.body
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`${path} -> HTTP ${res.status}: ${text.slice(0, 300)}`);
  return text ? JSON.parse(text) : null;
}

async function installationToken(installationId) {
  const res = await fetch(`${API}/app/installations/${installationId}/access_tokens`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${appJwt()}`, Accept: 'application/vnd.github+json' }
  });
  if (!res.ok) throw new Error(`installation token -> HTTP ${res.status}`);
  return (await res.json()).token;
}

function hmacOk(raw, sigHeader) {
  if (!WEBHOOK_SECRET || !sigHeader) return false;
  const expected = 'sha256=' + crypto.createHmac('sha256', WEBHOOK_SECRET).update(raw).digest('hex');
  const a = Buffer.from(sigHeader), b = Buffer.from(expected);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

async function handlePullRequest(event) {
  const { action, pull_request, repository, installation } = event;
  if (!['opened', 'synchronize', 'reopened'].includes(action)) return 'ignored action';
  if (!pull_request || !repository || !installation) return 'malformed event';

  const tok = await installationToken(installation.id);
  const repo = repository.full_name;
  const pr = pull_request.number;
  const sha = pull_request.head.sha;

  const files = await gh(`/repos/${repo}/pulls/${pr}/files?per_page=100`, tok);
  const verdicts = [];
  for (const f of files) {
    if (!f.filename.endsWith('.json')) continue;
    let meta;
    try { meta = await gh(`/repos/${repo}/contents/${f.filename}?ref=${encodeURIComponent(sha)}`, tok); }
    catch { continue; } // deleted/renamed or binary — nothing to verify
    if (!meta.content) continue;
    const text = Buffer.from(meta.content, 'base64').toString('utf8');
    const v = verifyReceiptText(text);
    if (v.why === 'receipt has no selo_sha3_256') continue; // plain JSON, not a receipt
    verdicts.push({ file: f.filename, ...v });
  }

  const okAll = verdicts.length > 0 && verdicts.every(v => v.ok);
  const summary = verdicts.length === 0
    ? 'No Z-QEA receipts among the changed JSON files.'
    : verdicts.map(v => `${v.ok ? 'INTEGRAL' : 'BROKEN '} ${v.file}${v.ok ? '' : ' (declared ' + (v.declared || '') + ' != recomputed ' + v.recomputed + ')'}`).join('\n');
  if (verdicts.length > 0) verdicts.forEach(v => { if (!v.declared) v.declared = ''; });

  await gh(`/repos/${repo}/check-runs`, tok, {
    method: 'POST',
    body: JSON.stringify({
      name: 'Z-QEA Guardian',
      head_sha: sha,
      status: 'completed',
      conclusion: verdicts.length === 0 ? 'neutral' : (okAll ? 'success' : 'failure'),
      output: {
        title: verdicts.length === 0 ? 'No receipts to verify'
          : (okAll ? `All Z-QEA receipts INTEGRAL (${verdicts.length})` : 'Z-QEA seal mismatch'),
        summary
      }
    })
  });
  return okAll ? 'all integral' : (verdicts.length === 0 ? 'no receipts' : 'failure reported');
}

const server = http.createServer(async (req, res) => {
  if (req.method === 'GET' && req.url === '/healthz') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({ ok: true, app: 'zqea-guardian', checks: 'Z-QEA receipts on PRs' }));
  }
  if (req.method !== 'POST') { res.writeHead(404); return res.end(); }
  const chunks = [];
  for await (const c of req) chunks.push(c);
  const raw = Buffer.concat(chunks).toString('utf8');
  if (!hmacOk(raw, req.headers['x-hub-signature-256'])) {
    res.writeHead(401); return res.end('bad signature');
  }
  const event = req.headers['x-github-event'];
  let body = {};
  try { body = JSON.parse(raw); } catch {}
  let outcome = 'ignored';
  try {
    if (event === 'pull_request') outcome = await handlePullRequest(body);
  } catch (e) {
    console.error('[guardian]', e.message);
    res.writeHead(500); return res.end('guardian error');
  }
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ ok: true, event, outcome }));
});

server.listen(PORT, () => console.log(`Z-QEA Guardian listening on :${PORT}`));
