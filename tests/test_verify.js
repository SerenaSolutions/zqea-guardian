// Canonical battery: cross-language seal verification.
//   1. real_receipt.json — sealed by the PYTHON tools of the ecosystem (experiments/)
//      must validate INTEGRAL here (Node), proving the canonical rule matches.
//   2. tampered_receipt.json — one flipped hex digit in the seal must fail.
// Exit 0 = all pass. Any failure exits 1 — nothing passes silently.
'use strict';
const fs = require('fs');
const path = require('path');
const { canonical, parseJson, verifyReceipt, verifyReceiptText } = require('../verify.js');

let failed = 0;
function check(name, cond, detail) {
  console.log(`  [${cond ? 'OK' : 'FAIL'}] ${name}${detail ? ' — ' + detail : ''}`);
  if (!cond) failed++;
}

// NOTE: verification must use parseJson (float-preserving). JSON.parse
// collapses 1.0 -> 1 and the canonical form diverges from Python. Proven
// the hard way during development — kept here as a regression anchor.
const realText = fs.readFileSync(path.join(__dirname, 'fixtures/real_receipt.json'), 'utf8');
const v1 = verifyReceiptText(realText);
const real = parseJson(realText);
check('real receipt (sealed by Python tools) validates in Node', v1.ok,
  v1.ok ? v1.recomputed.slice(0, 16) + '...' : v1.why);

const v2 = verifyReceiptText(fs.readFileSync(path.join(__dirname, 'fixtures/tampered_receipt.json'), 'utf8'));
check('tampered receipt is REFUSED', v2.ok === false, v2.why);

check('receipt without seal is REFUSED', verifyReceipt({ spec: 'x' }).ok === false);

// canonical sanity: sorted keys, Python separators
const c = canonical({ b: 1, a: [2, { d: 3, c: 4 }] });
check('canonical JSON shape matches Python json.dumps', c === '{"a": [2, {"c": 4, "d": 3}], "b": 1}', c);

process.exit(failed ? 1 : 0);
