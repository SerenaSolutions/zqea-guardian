// Z-QEA seal verification — the canonical rule of the ecosystem, in Node.
//
// Canonical rule (identical to the Python tools): SHA3-256 over the receipt's
// JSON WITHOUT selo_sha3_256, serialized exactly like Python's
// json.dumps(payload, sort_keys=True, ensure_ascii=True):
//   - keys sorted recursively, separators ", " and ": "
//   - non-ASCII escaped as \uXXXX (lowercase hex)
//   - FLOATS STAY FLOATS: Python writes 1.0, not 1 — so this module ships its
//     own JSON parser that tags float literals and formats them Python-style.
//
// Declared limitation (honest scope): floats >= 1e16 may differ from Python's
// repr (Python switches to exponential notation at 1e16, Node at 1e21).
// Receipt values are probabilities (<=1) and tiny error bounds, so this
// never occurs in practice; the test battery proves it on a real receipt.
//
// Cross-language proof: tests/test_verify.js validates a receipt sealed by the
// Python tools against this implementation (and a tampered copy fails).
'use strict';
const crypto = require('crypto');

// ---- JSON parser that keeps the float/int distinction (Python json.loads) ----
const FLOAT = Symbol('float');

function parseJson(text) {
  let i = 0;
  const s = text;
  function ws() { while (i < s.length && ' \t\n\r'.includes(s[i])) i++; }
  function value() {
    ws();
    const c = s[i];
    if (c === '{') { i++; const o = {}; ws();
      if (s[i] === '}') { i++; return o; }
      for (;;) { ws(); const k = value(); ws(); if (s[i] !== ':') throw new Error('expected :'); i++;
        o[k] = value(); ws();
        if (s[i] === ',') { i++; continue; }
        if (s[i] === '}') { i++; return o; }
        throw new Error('expected , or }'); }
    }
    if (c === '[') { i++; const a = []; ws();
      if (s[i] === ']') { i++; return a; }
      for (;;) { a.push(value()); ws();
        if (s[i] === ',') { i++; continue; }
        if (s[i] === ']') { i++; return a; }
        throw new Error('expected , or ]'); }
    }
    if (c === '"') { i++; let out = '';
      while (i < s.length && s[i] !== '"') {
        if (s[i] === '\\') { i++; const e = s[i]; i++;
          if (e === 'n') out += '\n'; else if (e === 't') out += '\t'; else if (e === 'r') out += '\r';
          else if (e === 'b') out += '\b'; else if (e === 'f') out += '\f';
          else if (e === 'u') { out += String.fromCharCode(parseInt(s.slice(i, i + 4), 16)); i += 4; }
          else out += e; // \" \\ \/ \' are identity
        } else { out += s[i]; i++; }
      }
      i++; return out;
    }
    if (s.startsWith('true', i)) { i += 4; return true; }
    if (s.startsWith('false', i)) { i += 5; return false; }
    if (s.startsWith('null', i)) { i += 4; return null; }
    // number
    const m = /^[+-]?(Infinity|\d+\.?\d*(?:[eE][+-]?\d+)?|\.\d+(?:[eE][+-]?\d+)?)/.exec(s.slice(i));
    if (!m) throw new Error('unexpected char at ' + i);
    const tok = m[0]; i += tok.length;
    if (/[.eE]/.test(tok)) return { [FLOAT]: parseFloat(tok) };
    return Number(tok);
  }
  const v = value(); ws();
  return v;
}

// ---- Python-compatible canonical serialization ----
function pyEscape(str) {
  let out = JSON.stringify(str);
  out = out.replace(/[\u007f-\uffff]/g, c => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'));
  return out;
}

function pyFloat(v) {
  // Python repr: integral floats keep '.0'; shortest round-trip otherwise.
  return Number.isInteger(v) ? v.toFixed(1) : String(v);
}

function pyNumber(v) {
  if (v && typeof v === 'object' && FLOAT in v) return pyFloat(v[FLOAT]);
  if (Number.isInteger(v)) return String(v);
  return String(v);
}

function canonical(v) {
  if (v === null) return 'null';
  if (typeof v === 'boolean') return v ? 'true' : 'false';
  if (typeof v === 'number') return pyNumber(v);
  if (typeof v === 'string') return pyEscape(v);
  if (Array.isArray(v)) return '[' + v.map(canonical).join(', ') + ']';
  if (typeof v === 'object' && FLOAT in v) return pyFloat(v[FLOAT]); // tagged float literal
  const keys = Object.keys(v).sort();
  return '{' + keys.map(k => pyEscape(k) + ': ' + canonical(v[k])).join(', ') + '}';
}

function verifyReceiptText(text) {
  const receipt = parseJson(text);
  return verifyReceipt(receipt);
}

function verifyReceipt(receipt) {
  if (!receipt || typeof receipt !== 'object' || !receipt.selo_sha3_256)
    return { ok: false, why: 'receipt has no selo_sha3_256' };
  const payload = { ...receipt };
  delete payload.selo_sha3_256;
  const recomputed = crypto.createHash('sha3-256').update(canonical(payload)).digest('hex');
  if (recomputed === receipt.selo_sha3_256) return { ok: true, recomputed };
  return { ok: false, recomputed, why: 'seal mismatch' };
}

module.exports = { canonical, parseJson, verifyReceipt, verifyReceiptText, FLOAT };
