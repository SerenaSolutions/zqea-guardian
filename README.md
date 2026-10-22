# Z-QEA Guardian

**A GitHub App — not an Action.** Install it and a **Check Run** appears on
every pull request, verifying the Z-QEA seal (SHA3-256) of each receipt
among the changed files. No YAML, no workflow file, no CI configuration.
That is the entire difference from the [Actions of the ecosystem](https://github.com/marketplace?query=z-qea).

```
Z-QEA Guardian: All Z-QEA receipts INTEGRAL (3)
  INTEGRAL experiments/s3_qutrit_final_receipt.json
  INTEGRAL experiments/round5_photonic_receipt.json
  INTEGRAL docs/receipt.json
```

## What it does (and what it proves)

On `pull_request` (opened / synchronize / reopened) in each installed
repository:

1. Lists the changed `.json` files.
2. For each one carrying `selo_sha3_256`, recomputes the seal: SHA3-256 over
   the receipt's canonical JSON without the seal field (keys sorted
   recursively, Python `json.dumps(sort_keys=True, ensure_ascii=True)`
   byte-compatible — including the `1.0` vs `1` float distinction).
3. Posts a Check Run: **success** (all integral), **failure** (any seal
   mismatch) or **neutral** (no receipts among the changes).

**Security scope, declared:** the seal proves **integrity** of the receipt.
It says nothing about authorship or authenticity. Every webhook is
HMAC-verified (`X-Hub-Signature-256`, timing-safe); unsigned requests get
`401`.

## Zero dependencies

Node >= 18, standard library only. The seal rule is implemented from scratch
in [`verify.js`](verify.js) — including a JSON parser that preserves the
float/integer distinction so the canonical form matches Python exactly.
The test battery proves it: a receipt sealed by the Python tools validates
here, and a tampered copy fails.

```bash
node tests/test_verify.js   # 4/4 — exit 0, nothing passes silently
```

## Deploy (any free host)

```bash
node server.js
# env: GUARDIAN_WEBHOOK_SECRET, GUARDIAN_APP_ID, GUARDIAN_PRIVATE_KEY, PORT
# health: GET /healthz  webhook: POST /webhook
```

Works on Render / Railway / Fly / any Node host as-is.

## Register the app

```bash
node scripts/make-registration-url.js https://YOUR-HOST/webhook
```

Open the printed URL (GitHub App registration, pre-filled: permissions
`checks: write`, `contents: read`; events `pull_request`, `ping`), click
**Create GitHub App**, then exchange the redirect `?code=...`:

```bash
node scripts/exchange-code.js THE_CODE
```

Store the returned private key and webhook secret as environment secrets.
Once the app is public you can submit it to the GitHub Marketplace from the
app's settings page (**GitHub Apps → Z-QEA Guardian → Share on GitHub
Marketplace**) — free listing.

## Honest scope

- v0.1 (this): receipt verification on PRs, as a Check Run.
- Declared roadmap (not claimed, not shipped): seal-on-tag (the counterpart
  of zqea-seal), trivalent battery as a check, org-level reports.
- The ML-DSA-44 layer of receipts is **reported** by the app when present
  but its verification requires the Python tools (`zqea-verify` Action);
  the Node layer covers the SHA3-256 seal, and the summary says so.

## Related

- [zqea-verify](https://github.com/SerenaSolutions/zqea-verify) — the verifier as an Action
- [zqea-seal](https://github.com/SerenaSolutions/zqea-seal) — the sealer as an Action
- [zephirum-lang](https://github.com/SerenaSolutions/zephirum-lang) — the language and the receipts' home

## License

MIT — see [LICENSE](LICENSE).
