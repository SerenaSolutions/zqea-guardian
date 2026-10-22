// After one-click registration GitHub redirects to redirect_url?code=XXXX.
// Exchange that code for the app credentials (id, private key, webhook secret).
// Usage: node scripts/exchange-code.js THE_CODE
// SECURITY: the output contains the app private key. Store it as a secret
// (GUARDIAN_PRIVATE_KEY); never commit it. If exposed, rotate in app settings.
'use strict';
const code = process.argv[2];
if (!code) { console.error('usage: node scripts/exchange-code.js CODE'); process.exit(2); }
fetch(`https://api.github.com/app-manifests/${code}/conversions`, { method: 'POST' })
  .then(async r => {
    if (!r.ok) throw new Error('HTTP ' + r.status + ' — code expired? (they last a short time)');
    const d = await r.json();
    console.log('App created: ' + d.name + ' (id ' + d.id + ')');
    console.log('Webhook secret: ' + d.webhook_secret);
    console.log('Private key (GUARDIAN_PRIVATE_KEY):');
    console.log(d.pem);
  })
  .catch(e => { console.error('exchange failed:', e.message); process.exit(1); });
