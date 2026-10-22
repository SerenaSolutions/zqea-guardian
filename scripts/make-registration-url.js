// Prints the one-click GitHub App registration URL with the manifest embedded.
// Usage: node scripts/make-registration-url.js [WEBHOOK_URL]
//   The webhook URL is where the standalone server (server.js) is deployed.
'use strict';
const fs = require('fs');
const manifest = JSON.parse(fs.readFileSync(require('path').join(__dirname, '..', 'app-manifest.json'), 'utf8'));
const webhook = process.argv[2] || 'REPLACE_WITH_YOUR_WEBHOOK_URL/webhook';
manifest.hook_attributes = { url: webhook };
const json = JSON.stringify(manifest);
console.log('https://github.com/settings/apps/new?manifest=' + Buffer.from(json).toString('base64'));
