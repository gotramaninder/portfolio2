# Deploy notes (Design Hustler / portfolio2)

1. Replace the repo files with this folder's contents and push (Workers Builds deploys on push).
   - New: src/index.js, wrangler.jsonc, package.json, .assetsignore, dashboard.html, migrations/, test/
   - Changed: index.html (Leave a review modal + approved reviews in Kind Words)
   - Untouched: admin.html, review.html, work.js, sw.js, images, videos, JSON files
2. Admin: https://<your-site>/admin  (email: gotramaninder@gmail.com). First login forces a new password.
3. The old portfolio editor (admin.html, GitHub token based) now lives at /studio.
4. Keep your existing proof/ folder in the repo if you have one (it was not in the ZIP).
5. Local tests: `node test/run.mjs` (API) and `node test/browser.mjs` (needs a Chromium).
