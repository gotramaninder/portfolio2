# Deploy notes (Design Hustler / portfolio2) - code-only update

Copy these into the repo root (they only ADD or replace code files):
  index.html, dashboard.html, wrangler.jsonc, package.json, .assetsignore, _headers, SETUP.md
  src/  migrations/  scripts/  test/

DO NOT touch your content files: work.js, display-settings.json, site-content.json, covers/, videos/, designs/, posts/, proof/, photo.jpg, og.jpg.

After deploy:
  /admin   -> reviews dashboard (gotramaninder@gmail.com)
  /studio  -> your existing portfolio editor (old admin.html)
Database guards (migration 0003) are already applied to designhustler-db.
Tests: `node test/run.mjs` (API), `node test/browser.mjs` (needs Chromium).
Forgot the admin password: `node scripts/reset-admin-password.mjs "new password"`, or ask Claude to run the SQL.
