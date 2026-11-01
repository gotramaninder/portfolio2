MANINDER PORTFOLIO - FILES AND HOW TO USE
=========================================
Upload ALL of these to your GitHub repo (replace the old ones):
  index.html   the site (do not edit by hand)
  work.js      your 31 reels + 16 designs (Admin keeps it updated)
  photo.jpg    About section photo
  sw.js        clears old caches so updates appear right away
  og.jpg       share preview image (WhatsApp / Instagram / LinkedIn)
Keep your existing folders: designs/  covers/  proof/

ADMIN
-----
Open your site, scroll to the footer, click "Admin" (or add #admin to the link).
One time: GitHub connection (username, repo name, branch, token).
Token: GitHub > Settings > Developer settings > Fine-grained tokens. Pick only this repo,
set Contents to Read and write. It is stored only in your browser.

ADDING WORK
-----------
1. Paste the Instagram link. It is detected automatically.
2. Pick the client, enter views / reach / likes / comments / shares
   (or upload an Insights screenshot and they are read for you).
3. Cover is optional:
   - leave empty: a designed cover with the views number is generated automatically
   - upload an image, or the reel's video file: a frame is captured for you
4. Many reels at once: use "Add many links at once", then fix titles/numbers with Edit.
5. Save and publish. Wait 1-2 minutes, then refresh with Ctrl+F5.

WHAT UPDATES BY ITSELF
----------------------
- Pink section: total views, reach, likes, engagement, top 5 reels, views per client.
- Orb stage: the best reels by views (tick "Feature this first" to pin one) plus latest designs.
- Work section: filters, cards, 3D tilt, hover preview on desktop.

SHARE PREVIEW
-------------
In index.html find:  <meta property="og:image" content="og.jpg">
Change og.jpg to the full link, e.g. https://USERNAME.github.io/REPO/og.jpg
