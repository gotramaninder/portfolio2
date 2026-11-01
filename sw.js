/* Clears old caches and always loads the newest site, so Admin changes show up right after publishing. */
self.addEventListener('install',function(){self.skipWaiting()});
self.addEventListener('activate',function(e){e.waitUntil(caches.keys().then(function(k){return Promise.all(k.map(function(x){return caches.delete(x)}))}).then(function(){return self.clients.claim()}))});
