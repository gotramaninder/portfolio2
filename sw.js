/* online: always fresh. offline: last visited copy */
self.addEventListener('install',function(){self.skipWaiting()});
self.addEventListener('activate',function(e){e.waitUntil(clients.claim())});
self.addEventListener('fetch',function(e){var u=e.request.url;
 if(e.request.method!=='GET'||!(u.indexOf(self.location.origin)===0||/fonts\.(googleapis|gstatic)\.com/.test(u)))return;
 e.respondWith(fetch(e.request).then(function(r){var c=r.clone();caches.open('p1').then(function(x){x.put(e.request,c)});return r}).catch(function(){return caches.match(e.request)}))});
