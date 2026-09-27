// Serves vault/<bundle>/view/<path> by decrypting that file's blob with the
// bundle's key from IndexedDB. Without a working key, navigations go to the
// bundle's password page and come back afterwards.
importScripts("common.js");

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (event) => event.waitUntil(self.clients.claim()));

self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);
  const scope = new URL(self.registration.scope);
  if (url.origin !== scope.origin || !url.pathname.startsWith(scope.pathname)) return;
  const match = url.pathname.slice(scope.pathname.length).match(/^([^/]+)\/view\/(.*)$/);
  if (!match || event.request.method !== "GET") return;
  event.respondWith(serve(event.request, match[1], decodeURIComponent(match[2])));
});

async function serve(request, bundle, path) {
  const bundleUrl = new URL(`${bundle}/`, self.registration.scope);
  const locked = () => {
    if (request.mode !== "navigate") return new Response("Locked", { status: 401 });
    const next = new URLSearchParams({ next: path });
    return Response.redirect(`${bundleUrl}?${next}`, 302);
  };

  const key = await vault.getKey(bundle);
  if (!key) return locked();

  let manifest;
  try {
    manifest = await vault.manifest(key, bundleUrl);
  } catch (err) {
    if (err.name !== "OperationError") throw err;
    await vault.deleteKey(bundle); // password changed since this device unlocked
    return locked();
  }

  const files = manifest.files;
  const entry = files[path || manifest.index] || files[`${path.replace(/\/?$/, "/")}index.html`];
  if (!entry) return new Response("Not found", { status: 404 });

  const blob = await fetch(new URL(`blobs/${entry.id}.bin`, bundleUrl));
  if (!blob.ok) return new Response("Not found", { status: 404 });
  const body = await vault.decrypt(key, await blob.arrayBuffer());
  return new Response(body, {
    headers: { "Content-Type": entry.type, "Cache-Control": "no-store", "X-Robots-Tag": "noindex" },
  });
}
