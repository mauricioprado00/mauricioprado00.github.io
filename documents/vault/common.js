// Shared by the unlock page and the service worker (sw.js).
// Derived keys are stored per bundle in IndexedDB as non-extractable
// CryptoKeys: they can decrypt on this device but cannot be read back out.
// See tools/vault.py for the file format.
const vault = (() => {
  const DB = "vault";
  const STORE = "keys";

  function db() {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(DB, 1);
      req.onupgradeneeded = () => req.result.createObjectStore(STORE);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }

  async function tx(mode, fn) {
    const conn = await db();
    return new Promise((resolve, reject) => {
      const req = fn(conn.transaction(STORE, mode).objectStore(STORE));
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    }).finally(() => conn.close());
  }

  const getKey = (bundle) => tx("readonly", (s) => s.get(bundle));
  const setKey = (bundle, key) => tx("readwrite", (s) => s.put(key, bundle));
  const deleteKey = (bundle) => tx("readwrite", (s) => s.delete(bundle));

  async function deriveKey(password, params) {
    const salt = Uint8Array.from(atob(params.salt), (c) => c.charCodeAt(0));
    const base = await crypto.subtle.importKey(
      "raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits(
      { name: "PBKDF2", hash: "SHA-256", salt, iterations: params.iterations }, base, 512);
    return crypto.subtle.importKey("raw", bits.slice(0, 32), "AES-GCM", false, ["decrypt"]);
  }

  // Throws if the key is wrong or the blob was tampered with.
  async function decrypt(key, blob) {
    const bytes = new Uint8Array(blob);
    return crypto.subtle.decrypt({ name: "AES-GCM", iv: bytes.slice(0, 12) }, key, bytes.slice(12));
  }

  async function fetchBytes(url) {
    const res = await fetch(url, { cache: "no-cache" });
    if (!res.ok) throw new Error(`${res.status} ${url}`);
    return res.arrayBuffer();
  }

  async function manifest(key, bundleUrl) {
    const plain = await decrypt(key, await fetchBytes(new URL("manifest.enc", bundleUrl)));
    return JSON.parse(new TextDecoder().decode(plain));
  }

  return { getKey, setKey, deleteKey, deriveKey, decrypt, fetchBytes, manifest };
})();
