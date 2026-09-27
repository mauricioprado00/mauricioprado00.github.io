// Password page for vault/<bundle>/index.html. Derives the key, checks it
// against the manifest, stores it for sw.js and opens the document.
// Visit the page with ?lock to forget the key on this device.
(async () => {
  const form = document.getElementById("unlock");
  const input = document.getElementById("password");
  const status = document.getElementById("status");
  const bundleUrl = new URL("./", location.href);
  const bundle = bundleUrl.pathname.split("/").filter(Boolean).pop();
  const params = new URLSearchParams(location.search);
  const next = params.get("next") || "";
  const open = () => location.replace(new URL(`view/${next.split("/").map(encodeURIComponent).join("/")}`, bundleUrl));

  const show = (message) => {
    status.textContent = message;
    form.hidden = false;
  };

  if (!("serviceWorker" in navigator) || !window.isSecureContext) {
    return show("This browser cannot open protected documents (service workers unavailable).");
  }
  await navigator.serviceWorker.register("../sw.js", { scope: "../" });
  await navigator.serviceWorker.ready;

  if (params.has("lock")) {
    await vault.deleteKey(bundle);
    history.replaceState(null, "", location.pathname);
    return show("Locked on this device.");
  }
  if (await vault.getKey(bundle)) return open();
  show("");

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = form.querySelector("button");
    button.disabled = true;
    status.textContent = "Checking…";
    try {
      const kdf = await (await fetch(new URL("vault.json", bundleUrl), { cache: "no-cache" })).json();
      const key = await vault.deriveKey(input.value, kdf);
      await vault.manifest(key, bundleUrl);
      await vault.setKey(bundle, key);
      open();
    } catch (err) {
      status.textContent = err.name === "OperationError" ? "Wrong password." : `Could not open: ${err.message}`;
      button.disabled = false;
      input.select();
    }
  });
})();
