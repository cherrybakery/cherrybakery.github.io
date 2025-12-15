// ================= CONFIG =================
const PKG_FILE = "site.pkg";
const PBKDF2_ITER = 200000;
const PKG_MAGIC = "PKG1";
// ========================================

async function unlock() {
  const pw = document.getElementById("pw").value;
  if (!pw) return alert("Enter password");

  const buf = await fetch(PKG_FILE).then(r => r.arrayBuffer());
  const u8 = new Uint8Array(buf);

  // ---- parse header ----
  const magic = String.fromCharCode(...u8.slice(0, 4));
  if (magic !== PKG_MAGIC) return alert("Invalid package");

  const salt  = u8.slice(4, 20);
  const nonce = u8.slice(20, 32);
  const enc   = u8.slice(32);

  // ---- derive key ----
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(pw),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  const key = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: PBKDF2_ITER,
      hash: "SHA-256"
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );

  let plain;
  try {
    plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce },
      key,
      enc
    );
  } catch {
    return alert("Wrong password");
  }

  const pkg = JSON.parse(new TextDecoder().decode(plain));
  mountSite(pkg.files);
}

// =======================================================
// ======================= LOADER =========================
// =======================================================

function mountSite(files) {
  const blobMap = buildBlobMap(files);

  // ---- HTML ----
  if (!files["index.html"]) {
    alert("index.html not found in package");
    return;
  }

  const html = atob(files["index.html"]);
  const doc = rewriteHTML(html, blobMap);

  document.replaceChild(
    document.importNode(doc.documentElement, true),
    document.documentElement
  );

  // ---- CSS ----
  injectCSS(files, blobMap);

  // ---- JS ----
  //injectJS(files, blobMap);

  injectJSFromHTML(doc, blobMap);

}

// ================= BLOB MAP =================

function buildBlobMap(files) {
  const map = {};

  for (const [path, b64] of Object.entries(files)) {
    const bytes = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    const blob = new Blob([bytes], { type: guessMime(path) });
    map[path] = URL.createObjectURL(blob);
  }
  return map;
}

function guessMime(path) {
  if (path.endsWith(".html")) return "text/html";
  if (path.endsWith(".css"))  return "text/css";
  if (path.endsWith(".js"))   return "application/javascript";
  if (path.endsWith(".png"))  return "image/png";
  if (path.endsWith(".jpg") || path.endsWith(".jpeg")) return "image/jpeg";
  if (path.endsWith(".svg"))  return "image/svg+xml";
  if (path.endsWith(".woff")) return "font/woff";
  if (path.endsWith(".woff2"))return "font/woff2";
  return "application/octet-stream";
}

// ================= HTML REWRITE =================

function rewriteHTML(html, blobMap) {
  const doc = new DOMParser().parseFromString(html, "text/html");

  doc.querySelectorAll("img[src]").forEach(el => {
    const p = el.getAttribute("src");
    if (blobMap[p]) el.src = blobMap[p];
  });

  doc.querySelectorAll("link[href]").forEach(el => {
    const p = el.getAttribute("href");
    if (blobMap[p]) el.href = blobMap[p];
  });

  doc.querySelectorAll("script[src]").forEach(el => {
    const p = el.getAttribute("src");
    if (blobMap[p]) el.src = blobMap[p];
  });

  return doc;
}

// ================= CSS =================

function rewriteCSS(cssText, blobMap) {
  return cssText.replace(/url\(([^)]+)\)/g, (_, url) => {
    url = url.replace(/['"]/g, "").trim();
    return blobMap[url] ? `url(${blobMap[url]})` : `url(${url})`;
  });
}

function injectCSS(files, blobMap) {
  for (const [path, b64] of Object.entries(files)) {
    if (!path.endsWith(".css")) continue;

    const css = atob(b64);
    const fixed = rewriteCSS(css, blobMap);

    const style = document.createElement("style");
    style.textContent = fixed;
    document.head.appendChild(style);
  }
}

// ================= JS =================

async function injectJS(files, blobMap) {
  const scripts = Object.keys(files)
    .filter(p => p.endsWith(".js"))
    .sort(); // đảm bảo thứ tự nếu cần

  for (const path of scripts) {
    const s = document.createElement("script");
    s.src = blobMap[path];
    document.body.appendChild(s);
    await new Promise(r => (s.onload = r));
  }
}

async function injectJSFromHTML(doc, blobMap) {
  const scripts = [...doc.querySelectorAll("script[src]")];

  for (const el of scripts) {
    const src = el.getAttribute("src");
    if (!blobMap[src]) continue;

    const s = document.createElement("script");
    s.src = blobMap[src];
    document.body.appendChild(s);

    await new Promise(r => (s.onload = r));
  }
}

// ================= EXPORT =================
window.unlock = unlock;
