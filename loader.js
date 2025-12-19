/* =========================================================
 * SECURE STATIC SITE LOADER
 * - AES-256-GCM + PBKDF2
 * - Per-page encrypted PKG
 * - Multi-page SPA-style navigation
 * ========================================================= */

const PKG_DIR = "pkg/";
const PKG_MAGIC = "PKG1";
const PBKDF2_ITER = 200000;

/* ---------------- GLOBAL STATE ---------------- */
let __PASSWORD = null;
let __KEY = null;
let __FILES = null;
let __BLOB_MAP = null;
let __CSS_LOADED = false;

/* ================= ENTRY ================= */

async function unlock() {
  const pw = document.getElementById("pw").value;
  if (!pw) return alert("Enter password");

  __PASSWORD = pw;

  interceptLinks();
  window.addEventListener("popstate", onPopState);

  const page = currentPage();
  await loadPage(page);
}

window.unlock = unlock;

/* ================= PAGE LOGIC ================= */

function currentPage() {
  const p = location.pathname.split("/").pop();
  return p && p.endsWith(".html") ? p.replace(".html", "") : "index";
}

async function loadPage(page) {
  const files = await loadPkg(page);
  __FILES = files;
  __BLOB_MAP = buildBlobMap(files);

  const htmlName = `${page}.html`;
  if (!files[htmlName]) {
    alert(`Page not found: ${htmlName}`);
    return;
  }

  const html = atob(files[htmlName]);
  const scriptList = extractScripts(html);
  const doc = rewriteHTML(html, __BLOB_MAP);

  /* replace BODY only (keeps loader alive) */
  document.body.replaceWith(
    document.importNode(doc.body, true)
  );

  if (!__CSS_LOADED) {
    injectCSS(files, __BLOB_MAP);
    __CSS_LOADED = true;
  }

  await loadScriptsSequential(scriptList, __BLOB_MAP);
  fireReadyEvents();
}

/* ================= PKG LOAD ================= */

async function loadPkg(page) {
  const res = await fetch(`${PKG_DIR}${page}.pkg`);
  if (!res.ok) throw new Error("PKG not found: " + page);

  const buf = await res.arrayBuffer();
  const u8 = new Uint8Array(buf);

  const magic = String.fromCharCode(...u8.slice(0, 4));
  if (magic !== PKG_MAGIC) throw new Error("Invalid PKG");

  const salt  = u8.slice(4, 20);
  const nonce = u8.slice(20, 32);
  const enc   = u8.slice(32);

  if (!__KEY) __KEY = await deriveKey(__PASSWORD, salt);

  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: nonce },
    __KEY,
    enc
  );

  return JSON.parse(new TextDecoder().decode(plain)).files;
}

async function deriveKey(password, salt) {
  const km = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: PBKDF2_ITER,
      hash: "SHA-256"
    },
    km,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );
}

/* ================= HTML ================= */

function rewriteHTML(html, blobMap) {
  const doc = new DOMParser().parseFromString(html, "text/html");

  /* remove scripts (we load manually) */
  doc.querySelectorAll("script[src]").forEach(s => s.remove());

  doc.querySelectorAll("img[src]").forEach(el => {
    const p = el.getAttribute("src");
    if (blobMap[p]) el.src = blobMap[p];
  });

  doc.querySelectorAll("link[href]").forEach(el => {
    const p = el.getAttribute("href");
    if (blobMap[p]) el.href = blobMap[p];
  });

  return doc;
}

function extractScripts(html) {
  const doc = new DOMParser().parseFromString(html, "text/html");
  return [...doc.querySelectorAll("script[src]")]
    .map(s => s.getAttribute("src"));
}

/* ================= CSS ================= */

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

function rewriteCSS(css, blobMap) {
  return css.replace(/url\(([^)]+)\)/g, (_, u) => {
    u = u.replace(/['"]/g, "").trim();
    return blobMap[u] ? `url(${blobMap[u]})` : `url(${u})`;
  });
}

/* ================= JS ================= */

async function loadScriptsSequential(list, blobMap) {
  /* remove old dynamic scripts */
  document.querySelectorAll("script[data-dynamic]")
    .forEach(s => s.remove());

  for (const p of list) {
    if (!blobMap[p]) continue;

    const s = document.createElement("script");
    s.src = blobMap[p];
    s.defer = false;
    s.dataset.dynamic = "1";
    document.body.appendChild(s);

    await new Promise(r => (s.onload = r));
  }
}

/* ================= BLOB ================= */

function buildBlobMap(files) {
  const map = {};
  for (const [path, b64] of Object.entries(files)) {
    const bytes = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    const blob = new Blob([bytes], { type: mimeOf(path) });
    map[path] = URL.createObjectURL(blob);
  }
  return map;
}

function mimeOf(p) {
  if (p.endsWith(".html")) return "text/html";
  if (p.endsWith(".css")) return "text/css";
  if (p.endsWith(".js")) return "application/javascript";
  if (p.endsWith(".png")) return "image/png";
  if (p.endsWith(".jpg") || p.endsWith(".jpeg")) return "image/jpeg";
  if (p.endsWith(".svg")) return "image/svg+xml";
  if (p.endsWith(".woff")) return "font/woff";
  if (p.endsWith(".woff2")) return "font/woff2";
  return "application/octet-stream";
}

/* ================= NAVIGATION ================= */

function interceptLinks() {
  document.addEventListener("click", e => {
    const a = e.target.closest("a");
    if (!a) return;

    const href = a.getAttribute("href");
    if (!href || !href.endsWith(".html")) return;

    e.preventDefault();
    history.pushState({}, "", href);
    loadPage(href.replace(".html", ""));
  });
}

function onPopState() {
  loadPage(currentPage());
}

/* ================= READY ================= */

function fireReadyEvents() {
  document.dispatchEvent(new Event("DOMContentLoaded"));
  window.dispatchEvent(new Event("load"));

  if (window.jQuery) {
    jQuery(document).ready();
    jQuery(window).trigger("load");
  }
}
