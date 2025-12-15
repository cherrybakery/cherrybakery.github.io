async function unlock() {
  const pw = document.getElementById("pw").value;
  const buf = await fetch("site.pkg").then(r => r.arrayBuffer());
  const u8 = new Uint8Array(buf);

  if (String.fromCharCode(...u8.slice(0,4)) !== "PKG1") {
    alert("Invalid package");
    return;
  }

  const salt = u8.slice(4, 20);
  const nonce = u8.slice(20, 32);
  const enc = u8.slice(32);

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
      iterations: 200000,
      hash: "SHA-256"
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );

  let data;
  try {
    data = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce },
      key,
      enc
    );
  } catch {
    alert("Wrong password");
    return;
  }

  const pkg = JSON.parse(new TextDecoder().decode(data));
  mount(pkg.files);
}

function mount(files) {
  for (const [path, b64] of Object.entries(files)) {
    if (path.endsWith(".html")) {
      document.documentElement.innerHTML = atob(b64);
    }
  }
}
