
const enc = new TextEncoder();

const BASE_HEADERS = {
  "Cache-Control": "no-store, no-cache, must-revalidate, private",
  "Pragma": "no-cache",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "X-Frame-Options": "DENY",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=()"
};

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      ...BASE_HEADERS,
      "Content-Type": "application/json; charset=utf-8",
      ...extra
    }
  });
}

function b64url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function unb64url(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded =
    normalized + "=".repeat((4 - normalized.length % 4) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}

async function hmac(value, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  return b64url(
    new Uint8Array(
      await crypto.subtle.sign("HMAC", key, enc.encode(value))
    )
  );
}

async function makeToken(payload, secret) {
  const body = b64url(enc.encode(JSON.stringify(payload)));
  return `${body}.${await hmac(body, secret)}`;
}

async function readToken(token, secret) {
  if (!token || !token.includes(".")) return null;

  const dot = token.lastIndexOf(".");
  const body = token.slice(0, dot);
  const signature = token.slice(dot + 1);

  if (!body || !signature) return null;

  const expected = await hmac(body, secret);

  if (signature.length !== expected.length) return null;

  let diff = 0;
  for (let i = 0; i < signature.length; i++) {
    diff |= signature.charCodeAt(i) ^ expected.charCodeAt(i);
  }

  if (diff !== 0) return null;

  try {
    const payload = JSON.parse(
      new TextDecoder().decode(unb64url(body))
    );

    if (
      !payload ||
      typeof payload !== "object" ||
      payload.exp < Date.now()
    ) {
      return null;
    }

    return payload;
  } catch {
    return null;
  }
}

function cookieValue(request, name) {
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(
    new RegExp("(?:^|;\\\\s*)" + name + "=([^;]*)")
  );
  return match ? match[1] : "";
}

function setCookie(name, value, maxAge) {
  return `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;
}

function clearCookie(name) {
  return `${name}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;
}

function loginPage() {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#f8d9e8">
<title>Er. Sahiba ❤️</title>
<style>
:root{color-scheme:light}
*{box-sizing:border-box}
body{margin:0;min-height:100svh;display:grid;place-items:center;padding:22px;background:radial-gradient(circle at 15% 15%,#fff7fb 0,transparent 36%),linear-gradient(145deg,#fce7f3,#eadcff 55%,#ffe8df);font-family:system-ui,-apple-system,sans-serif;color:#582449;overflow-x:hidden}
.heart{position:fixed;opacity:.24;animation:float 8s ease-in-out infinite;pointer-events:none;font-size:24px}
.h1{top:8%;left:9%}
.h2{right:10%;top:20%;animation-delay:-3s}
.h3{bottom:12%;left:17%;animation-delay:-5s}
.card{width:min(100%,410px);padding:30px 24px 26px;text-align:center;border:1px solid #fff9;border-radius:28px;background:#ffffffc9;box-shadow:0 24px 80px #9e4b7b24;backdrop-filter:blur(12px)}
.badge{font-size:40px;filter:drop-shadow(0 5px 12px #df5b9d44)}
h1{font-size:clamp(27px,7vw,36px);margin:8px 0;color:#9d2868}
p{line-height:1.55;color:#80516e}
.field{display:flex;gap:8px;margin-top:20px}
input{min-width:0;flex:1;padding:14px;border:1px solid #e6b8d1;border-radius:13px;background:#fff;color:#582449;font-size:16px}
button{font:inherit;cursor:pointer;border:0;border-radius:13px;padding:13px 16px;background:#bd397d;color:white;font-weight:700;box-shadow:0 7px 18px #bd397d25}
button:focus-visible,input:focus-visible,a:focus-visible{outline:3px solid #7c3aed;outline-offset:3px}
.toggle{background:#f5e4ef;color:#8d2861;box-shadow:none;padding:0 12px}
.submit{width:100%;margin-top:12px}
.msg{min-height:28px;margin:16px 0 0;font-weight:650;color:#9d2868}
.actions{display:none;gap:9px;flex-direction:column;margin-top:12px}
.actions a{display:block;padding:13px;border-radius:12px;text-decoration:none;color:white;background:#159b64;font-weight:700}
.actions .call{background:#d13d83}
.small{font-size:12px;color:#946d87;margin-top:18px}
@keyframes float{0%,100%{transform:translateY(0) rotate(-8deg)}50%{transform:translateY(-18px) rotate(8deg)}}
@media(prefers-reduced-motion:reduce){*,*::before,*::after{animation:none!important;transition:none!important}}
</style>
</head>
<body>
<span class="heart h1">♥</span>
<span class="heart h2">♡</span>
<span class="heart h3">♥</span>

<main class="card">
  <div class="badge">🎁💗</div>
  <h1>Er. Sahiba</h1>
  <p>Aapke liye ek chhota sa surprise hai.<br>Unlock karke dekhiye ✨</p>

  <form id="form">
    <div class="field">
      <input id="password" type="password" autocomplete="current-password" placeholder="Enter password" required maxlength="256">
      <button class="toggle" id="toggle" type="button" aria-label="Show password">👁</button>
    </div>
    <button class="submit" type="submit">Unlock My Surprise 💖</button>
  </form>

  <div class="msg" id="message" role="status" aria-live="polite"></div>

  <div class="actions" id="actions">
    <a class="call" href="tel:+917905241894">Call ❤️</a>
    <a id="wa" target="_blank" rel="noopener noreferrer">WhatsApp 💌</a>
    <button id="option1" type="button" style="display:none">Option 1: Mujhe yaad kar lo</button>
    <button id="reset" type="button" style="display:none">Option 2: Page refresh kar lo</button>
  </div>

  <div class="small">Made with love 💗</div>
</main>

<script>
const form = document.querySelector("#form");
const input = document.querySelector("#password");
const message = document.querySelector("#message");
const actions = document.querySelector("#actions");
const submit = form.querySelector("button[type=submit]");

let attempts = 0;
let locked = false;

document.querySelector("#toggle").addEventListener("click", () => {
  input.type = input.type === "password" ? "text" : "password";

  document.querySelector("#toggle").setAttribute(
    "aria-label",
    input.type === "password" ? "Show password" : "Hide password"
  );
});

document.querySelector("#wa").href =
  "https://wa.me/917905241894?text=" +
  encodeURIComponent(
    "Baby please 🥹❤️\n\nPassword bata do na 🙈💗 Aapki Er. Sahiba apne surprise ka wait kar rahi hai 🎁😘\n\nLove you, mere pyare pati ji 💋💕"
  );

function showActions() {
  actions.style.display = "flex";
}

form.addEventListener("submit", async e => {
  e.preventDefault();

  if (locked) return;

  submit.disabled = true;
  message.textContent = "Checking...";

  try {
    const r = await fetch("/__auth", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: input.value })
    });

    const d = await r.json().catch(() => ({}));

    if (r.ok && d.success) {
      location.replace("/");
      return;
    }

    attempts = d.attempts || attempts + 1;

    if (attempts === 1 || attempts === 2) {
      message.textContent =
        "Ofhoo... Glt h meri Er. Sahiba 😏❤️";
    } else if (attempts === 3) {
      message.textContent =
        "Ofho mdm ji ab mujhe yaad kr lo 😘❤️";
    } else {
      message.textContent =
        "Ofhooo, Madam Ji! Ab bas, aur attempts nahi! 🙈💕";

      locked = true;
      input.disabled = true;
      submit.disabled = true;

      // CHANGE: Fourth wrong attempt par poora password form hide hoga.
      form.style.display = "none";

      document.querySelector("#option1").style.display = "block";
      document.querySelector("#reset").style.display = "block";
    }

    if (attempts >= 2) showActions();

    input.value = "";
  } catch {
    message.textContent = "Connection issue. Please try again.";
  } finally {
    if (!locked) submit.disabled = false;
  }
});

document.querySelector("#option1").addEventListener("click", () => {
  location.href = "tel:+917905241894";
});

document.querySelector("#reset").addEventListener("click", async () => {
  const r = await fetch("/__reset", { method: "POST" });

  if (r.ok) {
    location.replace("/");
  } else {
    message.textContent = "Reset failed. Please try again.";
  }
});
</script>
</body>
</html>`;
}

export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const method = request.method.toUpperCase();

  if (
    !env.BDAY_PASSWORD ||
    !env.SESSION_SECRET ||
    env.SESSION_SECRET.length < 32
  ) {
    return new Response(
      "Website configuration incomplete. Please configure BDAY_PASSWORD and a SESSION_SECRET of at least 32 characters.",
      {
        status: 500,
        headers: {
          ...BASE_HEADERS,
          "Content-Type": "text/plain; charset=utf-8"
        }
      }
    );
  }

  if (url.pathname === "/__auth") {
    if (method !== "POST") {
      return json({ error: "Method not allowed." }, 405, {
        Allow: "POST"
      });
    }

    let body;

    try {
      if (Number(request.headers.get("Content-Length") || 0) > 4096) {
        return json({ error: "Request too large." }, 413);
      }

      body = await request.json();
    } catch {
      return json({ error: "Invalid request." }, 400);
    }

    if (
      !body ||
      typeof body.password !== "string" ||
      body.password.length > 256
    ) {
      return json({ error: "Invalid request." }, 400);
    }

    const state = await readToken(
      cookieValue(request, "bday_state"),
      env.SESSION_SECRET
    );

    const attempts = Math.min(
      4,
      Math.max(0, Number(state?.attempts) || 0)
    );

    if (attempts >= 4) {
      return json({ error: "Attempts locked.", attempts: 4 }, 429);
    }

    if (body.password !== env.BDAY_PASSWORD) {
      const nextAttempts = attempts + 1;

      const token = await makeToken(
        {
          attempts: nextAttempts,
          exp: Date.now() + 7 * 24 * 60 * 60 * 1000
        },
        env.SESSION_SECRET
      );

      return json(
        { error: "Incorrect password.", attempts: nextAttempts },
        401,
        {
          "Set-Cookie": setCookie("bday_state", token, 604800)
        }
      );
    }

    const ticket = await makeToken(
      {
        kind: "one-use",
        exp: Date.now() + 30000,
        nonce: crypto.randomUUID()
      },
      env.SESSION_SECRET
    );

    const responseHeaders = new Headers({
      ...BASE_HEADERS,
      "Content-Type": "application/json; charset=utf-8"
    });

    responseHeaders.append(
      "Set-Cookie",
      setCookie("bday_ticket", ticket, 30)
    );

    responseHeaders.append(
      "Set-Cookie",
      clearCookie("bday_state")
    );

    return new Response(JSON.stringify({ success: true }), {
      status: 200,
      headers: responseHeaders
    });
  }

  if (url.pathname === "/__reset") {
    if (method !== "POST") {
      return json({ error: "Method not allowed." }, 405, {
        Allow: "POST"
      });
    }

    const state = await readToken(
      cookieValue(request, "bday_state"),
      env.SESSION_SECRET
    );

    if (
      !state ||
      !Number.isFinite(state.attempts) ||
      state.attempts < 4
    ) {
      return json(
        {
          error:
            "Reset is only available after the fourth incorrect attempt."
        },
        403
      );
    }

    return new Response(null, {
      status: 204,
      headers: {
        ...BASE_HEADERS,
        "Set-Cookie": clearCookie("bday_state")
      }
    });
  }

  if (url.pathname === "/" || url.pathname === "/index.html") {
    const ticket = await readToken(
      cookieValue(request, "bday_ticket"),
      env.SESSION_SECRET
    );

    if (ticket?.kind === "one-use") {
      const assetResponse = await context.next();
      const responseHeaders = new Headers(assetResponse.headers);

      for (const [key, value] of Object.entries(BASE_HEADERS)) {
        responseHeaders.set(key, value);
      }

      responseHeaders.append(
        "Set-Cookie",
        clearCookie("bday_ticket")
      );

      return new Response(assetResponse.body, {
        status: assetResponse.status,
        statusText: assetResponse.statusText,
        headers: responseHeaders
      });
    }

    return new Response(loginPage(), {
      status: 200,
      headers: {
        ...BASE_HEADERS,
        "Content-Type": "text/html; charset=utf-8"
      }
    });
  }

  return context.next();
    }
                               
