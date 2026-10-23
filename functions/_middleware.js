
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
  const padded = normalized + "=".repeat((4 - normalized.length % 4) % 4);
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
      typeof payload.exp !== "number" ||
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
    new RegExp("(?:^|;\\s*)" + name + "=([^;]*)")
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
*{box-sizing:border-box}
body{
  margin:0;min-height:100svh;display:grid;place-items:center;
  padding:20px;overflow-x:hidden;
  background:radial-gradient(circle at 15% 15%,#fff7fb,transparent 36%),
  linear-gradient(145deg,#ffe3f0,#eadcff 55%,#ffe8df);
  font-family:system-ui,-apple-system,sans-serif;color:#63264c
}
.card{
  position:relative;width:min(100%,420px);padding:28px 22px;
  text-align:center;border:1px solid #fff9;border-radius:28px;
  background:#ffffffdc;box-shadow:0 24px 80px #9e4b7b28;
  backdrop-filter:blur(12px);z-index:2
}
.badge{font-size:46px;animation:bounce 2s infinite}
h1{font-size:clamp(27px,7vw,36px);margin:8px 0;color:#a42c70}
p{line-height:1.6;color:#80516e}
.field{display:flex;gap:8px;margin-top:20px}
input{
  min-width:0;flex:1;padding:14px;border:1px solid #e6b8d1;
  border-radius:13px;background:#fff;color:#582449;font-size:16px
}
button{
  font:inherit;cursor:pointer;border:0;border-radius:14px;
  padding:13px 16px;background:linear-gradient(135deg,#d94691,#a33bd2);
  color:white;font-weight:750;box-shadow:0 7px 18px #bd397d25
}
button:focus-visible,input:focus-visible,a:focus-visible{
  outline:3px solid #7c3aed;outline-offset:3px
}
.toggle{background:#f5e4ef;color:#8d2861;box-shadow:none;padding:0 12px}
.submit,.try-btn,.ask-btn{width:100%;margin-top:12px}
.msg{margin:18px 0 0;font-size:18px;font-weight:800;color:#a42c70}
.hint{margin:9px 0;color:#885271;font-size:14px;line-height:1.65}
#tryAgain,#askButton,#contactScreen{display:none}
.try-btn{background:linear-gradient(135deg,#ff75b5,#bb55e8)}
.ask-btn{background:linear-gradient(135deg,#ff4d88,#a33bd2)}
.actions{display:flex;gap:10px;flex-direction:column;margin-top:18px}
.actions a{
  display:block;padding:14px;border-radius:14px;
  text-decoration:none;color:white;font-weight:800
}
.call{background:linear-gradient(135deg,#ff6197,#d72e78)}
.wa{background:linear-gradient(135deg,#20c878,#07995c)}
.small{font-size:12px;color:#946d87;margin-top:20px}
.float{
  position:fixed;z-index:1;pointer-events:none;bottom:-55px;
  animation:floatUp 5s linear forwards
}
.stickers{font-size:30px;line-height:1.9;word-spacing:5px}
@keyframes floatUp{
  0%{transform:translateY(0) rotate(0deg);opacity:0}
  12%{opacity:1}
  100%{transform:translateY(-115vh) rotate(35deg);opacity:0}
}
@keyframes bounce{
  0%,100%{transform:translateY(0)}
  50%{transform:translateY(-5px)}
}
@media(prefers-reduced-motion:reduce){
  *,*::before,*::after{animation:none!important;transition:none!important}
}
</style>
</head>
<body>
<main class="card">
  <div class="badge">🎁💗🧸</div>
  <h1 id="heading">Er. Sahiba 👑</h1>
  <p id="intro">
    Aapke liye ek secret surprise hai ji! 🥹💝<br>
    Password daalo aur surprise unlock karo 🎀🔐
  </p>

  <form id="form">
    <div class="field">
      <input id="password" type="password" autocomplete="current-password"
        placeholder="Secret password 🔐" required maxlength="256">
      <button class="toggle" id="toggle" type="button"
        aria-label="Show password">👁️</button>
    </div>
    <button class="submit" type="submit">Unlock My Surprise 💖🎁</button>
  </form>

  <div class="msg" id="message" role="status" aria-live="polite"></div>
  <div class="hint" id="hint"></div>

  <button id="tryAgain" class="try-btn" type="button">Try Again 💖🔄</button>
  <button id="askButton" class="ask-btn" type="button">
    💌 Password poochne ke liye yahan click karein 😘
  </button>

  <section id="contactScreen">
    <div class="stickers">😂 🤭 🙈 😜 💋 💖 🧸 🎀 😘 💞</div>
    <h1 style="font-size:28px">Ohooo, Madam Ji! 😂❤️</h1>
    <p>
      Ab toh apne pati ji se hi password poochhna padega! 😜💋💕<br>
      Itna bhi kya dimaag lagana, meri jaan! 🙈🥹💗
    </p>
    <div class="stickers">🌸 😘 🤣 💝 🙈 💋 🫶 😏 🎀</div>
    <div class="actions">
      <a class="wa" id="wa" target="_blank" rel="noopener noreferrer">
        💚 WhatsApp par password poochhein 💌
      </a>
      <a class="call" href="tel:+917905241894">
        📞 Call karo, mere pyare pati ji ❤️😘
      </a>
    </div>
    <div class="stickers">🙈 😜 😂 💋 😘 💝 🌸 💗 🤣</div>
  </section>

  <div class="small" id="footer">Made with endless love 💗✨</div>
</main>

<script>
const form = document.querySelector("#form");
const input = document.querySelector("#password");
const message = document.querySelector("#message");
const hint = document.querySelector("#hint");
const tryAgain = document.querySelector("#tryAgain");
const askButton = document.querySelector("#askButton");
const contactScreen = document.querySelector("#contactScreen");
const intro = document.querySelector("#intro");
const footer = document.querySelector("#footer");
const heading = document.querySelector("#heading");
const submit = form.querySelector(".submit");

let attempts = 0;
let busy = false;
let finished = false;

document.querySelector("#toggle").addEventListener("click", () => {
  input.type = input.type === "password" ? "text" : "password";
  document.querySelector("#toggle").textContent =
    input.type === "password" ? "👁️" : "🙈";
});

document.querySelector("#wa").href =
  "https://wa.me/917905241894?text=" +
  encodeURIComponent(
    "Baby please 🥹❤️\\n\\n" +
    "Password bata do na 🙈💗 Aapki Er. Sahiba apne surprise ka wait kar rahi hai 🎁😘\\n\\n" +
    "Love you, mere pyare pati ji 💋💕"
  );

function sprinkleEmojis() {
  const emojis = [
    "💗","💖","💕","💋","😘","🙈","😜","😂","🧸","🌸",
    "💝","🎀","🥹","😏","🫶","❤️","🤣","💞","🌷","✨","😝"
  ];

  for (let i = 0; i < 45; i++) {
    const el = document.createElement("span");
    el.className = "float";
    el.textContent = emojis[Math.floor(Math.random() * emojis.length)];
    el.style.left = Math.random() * 100 + "vw";
    el.style.animationDuration = (4 + Math.random() * 4) + "s";
    el.style.animationDelay = (Math.random() * 1.5) + "s";
    el.style.fontSize = (20 + Math.random() * 24) + "px";
    document.body.appendChild(el);
    setTimeout(() => el.remove(), 9000);
  }
}

function showContactScreen() {
  finished = true;
  form.style.display = "none";
  tryAgain.style.display = "none";
  askButton.style.display = "none";
  intro.style.display = "none";
  heading.style.display = "none";
  message.style.display = "none";
  hint.style.display = "none";
  footer.style.display = "none";
  contactScreen.style.display = "block";
  sprinkleEmojis();
}

tryAgain.addEventListener("click", () => {
  if (finished || busy || attempts >= 4) return;

  message.textContent = "";
  hint.textContent = "";
  tryAgain.style.display = "none";
  askButton.style.display = "none";
  form.style.display = "block";
  input.disabled = false;
  submit.disabled = false;
  input.value = "";
  input.focus();
});

askButton.addEventListener("click", showContactScreen);

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  if (busy || finished) return;

  busy = true;
  submit.disabled = true;
  message.textContent = "Password check ho raha hai ji... 🔐💗";
  hint.textContent = "";

  try {
    const response = await fetch("/__auth", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: input.value })
    });

    const data = await response.json().catch(() => ({}));

    if (response.ok && data.success) {
      let target = "/";
      try {
        const saved = sessionStorage.getItem("bday_return_url");
        if (saved) {
          const parsed = new URL(saved, location.origin);
          if (parsed.origin === location.origin &&
              !parsed.pathname.startsWith("/__")) {
            target = parsed.pathname + parsed.search + parsed.hash;
          }
        }
      } catch {}
      location.replace(target);
      return;
    }

    if (response.status === 429) {
      attempts = 4;
    } else if (Number(data.attempts) > 0) {
      attempts = Number(data.attempts);
    } else {
      message.textContent = "Server se response nahi mila ji 😭";
      hint.textContent = "Deployment aur internet connection check karo. 💗";
      form.style.display = "block";
      return;
    }

    input.value = "";
    form.style.display = "none";
    tryAgain.style.display = "none";
    askButton.style.display = "none";

    if (attempts === 1) {
      message.textContent = "Ofhoo... Glt h meri Er. Sahiba 😏❤️";
      hint.textContent =
        "Kya hua ji? Apne surprise ka password bhi bhool gayi? 🙈🥹💕";
      tryAgain.textContent = "Try Again 💖🔄";
      tryAgain.style.display = "block";
    } else if (attempts === 2) {
      message.textContent = "Haye re meri bhulakkad Madam Ji! 😂🙈";
      hint.textContent =
        "Thoda dimaag lagao ji! 😜🧠 Surprise aise thodi khulega! 🎁💗";
      tryAgain.textContent = "Try Again 😜💗";
      tryAgain.style.display = "block";
    } else if (attempts === 3) {
      message.textContent =
        "Kya Er. Sahiba, ek password bhi nahi crack kiya ja raha? 😂🙈🔐";
      hint.textContent = "Abhi ek chance aur hai ji! 😏💋 Soch lo, Madam Ji! 💞";
      tryAgain.textContent = "Try Again 💗🔄";
      tryAgain.style.display = "block";
      askButton.style.display = "block";
    } else {
      message.textContent = "Haar gayi na, meri Er. Sahiba? 😂🙈❤️";
      hint.textContent =
        "Ab toh apne pati ji se hi password poochhna padega! 😜💋💕";
      askButton.textContent =
        "💌 Password poochne ke liye yahan click karein 😘";
      askButton.style.display = "block";
    }
  } catch {
    message.textContent = "Connection issue ho gaya ji 😭📶";
    hint.textContent = "Internet check karke dobara try karo. 💗";
    form.style.display = "block";
  } finally {
    busy = false;
    submit.disabled = false;
  }
});
</script>
</body>
</html>`;
}

function injectWebsiteRefreshScript(html) {
  const script = `<script>
(function(){
  try {
    if (sessionStorage.getItem("bday_restore_scroll") === "1") {
      var savedY = Number(sessionStorage.getItem("bday_scroll_y") || 0);
      sessionStorage.removeItem("bday_restore_scroll");
      sessionStorage.removeItem("bday_scroll_y");
      window.addEventListener("load", function(){
        requestAnimationFrame(function(){
          window.scrollTo(0, savedY);
          setTimeout(function(){ window.scrollTo(0, savedY); }, 250);
        });
      });
    }

    window.addEventListener("pagehide", function(){
      try {
        sessionStorage.setItem("bday_return_url", location.href);
        sessionStorage.setItem("bday_scroll_y", String(window.scrollY));
        sessionStorage.setItem("bday_restore_scroll", "1");
      } catch(e) {}
    });
  } catch(e) {}
})();
</script>`;

  if (/<\/body>/i.test(html)) {
    return html.replace(/<\/body>/i, script + "</body>");
  }
  return html + script;
}

async function serveProtectedPage(context) {
  const response = await context.next();
  const contentType = response.headers.get("Content-Type") || "";

  if (!contentType.includes("text/html")) return response;

  const html = await response.text();
  const updatedHtml = injectWebsiteRefreshScript(html);
  const headers = new Headers(response.headers);

  for (const [key, value] of Object.entries(BASE_HEADERS)) {
    headers.set(key, value);
  }

  headers.set("Content-Type", "text/html; charset=utf-8");
  headers.delete("Content-Length");
  headers.delete("Content-Encoding");
  headers.delete("ETag");

  return new Response(updatedHtml, {
    status: response.status,
    statusText: response.statusText,
    headers
  });
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
      "Website configuration incomplete. Configure BDAY_PASSWORD and a SESSION_SECRET of at least 32 characters.",
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
      return json({ error: "Method not allowed." }, 405, { Allow: "POST" });
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
        { "Set-Cookie": setCookie("bday_state", token, 604800) }
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

    const headers = new Headers({
      ...BASE_HEADERS,
      "Content-Type": "application/json; charset=utf-8"
    });

    headers.append("Set-Cookie", setCookie("bday_ticket", ticket, 30));
    headers.append("Set-Cookie", clearCookie("bday_state"));

    return new Response(JSON.stringify({ success: true }), {
      status: 200,
      headers
    });
  }

  if (url.pathname === "/" || url.pathname === "/index.html") {
    const ticket = await readToken(
      cookieValue(request, "bday_ticket"),
      env.SESSION_SECRET
    );

    if (ticket?.kind === "one-use") {
      return serveProtectedPage(context);
    }

    const headers = new Headers({
      ...BASE_HEADERS,
      "Content-Type": "text/html; charset=utf-8",
      "Set-Cookie": clearCookie("bday_state")
    });

    return new Response(loginPage(), {
      status: 200,
      headers
    });
  }

  return context.next();
}
