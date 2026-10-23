const encoder = new TextEncoder();

async function sign(value, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(value)
  );

  return btoa(String.fromCharCode(...new Uint8Array(signature)));
}

export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);

  const headers = {
    "Cache-Control": "no-store, no-cache, must-revalidate",
    "Pragma": "no-cache",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer"
  };

  if (!env.BDAY_PASSWORD || !env.SESSION_SECRET) {
    return new Response("Website configuration incomplete.", {
      status: 500,
      headers
    });
  }

  if (url.pathname === "/__auth" && request.method === "POST") {
    let body;

    try {
      body = await request.json();
    } catch {
      return Response.json(
        { error: "Invalid request." },
        { status: 400, headers }
      );
    }

    if (typeof body.password !== "string") {
      return Response.json(
        { error: "Invalid request." },
        { status: 400, headers }
      );
    }

    if (body.password !== env.BDAY_PASSWORD) {
      return Response.json(
        { error: "Incorrect password." },
        { status: 401, headers }
      );
    }

    const expires = Date.now() + 60_000;
    const payload = `${expires}`;
    const signature = await sign(payload, env.SESSION_SECRET);

    return Response.json(
      { success: true },
      {
        headers: {
          ...headers,
          "Set-Cookie": `bday_ticket=${payload}.${signature}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=60`
        }
      }
    );
  }

  if (url.pathname === "/__reset" && request.method === "POST") {
    return new Response("Reset requires the attempt counter to be implemented.", {
      status: 501,
      headers
    });
  }

  if (url.pathname !== "/") {
    return next();
  }

  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(/(?:^|;\s*)bday_ticket=([^;]+)/);

  if (match) {
    const [expires, signature] = match[1].split(".");

    if (
      expires &&
      signature &&
      Number(expires) > Date.now() &&
      await sign(expires, env.SESSION_SECRET) === signature
    ) {
      return next();
    }
  }

  return new Response(
    `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Er. Sahiba ❤️</title>
<style>
body{margin:0;min-height:100vh;display:grid;place-items:center;background:linear-gradient(135deg,#ffe1ed,#e9d5ff);font-family:Arial,sans-serif;color:#64234d}
main{width:min(86%,360px);padding:28px 22px;background:#ffffffeb;border-radius:24px;text-align:center;box-shadow:0 12px 40px #8b477733}
h1{font-size:28px}input,button{box-sizing:border-box;width:100%;padding:14px;margin-top:12px;border-radius:12px;font-size:16px}
input{border:1px solid #d8a7c5}button{border:0;background:#d63384;color:white;font-weight:bold}
#message{margin-top:18px;line-height:1.5}.extra{display:none}a{display:block;margin-top:12px;padding:12px;background:#25a55b;color:white;text-decoration:none;border-radius:12px}
</style>
</head>
<body>
<main>
<h1>Er. Sahiba ❤️</h1>
<p>Aapka surprise aapka intezaar kar raha hai 🎁</p>
<form id="form">
<input id="password" type="password" placeholder="Enter password" required>
<label><input id="show" type="checkbox" style="width:auto"> Show password</label>
<button type="submit">Unlock my surprise 💗</button>
</form>
<div id="message" role="status"></div>
<div id="extra" class="extra">
<a href="tel:+917905241894">Call ❤️</a>
<a id="wa" target="_blank" rel="noopener">WhatsApp 💌</a>
<button id="reset" type="button">Option 2: Page refresh kar lo</button>
</div>
</main>
<script>
let attempts=0, locked=false;
const form=document.querySelector("#form");
const password=document.querySelector("#password");
const message=document.querySelector("#message");
const extra=document.querySelector("#extra");
document.querySelector("#show").onchange=e=>password.type=e.target.checked?"text":"password";
document.querySelector("#wa").href="https://wa.me/917905241894?text="+encodeURIComponent("Baby please 🥹❤️\\n\\nPassword bata do na 🙈💗 Aapki Er. Sahiba apne surprise ka wait kar rahi hai 🎁😘\\n\\nLove you, mere pyare pati ji 💋💕");
form.onsubmit=async e=>{
e.preventDefault();if(locked)return;
const response=await fetch("/__auth",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({password:password.value})});
if(response.ok){location.reload();return}
attempts++;
message.textContent=attempts<3?"Ofhoo... Glt h meri Er. Sahiba 😏❤️":attempts===3?"Ofho mdm ji ab mujhe yaad kr lo 😘❤️":"Ofhooo, Madam Ji! Ab bas, aur attempts nahi! 🙈💕";
if(attempts>=2)extra.style.display="block";
if(attempts>=4){locked=true;form.querySelector("button").disabled=true;const call=document.createElement("a");call.href="tel:+917905241894";call.textContent="Option 1: Mujhe yaad kar lo";extra.prepend(call)}
password.value="";
};
document.querySelector("#reset").onclick=()=>location.reload();
</script>
</body>
</html>`,
    {
      status: 200,
      headers: {
        ...headers,
        "Content-Type": "text/html; charset=utf-8"
      }
    }
  );
    }
