// Estudio · servidor de IA principal (Cloudflare Worker, plan gratuito)
// Variables (Settings > Variables and Secrets del Worker):
//   GEMINI_API_KEY      (secreto)  clave de Google AI Studio
//   FIREBASE_PROJECT_ID            id del proyecto Firebase (p. ej. estudio-lopbas)
//   ALLOWED_EMAILS                 correos permitidos separados por comas
//   ALLOWED_ORIGINS                p. ej. https://albertosuperinventos.github.io
//   GEMINI_MODELS       (opcional) modelos en orden de preferencia, separados por comas

const JWKS_URL = "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com";
const MAX_B64 = 18 * 1024 * 1024;
let jwks = { keys: null, exp: 0 };

export default {
  async fetch(req, env) {
    const origin = req.headers.get("Origin") || "";
    const permitidos = lista(env.ALLOWED_ORIGINS);
    const okOrigin = !permitidos.length || permitidos.includes(origin);
    const cors = {
      "Access-Control-Allow-Origin": okOrigin ? (origin || "*") : "null",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
      "Access-Control-Max-Age": "86400",
      "Vary": "Origin"
    };
    const url = new URL(req.url);
    if (req.method === "OPTIONS") return new Response(null, { headers: cors });
    if (url.pathname === "/health") return json({ ok: true, servidor: "worker" }, 200, cors);
    if (!["/ai", "/telegram-test"].includes(url.pathname) || req.method !== "POST") return json({ error: "No encontrado" }, 404, cors);
    if (!okOrigin) return json({ error: "Origen no permitido" }, 403, cors);

    let user;
    try { user = await verificarToken((req.headers.get("Authorization") || "").replace(/^Bearer\s+/i, ""), env.FIREBASE_PROJECT_ID); }
    catch (e) { return json({ error: "Sesión no válida, vuelve a entrar" }, 401, cors); }
    const emails = lista(env.ALLOWED_EMAILS).map(s => s.toLowerCase());
    if (emails.length && !emails.includes(String(user.email || "").toLowerCase())) return json({ error: "Usuario no autorizado" }, 403, cors);

    if (url.pathname === "/telegram-test") {
      try { return json(await pruebaTelegram(env, user.sub), 200, cors); }
      catch (e) { return json({ error: e.message }, 400, cors); }
    }

    let body;
    try { body = await req.json(); } catch (e) { return json({ error: "Petición no válida" }, 400, cors); }
    const tam = (body.archivos || []).reduce((n, a) => n + String(a.data || "").length, 0);
    if (tam > MAX_B64) return json({ error: "Los adjuntos son demasiado grandes (máx. ~13 MB por petición)" }, 413, cors);

    let p;
    try { p = construirPrompt(body); } catch (e) { return json({ error: e.message }, 400, cors); }
    try {
      const out = await gemini(env, p.sistema, p.partes);
      return json(out, 200, cors);
    } catch (e) {
      return json({ error: "La IA no ha respondido (" + (e.status || "error") + "). Prueba de nuevo en un rato." }, e.status === 429 ? 429 : 502, cors);
    }
  },

  // Disparador programado (Cron Triggers): "0 20 * * *" y "0 21 * * *" (UTC).
  // Solo envía cuando en Madrid son las 22, así cubre horario de invierno y de verano.
  async scheduled(event, env, ctx) {
    if (horaMadrid(new Date(event.scheduledTime)) !== 22) return;
    ctx.waitUntil(enviarAvisos(env, new Date(event.scheduledTime)));
  }
};

// ---------- Avisos por Telegram ----------
// Variables extra: TELEGRAM_BOT_TOKEN (secreto), FIREBASE_SERVICE_ACCOUNT (secreto, JSON completo),
// FIREBASE_DB_URL (opcional; por defecto https://<FIREBASE_PROJECT_ID>-default-rtdb.europe-west1.firebasedatabase.app)
const TZ = "Europe/Madrid";
// Días de antelación con aviso (siempre a las 22:00) y qué tipos avisan en cada uno
const TODOS = ["Examen", "Entrega", "Tarea", "Otro"];
const AVISOS = { 1: TODOS, 2: TODOS, 3: ["Examen"] };

function horaMadrid(d) {
  return +new Intl.DateTimeFormat("en-GB", { timeZone: TZ, hour: "2-digit", hour12: false }).format(d) % 24;
}
function ymdMadrid(d, sumarDias = 0) {
  const [y, m, dd] = new Intl.DateTimeFormat("en-CA", { timeZone: TZ, year: "numeric", month: "2-digit", day: "2-digit" }).format(d).split("-").map(Number);
  return new Date(Date.UTC(y, m - 1, dd + sumarDias)).toISOString().slice(0, 10);
}
function fechaTxt(ymd) {
  const [y, m, d] = ymd.split("-").map(Number);
  return new Date(Date.UTC(y, m - 1, d)).toLocaleDateString("es-ES", { weekday: "long", day: "numeric", month: "long", timeZone: "UTC" });
}
const escH = s => String(s ?? "").replace(/[&<>]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
const ICONO = { Examen: "📝", Entrega: "📤", Tarea: "📚", Otro: "📌" };

let gtoken = { t: null, exp: 0 };
async function tokenGoogle(env) {
  if (gtoken.t && Date.now() < gtoken.exp) return gtoken.t;
  let sa;
  try { sa = JSON.parse(env.FIREBASE_SERVICE_ACCOUNT); } catch (e) { throw new Error("Falta o es incorrecta la variable FIREBASE_SERVICE_ACCOUNT"); }
  const ahora = Math.floor(Date.now() / 1000);
  const enc = o => btoa(JSON.stringify(o)).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
  const sinFirma = enc({ alg: "RS256", typ: "JWT" }) + "." + enc({
    iss: sa.client_email, aud: "https://oauth2.googleapis.com/token", iat: ahora, exp: ahora + 3600,
    scope: "https://www.googleapis.com/auth/firebase.database https://www.googleapis.com/auth/userinfo.email"
  });
  const pem = sa.private_key.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  const der = Uint8Array.from(atob(pem), c => c.charCodeAt(0));
  const key = await crypto.subtle.importKey("pkcs8", der, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
  const firma = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(sinFirma)));
  let bin = ""; firma.forEach(b => bin += String.fromCharCode(b));
  const jwt = sinFirma + "." + btoa(bin).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
  const r = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: "grant_type=" + encodeURIComponent("urn:ietf:params:oauth:grant-type:jwt-bearer") + "&assertion=" + jwt
  });
  if (!r.ok) throw new Error("Google no acepta la cuenta de servicio (" + r.status + ")");
  const j = await r.json();
  gtoken = { t: j.access_token, exp: Date.now() + (j.expires_in - 120) * 1000 };
  return gtoken.t;
}
async function leerDB(env, ruta, query = "") {
  const base = (env.FIREBASE_DB_URL || `https://${env.FIREBASE_PROJECT_ID}-default-rtdb.europe-west1.firebasedatabase.app`).replace(/\/+$/, "");
  const r = await fetch(`${base}/${ruta}.json${query}`, { headers: { Authorization: "Bearer " + await tokenGoogle(env) } });
  if (!r.ok) throw new Error("No se pudo leer la base de datos (" + r.status + ")");
  return r.json();
}
async function telegram(env, chatId, texto) {
  if (!env.TELEGRAM_BOT_TOKEN) throw new Error("Falta la variable TELEGRAM_BOT_TOKEN en el Worker");
  const r = await fetch(`https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ chat_id: chatId, text: texto, parse_mode: "HTML", disable_web_page_preview: true })
  });
  const j = await r.json().catch(() => ({}));
  if (!j.ok) {
    const d = String(j.description || r.status);
    if (/chat not found|bot can't initiate|blocked/i.test(d)) throw new Error("Telegram no deja escribirte: abre @FamiliaLopBas_bot, pulsa Iniciar y vuelve a probar");
    throw new Error("Telegram: " + d);
  }
}
// Construye el mensaje de un usuario (null si no hay nada que avisar)
async function resumenUsuario(env, uid, ahora) {
  const [agenda, asignaturas] = await Promise.all([leerDB(env, `u/${uid}/agenda`), leerDB(env, `u/${uid}/asignaturas`)]);
  const linea = e => {
    const a = e.asig && asignaturas?.[e.asig]?.nombre;
    return `${ICONO[e.tipo] || "📌"} <b>${escH(e.tipo || "Aviso")}</b>${" · " + escH(a || "Personal")}${e.titulo ? ": " + escH(e.titulo) : ""}`;
  };
  const pend = Object.values(agenda || {}).filter(e => e && !e.hecho);
  const partes = [];
  for (const n of [1, 2, 3]) {
    const f = ymdMadrid(ahora, n);
    const items = pend.filter(e => e.fecha === f && AVISOS[n].includes(e.tipo || "Otro"));
    const cab = n === 1 ? "Mañana" : n === 2 ? "Pasado mañana" : `Dentro de ${n} días`;
    if (items.length) partes.push(`<b>${cab}, ${fechaTxt(f)}</b>\n` + items.map(linea).join("\n"));
  }
  return partes.length ? "🔔 <b>Estudio</b>\n\n" + partes.join("\n\n") : null;
}
async function enviarAvisos(env, ahora = new Date()) {
  const uids = Object.keys(await leerDB(env, "u", "?shallow=true") || {});
  for (const uid of uids) {
    try {
      const chat = (await leerDB(env, `u/${uid}/perfil/telegramId`));
      if (!chat) continue;
      const msg = await resumenUsuario(env, uid, ahora);
      if (msg) await telegram(env, String(chat).trim(), msg);
    } catch (e) { console.log("Aviso fallido", uid, e.message); }
  }
}
async function pruebaTelegram(env, uid) {
  const chat = await leerDB(env, `u/${uid}/perfil/telegramId`);
  if (!chat) throw new Error("Primero guarda tu ID de Telegram");
  const msg = await resumenUsuario(env, uid, new Date());
  await telegram(env, String(chat).trim(), "✅ <b>Avisos de Estudio activados</b>\nCada día a las 22:00 te escribiré lo que tienes 1 y 2 días después, y los exámenes también con 3 días de antelación." +
    (msg ? "\n\nAsí sería el aviso de esta noche:\n\n" + msg : "\n\nAhora mismo no tienes nada para mañana."));
  return { ok: true };
}

function lista(s) { return String(s || "").split(",").map(x => x.trim()).filter(Boolean); }
function json(o, status, headers) {
  return new Response(JSON.stringify(o), { status, headers: { ...headers, "Content-Type": "application/json; charset=utf-8" } });
}

// ---------- Verificación del token de Firebase (RS256) ----------
function b64url(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/"); while (s.length % 4) s += "=";
  const bin = atob(s); const u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return u;
}
async function claves() {
  if (jwks.keys && Date.now() < jwks.exp) return jwks.keys;
  const r = await fetch(JWKS_URL);
  const j = await r.json();
  const m = (r.headers.get("Cache-Control") || "").match(/max-age=(\d+)/);
  jwks = { keys: j.keys, exp: Date.now() + (m ? +m[1] * 1000 : 3600000) };
  return jwks.keys;
}
async function verificarToken(token, projectId) {
  const [h, p, s] = String(token).split(".");
  if (!h || !p || !s || !projectId) throw new Error("token");
  const td = new TextDecoder();
  const header = JSON.parse(td.decode(b64url(h)));
  const payload = JSON.parse(td.decode(b64url(p)));
  if (header.alg !== "RS256") throw new Error("alg");
  const jwk = (await claves()).find(k => k.kid === header.kid);
  if (!jwk) throw new Error("kid");
  const key = await crypto.subtle.importKey("jwk", { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: "RS256", ext: true },
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
  const ok = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, b64url(s), new TextEncoder().encode(h + "." + p));
  const ahora = Date.now() / 1000;
  if (!ok || payload.aud !== projectId || payload.iss !== "https://securetoken.google.com/" + projectId ||
      payload.exp < ahora || payload.iat > ahora + 300 || !payload.sub) throw new Error("token");
  return payload;
}

// ---------- Prompts ----------
// Formatos de esquema visual: qué pedir y estructura JSON que dibuja la app
const ESQUEMAS = {
  mapa: { que: "un mapa conceptual: una idea central y de 4 a 7 ramas con los conceptos clave",
    json: `"centro" (la idea central) y "ramas": [{"t": "concepto", "sub": "autor/es o etiqueta breve, o vacío", "items": ["2 a 4 líneas: definición, concepto clave, ejemplo…"]}]` },
  sinoptico: { que: "un cuadro sinóptico que clasifique y jerarquice la información de lo general a lo concreto (3 niveles como máximo)",
    json: `"centro" (tema general) y "ramas": [{"t": "categoría", "sub": "", "items": ["subcategorías o elementos, 2 a 5"]}] (de 2 a 6 ramas)` },
  linea: { que: "una línea del tiempo en orden cronológico con los hechos clave (de 4 a 12)",
    json: `"eventos": [{"fecha": "año o fecha exacta", "t": "hecho", "d": "importancia en una línea", "etapa": "nombre de la etapa o periodo (pocas etapas distintas)"}]` },
  comparativa: { que: "una tabla comparativa entre los 2 a 4 conceptos, teorías o elementos principales del material",
    json: `"columnas": ["Criterio", "Elemento A", "Elemento B", …] y "filas": [["criterio", "valor A", "valor B", …]] (de 4 a 8 filas: definición, características, autores o fechas, ejemplos, diferencia clave…)` },
  flujo: { que: "un diagrama de flujo con los pasos de un proceso o procedimiento en orden (de 3 a 9 pasos)",
    json: `"pasos": [{"t": "paso", "d": "detalle breve o vacío", "decision": "pregunta de sí/no si el paso es una decisión, o vacío"}]` },
  infografia: { que: "una infografía que explique el tema de un vistazo en bloques (partes, fases o elementos), cada uno con su función y un dato destacado",
    json: `"bloques": [{"t": "parte o fase", "d": "función o explicación breve", "dato": "dato, cifra o ejemplo destacado, o vacío"}] (de 3 a 8 bloques)` },
  analisis: { que: "un esquema de análisis que descomponga el tema en profundidad",
    json: `"secciones": [{"t": "Definición" | "Características" | "Causas" | "Consecuencias" | "Tipos" | "Ejemplo" | otro título adecuado, "items": ["1 a 4 líneas"]}] (de 3 a 6 secciones, elige las que encajen con el tema)` }
};

function construirPrompt(b) {
  const nivel = String(b.nivel || "estudiante").slice(0, 200);
  const asignatura = String(b.asignatura || "").slice(0, 200);
  const archivos = (b.archivos || []).filter(a => a && a.data && /^(image\/|application\/pdf)/.test(a.mime || ""))
    .map(a => ({ inline_data: { mime_type: a.mime, data: a.data } }));

  if (b.task === "transcribir") {
    if (!archivos.length) throw new Error("No hay fotos ni PDF que leer");
    return {
      sistema: `Eres un asistente de estudio para un alumno de ${nivel}. Transcribe con fidelidad el contenido académico de las fotos y PDF (apuntes, pizarra, libro, diapositivas) de la asignatura "${asignatura}". Corrige errores evidentes de lectura, conserva fórmulas, fechas y ejemplos, y ordénalo con títulos y viñetas en texto plano. No añadas contenido que no aparezca. Marca lo ilegible como [ilegible]. Responde solo JSON: {"tema": "título breve del tema", "texto": "transcripción"}`,
      partes: [{ text: "Transcribe este material." }, ...archivos]
    };
  }
  if (b.task === "resumen") {
    const clases = (b.clases || []).slice(0, 200).map(c =>
      `### Clase del ${c.fecha || "?"}${c.tema ? " — " + c.tema : ""}\n${String(c.texto || "").slice(0, 20000)}`).join("\n\n");
    if (!clases.trim() && !archivos.length) throw new Error("No hay contenido para resumir");
    return {
      sistema: `Eres un profesor que prepara material de repaso para un alumno de ${nivel}, asignatura "${asignatura}". A partir SOLO del material dado (${b.alcance || "clases"}), crea:
- "titulo": título breve del contenido.
- "tabla": tabla resumen con 2 a 4 columnas adecuadas a la asignatura (p. ej. Concepto | Explicación | Ejemplo; en Historia Fecha | Hecho | Causa/Consecuencia; en idiomas Palabra o estructura | Significado | Ejemplo; en Matemáticas Concepto | Fórmula/regla | Ejemplo). Formato {"columnas": [...], "filas": [[...], ...]}.
- "puntos": de 3 a 10 ideas clave, frases cortas.
- "tarjetas": de 6 a 25 tarjetas de pregunta/respuesta tipo examen, respuestas breves y exactas. Formato [{"p": "...", "r": "..."}].
Lenguaje claro y adaptado al nivel. No inventes contenido que no esté en el material; si es escaso, genera menos. Responde solo JSON con las claves titulo, tabla, puntos y tarjetas.`,
      partes: [{ text: clases || "El material está en los adjuntos." }, ...archivos]
    };
  }
  if (b.task === "esquema") {
    const f = ESQUEMAS[b.formato];
    if (!f) throw new Error("Formato de esquema desconocido");
    const clases = (b.clases || []).slice(0, 200).map(c =>
      `### Clase del ${c.fecha || "?"}${c.tema ? " — " + c.tema : ""}\n${String(c.texto || "").slice(0, 20000)}`).join("\n\n");
    if (!clases.trim() && !archivos.length) throw new Error("No hay contenido para el esquema");
    return {
      sistema: `Eres un profesor que prepara material visual de estudio para un alumno de ${nivel}, asignatura "${asignatura}". A partir SOLO del material dado, crea ${f.que}.
Reglas: textos muy breves (cada línea de 3 a 14 palabras), lenguaje claro y adaptado al nivel, ortografía correcta en español. Si el nivel es universitario, incluye autores, teorías y términos técnicos de referencia cuando aparezcan o sean imprescindibles para entender el material. No inventes datos (fechas, cifras, autores) que no estén en el material o no sean de conocimiento básico seguro del tema. Si el material no encaja bien en este formato, adáptalo lo mejor posible.
Responde solo JSON con: "titulo" (breve), "subtitulo" (qué muestra, una línea), "idea" (idea clave final en una frase) y además ${f.json}`,
      partes: [{ text: clases || "El material está en los adjuntos." }, ...archivos]
    };
  }
  if (b.task === "horario") {
    if (!archivos.length) throw new Error("Falta la imagen del horario");
    return {
      sistema: `Extrae el horario semanal de clases de la imagen o PDF. Devuelve solo JSON: {"slots": [{"dia": 1, "ini": "HH:MM", "fin": "HH:MM", "asignatura": "", "profesor": "", "tipo": "", "grupo": "", "aula": "", "cuatri": "anual"}]}. dia: 1=lunes … 5=viernes. tipo: "Teoría", "Práctica", "Seminario" o "" si no consta. cuatri: "C1", "C2" o "anual" si no consta. Usa el nombre completo de la asignatura tal como aparece. Omite recreos.`,
      partes: [{ text: "Extrae el horario." }, ...archivos]
    };
  }
  throw new Error("Tarea desconocida");
}

// ---------- Gemini ----------
async function gemini(env, sistema, partes) {
  const modelos = lista(env.GEMINI_MODELS || "gemini-2.5-flash,gemini-2.5-flash-lite");
  let ultimo;
  for (const m of modelos) {
    const r = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${m}:generateContent`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-goog-api-key": env.GEMINI_API_KEY },
      body: JSON.stringify({
        systemInstruction: { parts: [{ text: sistema }] },
        contents: [{ role: "user", parts: partes }],
        generationConfig: { responseMimeType: "application/json", temperature: 0.3 }
      })
    });
    if (r.ok) {
      const j = await r.json();
      const txt = (j.candidates?.[0]?.content?.parts || []).map(x => x.text || "").join("");
      return parseJson(txt);
    }
    ultimo = new Error(await r.text()); ultimo.status = r.status;
    if (![429, 500, 503, 404].includes(r.status)) break; // solo se prueba el siguiente modelo si es saturación o modelo retirado
  }
  throw ultimo;
}
function parseJson(t) {
  t = String(t).trim().replace(/^```(?:json)?\s*/i, "").replace(/```\s*$/, "");
  try { return JSON.parse(t); }
  catch (e) { const a = t.indexOf("{"), b = t.lastIndexOf("}"); if (a >= 0 && b > a) return JSON.parse(t.slice(a, b + 1)); throw e; }
}
