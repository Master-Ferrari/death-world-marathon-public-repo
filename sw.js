// Service Worker зашифрованного сайта: подменяет каждый запрос к сайту расшифрованным
// файлом из e/<HMAC(путь)>.bin. Ключи кладёт страница входа (login.html) и они хранятся
// в IndexedDB как неизвлекаемые CryptoKey. /death-world-marathon-public-repo/ подставляет encrypt.mjs.
const BASE = "/death-world-marathon-public-repo/"
const DB = "site-keys"

const enc = new TextEncoder()

const MIME = {
  html: "text/html; charset=utf-8",
  css: "text/css; charset=utf-8",
  js: "text/javascript; charset=utf-8",
  mjs: "text/javascript; charset=utf-8",
  json: "application/json; charset=utf-8",
  xml: "application/xml; charset=utf-8",
  txt: "text/plain; charset=utf-8",
  md: "text/plain; charset=utf-8",
  svg: "image/svg+xml",
  png: "image/png",
  jpg: "image/jpeg",
  jpeg: "image/jpeg",
  gif: "image/gif",
  webp: "image/webp",
  avif: "image/avif",
  ico: "image/x-icon",
  mp4: "video/mp4",
  webm: "video/webm",
  mp3: "audio/mpeg",
  ogg: "audio/ogg",
  wav: "audio/wav",
  pdf: "application/pdf",
  woff: "font/woff",
  woff2: "font/woff2",
  ttf: "font/ttf",
}

function mimeOf(rel) {
  const ext = rel.split("/").pop().split(".").pop().toLowerCase()
  return MIME[ext] ?? "application/octet-stream"
}

// --- IndexedDB ---
function openDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB, 1)
    req.onupgradeneeded = () => req.result.createObjectStore("kv")
    req.onsuccess = () => resolve(req.result)
    req.onerror = () => reject(req.error)
  })
}

async function dbOp(mode, fn) {
  const db = await openDb()
  return new Promise((resolve, reject) => {
    const tx = db.transaction("kv", mode)
    const req = fn(tx.objectStore("kv"))
    tx.oncomplete = () => resolve(req.result)
    tx.onerror = () => reject(tx.error)
  })
}

let keysPromise = null
const getKeys = () => (keysPromise ??= dbOp("readonly", (s) => s.get("keys")).catch(() => undefined))
const setKeys = async (keys) => {
  await dbOp("readwrite", (s) => s.put(keys, "keys"))
  keysPromise = Promise.resolve(keys)
}
const clearKeys = async () => {
  await dbOp("readwrite", (s) => s.delete("keys"))
  keysPromise = Promise.resolve(undefined)
}

// --- жизненный цикл ---
self.addEventListener("install", () => self.skipWaiting())
self.addEventListener("activate", (e) => e.waitUntil(self.clients.claim()))

self.addEventListener("message", (e) => {
  if (e.data?.type !== "set-keys") return
  e.waitUntil(
    setKeys({ aes: e.data.aes, mac: e.data.mac }).then(
      () => e.ports[0]?.postMessage("ok"),
      (err) => e.ports[0]?.postMessage("error: " + err),
    ),
  )
})

// --- расшифровка ---
async function fileName(mac, rel) {
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", mac, enc.encode(rel)))
  return Array.from(sig.slice(0, 16), (b) => b.toString(16).padStart(2, "0")).join("")
}

// Кандидаты на файл для пути из URL (Quartz ссылается на страницы без .html)
function candidates(rel) {
  if (rel === "" || rel.endsWith("/")) return [rel + "index.html"]
  const last = rel.split("/").pop()
  return last.includes(".") ? [rel, rel + ".html"] : [rel + ".html", rel + "/index.html", rel]
}

async function load(keys, rel) {
  const res = await fetch(BASE + "e/" + (await fileName(keys.mac, rel)) + ".bin")
  if (!res.ok) return null
  const buf = await res.arrayBuffer()
  return crypto.subtle.decrypt(
    { name: "AES-GCM", iv: buf.slice(0, 12), additionalData: enc.encode(rel) },
    keys.aes,
    buf.slice(12),
  )
}

async function handle(request, rel) {
  const keys = await getKeys()
  if (!keys) return fetch(request)

  try {
    for (const candidate of candidates(rel)) {
      const body = await load(keys, candidate)
      if (body) return new Response(body, { headers: { "content-type": mimeOf(candidate) } })
    }
    const notFound = await load(keys, "404.html")
    return new Response(notFound ?? "Not found", { status: 404, headers: { "content-type": MIME.html } })
  } catch (err) {
    // ключ не подходит (сменили пароль) -> забываем его, сервер отдаст страницу входа
    console.warn("decrypt failed", rel, err)
    await clearKeys()
    return fetch(request)
  }
}

self.addEventListener("fetch", (e) => {
  const url = new URL(e.request.url)
  if (e.request.method !== "GET" || url.origin !== location.origin || !url.pathname.startsWith(BASE)) return

  const rel = decodeURIComponent(url.pathname.slice(BASE.length)).normalize("NFC")
  if (rel === "sw.js" || rel.startsWith("e/")) return

  // выход: открыть в адресной строке <сайт>/?logout
  if (e.request.mode === "navigate" && url.searchParams.has("logout")) {
    e.respondWith(clearKeys().then(() => Response.redirect(BASE, 302)))
    return
  }

  e.respondWith(handle(e.request, rel))
})
