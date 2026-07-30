import express from "express";
import session from "express-session";
import bcrypt from "bcryptjs";
import http from "http";
import { Server } from "socket.io";
import { fileURLToPath } from "url";
import path from "path";
import fs from "fs";
import crypto from "crypto";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 3004;

// --- Almacenamiento simple en archivos JSON ---
const DATA_DIR = path.join(__dirname, "data");
const UPLOADS_DIR = path.join(DATA_DIR, "uploads");
const USERS_FILE = path.join(DATA_DIR, "users.json");
const MESSAGES_FILE = path.join(DATA_DIR, "messages.json");
// Hilo: se conservan las últimas N "conversaciones" (mensajes). Al llegar una nueva
// por encima del tope, se borra la más antigua.
const MAX_MESSAGES = Number(process.env.MAX_MESSAGES ?? 30);
// Vida de cada mensaje: se borra al cumplir este tiempo desde que se envió.
// Por defecto 24h; se puede aumentar con MESSAGE_TTL_HOURS en el entorno.
const MESSAGE_TTL_MS = Number(process.env.MESSAGE_TTL_HOURS ?? 24) * 60 * 60 * 1000;
const MAX_AUDIO = 8 * 1024 * 1024; // 8 MB por audio

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(UPLOADS_DIR, { recursive: true });

function loadJson(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return fallback;
  }
}
function saveJson(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

let users = loadJson(USERS_FILE, {}); // { usuario: { hash, nombre, avatar } }
let messages = loadJson(MESSAGES_FILE, []); // [ { user, text|type/url, ts } ]

// --- Sembrado de cuentas (producción con disco efímero) ---
// Crea papa/noah/lumi al arrancar si su contraseña está en el entorno.
// Así no hace falta commitear contraseñas ni depender de que el disco persista.
function sembrarCuentas() {
  const seeds = [
    ["papa", "Papa", process.env.PAPA_PASS, "/avatars/papa.svg"],
    ["noah", "Noah", process.env.NOAH_PASS, "/avatars/noah.svg"],
    ["lumi", "Lumi", process.env.LUMI_PASS, "/avatars/lumi.svg"],
  ];
  let cambio = false;
  for (const [user, nombre, pass, avatar] of seeds) {
    if (pass && !users[user]) {
      users[user] = { hash: bcrypt.hashSync(pass, 10), nombre, avatar };
      cambio = true;
    }
  }
  if (cambio) saveJson(USERS_FILE, users);
}
sembrarCuentas();

// --- Poda del hilo: TTL por mensaje + tope de conversaciones ---
function borrarAudioDeMensaje(msg) {
  if (msg && msg.type === "audio" && typeof msg.url === "string") {
    try {
      fs.unlinkSync(path.join(UPLOADS_DIR, path.basename(msg.url)));
    } catch {}
  }
}

// Quita los mensajes vencidos (más viejos que MESSAGE_TTL_MS) y recorta el hilo
// a las últimas MAX_MESSAGES conversaciones. Borra los audios de lo descartado.
// Devuelve true si hubo cambios.
function podarMensajes() {
  const limite = Date.now() - MESSAGE_TTL_MS;
  const vigentes = [];
  const descartados = [];
  for (const m of messages) {
    (m.ts >= limite ? vigentes : descartados).push(m);
  }
  // Recorta al tope: descarta los más antiguos que sobren
  if (vigentes.length > MAX_MESSAGES) {
    descartados.push(...vigentes.splice(0, vigentes.length - MAX_MESSAGES));
  }
  if (descartados.length === 0) return false;
  for (const m of descartados) borrarAudioDeMensaje(m);
  messages = vigentes;
  saveJson(MESSAGES_FILE, messages);
  return true;
}

// Poda al arrancar y luego de forma periódica, así el TTL se cumple aunque no
// lleguen mensajes nuevos.
podarMensajes();
setInterval(podarMensajes, 10 * 60 * 1000);

// --- App / sesión ---
const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

if (!process.env.SESSION_SECRET) {
  console.warn(
    "  ⚠  SESSION_SECRET no definido: se usa uno aleatorio y las sesiones se pierden\n" +
    "     al reiniciar. En producción definí SESSION_SECRET en el entorno."
  );
}
app.set("trust proxy", 1); // detrás del proxy del VPS (https)
const sessionMiddleware = session({
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex"),
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: "auto", // cookie segura sólo cuando la conexión es https
    maxAge: 1000 * 60 * 60 * 24 * 7,
  },
});
app.use(sessionMiddleware);

// --- Helpers ---
function limpiarUsuario(u) {
  return typeof u === "string" ? u.trim() : "";
}
function requireAuth(req, res, next) {
  if (req.session.user) return next();
  res.redirect("/login.html");
}

// --- Rutas de autenticación ---
app.post("/api/register", async (req, res) => {
  const user = limpiarUsuario(req.body.user).toLowerCase();
  const pass = req.body.pass || "";
  if (user.length < 2 || user.length > 20 || !/^[a-z0-9_ñ]+$/.test(user)) {
    return res.status(400).json({ error: "Usuario inválido (2-20, letras/números/_)." });
  }
  if (pass.length < 4) {
    return res.status(400).json({ error: "La contraseña debe tener al menos 4 caracteres." });
  }
  if (users[user]) {
    return res.status(409).json({ error: "Ese usuario ya existe." });
  }
  const hash = await bcrypt.hash(pass, 10);
  users[user] = { hash };
  saveJson(USERS_FILE, users);
  req.session.user = user;
  res.json({ ok: true, user });
});

app.post("/api/login", async (req, res) => {
  const user = limpiarUsuario(req.body.user).toLowerCase();
  const pass = req.body.pass || "";
  const record = users[user];
  if (!record || !(await bcrypt.compare(pass, record.hash))) {
    return res.status(401).json({ error: "Usuario o contraseña incorrectos." });
  }
  req.session.user = user;
  res.json({ ok: true, user });
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get("/api/me", (req, res) => {
  const u = req.session.user;
  if (!u || !users[u]) return res.json({ user: null });
  res.json({ user: u, nombre: users[u].nombre || u, avatar: users[u].avatar || null });
});

// Lista de perfiles (sin datos sensibles) para el selector del login y los avatares del chat
app.get("/api/perfiles", (req, res) => {
  const perfiles = Object.entries(users).map(([user, r]) => ({
    user,
    nombre: r.nombre || user,
    avatar: r.avatar || null,
  }));
  res.json(perfiles);
});

// --- Páginas ---
app.get("/", (req, res) => {
  res.redirect(req.session.user ? "/chat.html" : "/login.html");
});
app.get("/chat.html", requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, "public", "chat.html"));
});
app.use("/uploads", requireAuth, express.static(UPLOADS_DIR));
app.use(express.static(path.join(__dirname, "public")));

// --- Socket.io (chat en tiempo real) ---
io.engine.use(sessionMiddleware);

io.on("connection", (socket) => {
  const sess = socket.request.session;
  const user = sess && sess.user;
  if (!user) {
    socket.disconnect(true);
    return;
  }

  // Historial al entrar (podado primero por si algún mensaje ya venció)
  podarMensajes();
  socket.emit("history", messages.slice(-MAX_MESSAGES));
  socket.broadcast.emit("system", `${user} se conectó`);

  socket.on("message", (text) => {
    text = String(text || "").trim().slice(0, 1000);
    if (!text) return;
    const msg = { user, text, ts: Date.now() };
    messages.push(msg);
    podarMensajes();
    io.emit("message", msg);
  });

  socket.on("audio", (payload) => {
    try {
      const { mime, data } = payload || {};
      if (!data) return;
      const buf = Buffer.from(data); // socket.io entrega binario como Buffer/ArrayBuffer
      if (buf.length === 0 || buf.length > MAX_AUDIO) return;
      const ext = String(mime || "").includes("mp4")
        ? "m4a"
        : String(mime || "").includes("ogg")
        ? "ogg"
        : "webm";
      const fname = `${crypto.randomBytes(8).toString("hex")}.${ext}`;
      fs.writeFileSync(path.join(UPLOADS_DIR, fname), buf);
      const msg = { user, type: "audio", url: `/uploads/${fname}`, ts: Date.now() };
      messages.push(msg);
      podarMensajes();
      io.emit("message", msg);
    } catch (e) {
      console.error("Error guardando audio:", e);
    }
  });

  socket.on("disconnect", () => {
    socket.broadcast.emit("system", `${user} se desconectó`);
  });
});

server.listen(PORT, () => {
  console.log(`\n  Chat de niños funcionando en:  http://localhost:${PORT}\n`);
});
