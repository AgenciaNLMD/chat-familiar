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
const MAX_HISTORY = 200; // mensajes que se guardan / envían al entrar
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

// --- Limpieza diaria de mensajes y audios ---
const RESET_HOUR_UTC = Number(process.env.RESET_HOUR_UTC ?? 5); // ~02:00 en Argentina
function limpiarDiario() {
  messages = [];
  saveJson(MESSAGES_FILE, messages);
  try {
    for (const f of fs.readdirSync(UPLOADS_DIR)) fs.unlinkSync(path.join(UPLOADS_DIR, f));
  } catch {}
  console.log("Limpieza diaria: mensajes y audios borrados.");
}
function programarLimpieza() {
  const now = new Date();
  const next = new Date(
    Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), RESET_HOUR_UTC, 0, 0)
  );
  if (next <= now) next.setUTCDate(next.getUTCDate() + 1);
  setTimeout(() => {
    limpiarDiario();
    setInterval(limpiarDiario, 24 * 60 * 60 * 1000);
  }, next - now);
}
programarLimpieza();

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

  // Historial al entrar
  socket.emit("history", messages.slice(-MAX_HISTORY));
  socket.broadcast.emit("system", `${user} se conectó`);

  socket.on("message", (text) => {
    text = String(text || "").trim().slice(0, 1000);
    if (!text) return;
    const msg = { user, text, ts: Date.now() };
    messages.push(msg);
    if (messages.length > MAX_HISTORY) messages = messages.slice(-MAX_HISTORY);
    saveJson(MESSAGES_FILE, messages);
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
      if (messages.length > MAX_HISTORY) messages = messages.slice(-MAX_HISTORY);
      saveJson(MESSAGES_FILE, messages);
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
