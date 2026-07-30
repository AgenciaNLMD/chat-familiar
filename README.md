# Chat (niños)

Canal de comunicación estilo chat, con usuario y contraseña. Para uso local.

## Stack

- **Express** + **express-session** — servidor y login con sesión por cookie
- **Socket.io** — mensajes en tiempo real
- **bcryptjs** — contraseñas hasheadas
- **Archivos JSON** (`data/`) — usuarios y mensajes (sin base de datos)

## Uso

```bash
npm install
npm start
```

Luego abrir **http://localhost:3004** en el navegador.

- La primera vez, crear una cuenta desde la pestaña **Crear cuenta**.
- Los datos se guardan en `data/users.json` y `data/messages.json` (ignorados por git).

## Notas

- Registro abierto y una sala común de chat.
- El historial guarda los últimos 200 mensajes.
- Para exponerlo fuera de tu red hace falta HTTPS y `SESSION_SECRET` fijo
  (variable de entorno). Por ahora está pensado para correr local.
