require("dotenv").config();
const express = require("express");
const http = require("http");
const helmet = require("helmet");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const { Server } = require("socket.io");
const path = require("path");

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: true, credentials: true } });
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error("Set JWT_SECRET to a random secret of at least 32 characters.");
  process.exit(1);
}
if (!process.env.DATABASE_URL) {
  console.error("DATABASE_URL is required. Create a PostgreSQL database and set DATABASE_URL.");
  process.exit(1);
}
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_SSL === "true" ? { rejectUnauthorized: false } : undefined,
  max: 10,
  idleTimeoutMillis: 30000
});

app.disable("x-powered-by");
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "1mb" }));
app.use(express.static(path.join(__dirname, "public"), { maxAge: "1h" }));

const schema = `
CREATE TABLE IF NOT EXISTS users (
 id BIGSERIAL PRIMARY KEY,
 username VARCHAR(24) UNIQUE NOT NULL,
 display_name VARCHAR(50) NOT NULL,
 password_hash TEXT NOT NULL,
 avatar_color VARCHAR(20) NOT NULL DEFAULT '#7c5cff',
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS chats (
 id BIGSERIAL PRIMARY KEY,
 title VARCHAR(80),
 is_group BOOLEAN NOT NULL DEFAULT FALSE,
 created_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS chat_members (
 chat_id BIGINT REFERENCES chats(id) ON DELETE CASCADE,
 user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
 joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
 PRIMARY KEY(chat_id, user_id)
);
CREATE TABLE IF NOT EXISTS messages (
 id BIGSERIAL PRIMARY KEY,
 chat_id BIGINT NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
 sender_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
 body VARCHAR(4000) NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS messages_chat_time_idx ON messages(chat_id, created_at DESC);
CREATE INDEX IF NOT EXISTS chat_members_user_idx ON chat_members(user_id, chat_id);
`;

async function initDb() {
  await pool.query(schema);
}
function tokenFor(user) {
  return jwt.sign({ id: String(user.id), username: user.username }, JWT_SECRET, { expiresIn: "14d" });
}
function safeUser(u) {
  return { id: String(u.id), username: u.username, displayName: u.display_name, avatarColor: u.avatar_color };
}
async function auth(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : "";
    const payload = jwt.verify(token, JWT_SECRET);
    const result = await pool.query("SELECT id, username, display_name, avatar_color FROM users WHERE id=$1", [payload.id]);
    if (!result.rowCount) return res.status(401).json({ error: "Account not found." });
    req.user = safeUser(result.rows[0]);
    next();
  } catch {
    return res.status(401).json({ error: "Please sign in again." });
  }
}
const wrap = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

app.get("/api/health", (req, res) => res.json({ ok: true, service: "MessageU" }));

app.post("/api/auth/register", wrap(async (req, res) => {
  let { username, displayName, password } = req.body || {};
  username = String(username || "").trim().toLowerCase();
  displayName = String(displayName || "").trim();
  password = String(password || "");
  if (!/^[a-z0-9_]{3,24}$/.test(username)) return res.status(400).json({ error: "Username must be 3–24 characters: letters, numbers, underscore." });
  if (displayName.length < 1 || displayName.length > 50) return res.status(400).json({ error: "Display name must be 1–50 characters." });
  if (password.length < 8 || password.length > 128) return res.status(400).json({ error: "Password must be 8–128 characters." });
  const hash = await bcrypt.hash(password, 12);
  const colors = ["#7c5cff", "#00bfa6", "#ff6b9a", "#3b82f6", "#f59e0b"];
  try {
    const r = await pool.query("INSERT INTO users(username,display_name,password_hash,avatar_color) VALUES($1,$2,$3,$4) RETURNING id,username,display_name,avatar_color", [username, displayName, hash, colors[Math.floor(Math.random()*colors.length)]]);
    const user = safeUser(r.rows[0]);
    res.status(201).json({ token: tokenFor(r.rows[0]), user });
  } catch (e) {
    if (e.code === "23505") return res.status(409).json({ error: "That username is already taken." });
    throw e;
  }
}));

app.post("/api/auth/login", wrap(async (req, res) => {
  const username = String(req.body?.username || "").trim().toLowerCase();
  const password = String(req.body?.password || "");
  const r = await pool.query("SELECT * FROM users WHERE username=$1", [username]);
  if (!r.rowCount || !(await bcrypt.compare(password, r.rows[0].password_hash))) return res.status(401).json({ error: "Username or password is incorrect." });
  res.json({ token: tokenFor(r.rows[0]), user: safeUser(r.rows[0]) });
}));

app.get("/api/me", auth, (req, res) => res.json({ user: req.user }));

app.get("/api/users/search", auth, wrap(async (req, res) => {
  const q = String(req.query.q || "").trim().toLowerCase();
  if (q.length < 2) return res.json({ users: [] });
  const r = await pool.query(
    "SELECT id,username,display_name,avatar_color FROM users WHERE id<>$1 AND (username LIKE $2 OR LOWER(display_name) LIKE $2) ORDER BY username LIMIT 15",
    [req.user.id, `%${q.replace(/[%_\\]/g, "\\$&")}%`]
  );
  res.json({ users: r.rows.map(safeUser) });
}));

app.get("/api/chats", auth, wrap(async (req, res) => {
  const r = await pool.query(`
    SELECT c.id,c.title,c.is_group,c.created_at,c.created_by,
      (SELECT json_build_object('id',u.id,'username',u.username,'displayName',u.display_name,'avatarColor',u.avatar_color)
       FROM chat_members cm2 JOIN users u ON u.id=cm2.user_id
       WHERE cm2.chat_id=c.id AND u.id<>$1 ORDER BY u.username LIMIT 1) AS other_user,
      (SELECT json_build_object('id',m.id,'body',m.body,'createdAt',m.created_at,'senderId',m.sender_id,'senderName',u.display_name)
       FROM messages m LEFT JOIN users u ON u.id=m.sender_id WHERE m.chat_id=c.id ORDER BY m.created_at DESC,m.id DESC LIMIT 1) AS last_message,
      (SELECT COUNT(*) FROM chat_members cm3 WHERE cm3.chat_id=c.id) AS member_count
    FROM chats c JOIN chat_members mine ON mine.chat_id=c.id
    WHERE mine.user_id=$1
    ORDER BY COALESCE((SELECT MAX(created_at) FROM messages WHERE chat_id=c.id),c.created_at) DESC
  `, [req.user.id]);
  res.json({ chats: r.rows.map(c => ({
    id: String(c.id), title: c.title, isGroup: c.is_group, createdAt: c.created_at, isCreator: String(c.created_by) === req.user.id,
    otherUser: c.other_user ? {...c.other_user, id:String(c.other_user.id)} : null,
    lastMessage: c.last_message ? {...c.last_message, id:String(c.last_message.id), senderId:c.last_message.senderId ? String(c.last_message.senderId) : null} : null,
    memberCount: Number(c.member_count)
  })) });
}));

app.post("/api/chats/direct", auth, wrap(async (req, res) => {
  const username = String(req.body?.username || "").trim().toLowerCase();
  const target = await pool.query("SELECT id FROM users WHERE username=$1", [username]);
  if (!target.rowCount) return res.status(404).json({ error: "No user found with that username." });
  const targetId = String(target.rows[0].id);
  if (targetId === req.user.id) return res.status(400).json({ error: "You cannot start a chat with yourself." });
  const existing = await pool.query(`
    SELECT c.id FROM chats c
    JOIN chat_members a ON a.chat_id=c.id AND a.user_id=$1
    JOIN chat_members b ON b.chat_id=c.id AND b.user_id=$2
    WHERE c.is_group=FALSE
    AND (SELECT COUNT(*) FROM chat_members cm WHERE cm.chat_id=c.id)=2 LIMIT 1
  `, [req.user.id, targetId]);
  if (existing.rowCount) return res.json({ id: String(existing.rows[0].id) });
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const c = await client.query("INSERT INTO chats(is_group,created_by) VALUES(FALSE,$1) RETURNING id", [req.user.id]);
    await client.query("INSERT INTO chat_members(chat_id,user_id) VALUES($1,$2),($1,$3)", [c.rows[0].id, req.user.id, targetId]);
    await client.query("COMMIT");
    res.status(201).json({ id: String(c.rows[0].id) });
  } catch (e) { await client.query("ROLLBACK"); throw e; } finally { client.release(); }
}));

app.post("/api/chats/group", auth, wrap(async (req, res) => {
  const title = String(req.body?.title || "").trim();
  const usernames = [...new Set((Array.isArray(req.body?.usernames) ? req.body.usernames : []).map(x=>String(x).trim().toLowerCase()).filter(Boolean))];
  if (title.length < 2 || title.length > 80) return res.status(400).json({ error: "Group name must be 2–80 characters." });
  if (usernames.length < 1 || usernames.length > 30) return res.status(400).json({ error: "Add between 1 and 30 other members by username." });
  const found = await pool.query("SELECT id,username FROM users WHERE username=ANY($1::text[])", [usernames]);
  const missing = usernames.filter(n=>!found.rows.some(u=>u.username===n));
  if (missing.length) return res.status(400).json({ error: `Usernames not found: ${missing.join(", ")}` });
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const c = await client.query("INSERT INTO chats(title,is_group,created_by) VALUES($1,TRUE,$2) RETURNING id", [title, req.user.id]);
    const ids = [...new Set([req.user.id, ...found.rows.map(u=>String(u.id))])];
    for (const id of ids) await client.query("INSERT INTO chat_members(chat_id,user_id) VALUES($1,$2)", [c.rows[0].id, id]);
    await client.query("COMMIT");
    res.status(201).json({ id: String(c.rows[0].id) });
  } catch (e) { await client.query("ROLLBACK"); throw e; } finally { client.release(); }
}));

app.post("/api/chats/:id/members", auth, wrap(async (req, res) => {
  const usernames = [...new Set((Array.isArray(req.body?.usernames) ? req.body.usernames : []).map(x => String(x).trim().toLowerCase()).filter(Boolean))];
  if (usernames.length < 1 || usernames.length > 30) return res.status(400).json({ error: "Add between 1 and 30 usernames." });
  const chat = await pool.query("SELECT is_group,created_by FROM chats WHERE id=$1", [req.params.id]);
  if (!chat.rowCount) return res.status(404).json({ error: "Group not found." });
  if (!chat.rows[0].is_group) return res.status(400).json({ error: "Members can only be added to groups." });
  if (String(chat.rows[0].created_by) !== req.user.id) return res.status(403).json({ error: "Only the group creator can add members." });
  const found = await pool.query("SELECT id,username FROM users WHERE username=ANY($1::text[])", [usernames]);
  const missing = usernames.filter(name => !found.rows.some(user => user.username === name));
  if (missing.length) return res.status(400).json({ error: "Usernames not found: " + missing.join(", ") });
  let added = 0;
  for (const user of found.rows) {
    const result = await pool.query("INSERT INTO chat_members(chat_id,user_id) VALUES($1,$2) ON CONFLICT(chat_id,user_id) DO NOTHING", [req.params.id, user.id]);
    added += result.rowCount;
  }
  res.json({ added });
}));
app.get("/api/chats/:id/messages", auth, wrap(async (req, res) => {
  const membership = await pool.query("SELECT 1 FROM chat_members WHERE chat_id=$1 AND user_id=$2", [req.params.id, req.user.id]);
  if (!membership.rowCount) return res.status(404).json({ error: "Conversation not found." });
  const r = await pool.query(`
    SELECT m.id,m.chat_id,m.sender_id,m.body,m.created_at,u.username,u.display_name,u.avatar_color
    FROM (SELECT * FROM messages WHERE chat_id=$1 ORDER BY created_at DESC,id DESC LIMIT 100) m
    LEFT JOIN users u ON u.id=m.sender_id ORDER BY m.created_at ASC,m.id ASC
  `, [req.params.id]);
  res.json({ messages: r.rows.map(m=>({id:String(m.id),chatId:String(m.chat_id),senderId:m.sender_id?String(m.sender_id):null,body:m.body,createdAt:m.created_at,sender:m.username?{id:String(m.sender_id),username:m.username,displayName:m.display_name,avatarColor:m.avatar_color}:null})) });
}));

app.use((err, req, res, next) => {
  console.error(err);
  if (res.headersSent) return next(err);
  res.status(500).json({ error: "Something went wrong. Please try again." });
});

const socketAuth = async (socket, next) => {
  try {
    const token = socket.handshake.auth?.token;
    const payload = jwt.verify(token, JWT_SECRET);
    const r = await pool.query("SELECT id,username,display_name,avatar_color FROM users WHERE id=$1", [payload.id]);
    if (!r.rowCount) return next(new Error("Unauthorized"));
    socket.user = safeUser(r.rows[0]);
    next();
  } catch { next(new Error("Unauthorized")); }
};
io.use(socketAuth);
io.on("connection", socket => {
  socket.on("chat:join", async ({ chatId } = {}) => {
    if (!/^\d+$/.test(String(chatId || ""))) return;
    const m = await pool.query("SELECT 1 FROM chat_members WHERE chat_id=$1 AND user_id=$2", [chatId, socket.user.id]);
    if (m.rowCount) socket.join(`chat:${chatId}`);
  });
  socket.on("message:send", async ({ chatId, body } = {}, ack = () => {}) => {
    try {
      body = String(body || "").trim();
      if (!/^\d+$/.test(String(chatId || "")) || !body || body.length > 4000) return ack({ error: "Messages must contain 1–4000 characters." });
      const member = await pool.query("SELECT 1 FROM chat_members WHERE chat_id=$1 AND user_id=$2", [chatId, socket.user.id]);
      if (!member.rowCount) return ack({ error: "You are not a member of this conversation." });
      const r = await pool.query("INSERT INTO messages(chat_id,sender_id,body) VALUES($1,$2,$3) RETURNING id,chat_id,sender_id,body,created_at", [chatId, socket.user.id, body]);
      const m = r.rows[0];
      const message = { id:String(m.id), chatId:String(m.chat_id), senderId:String(m.sender_id), body:m.body, createdAt:m.created_at, sender:socket.user };
      io.to(`chat:${chatId}`).emit("message:new", message);
      ack({ ok: true, message });
    } catch (e) { console.error(e); ack({ error: "Message could not be sent." }); }
  });
});

app.get("*", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
initDb().then(() => server.listen(PORT, () => console.log(`MessageU listening on ${PORT}`))).catch(e => { console.error("Database initialization failed:", e); process.exit(1); });
