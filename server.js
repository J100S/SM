require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const http = require('http');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'replace_this_with_a_secure_random_string';
const DB_FILE = process.env.DB_FILE || path.join(__dirname, 'data', 'db.sqlite');
const UPLOAD_DIR = path.join(__dirname, 'uploads');

// ensure folders
if (!fs.existsSync(path.join(__dirname, 'data'))) fs.mkdirSync(path.join(__dirname, 'data'));
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR);

const app = express();
const server = http.createServer(app);

app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(UPLOAD_DIR));
app.use(express.static(path.join(__dirname))); // serve index.html and other static files

const db = new sqlite3.Database(DB_FILE, (err) => {
  if (err) console.error('DB open error:', err.message);
  else console.log('Connected to SQLite database.');
});

// helper to run sql with promise
function runAsync(sql, params=[]) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function(err){
      if (err) reject(err);
      else resolve(this);
    });
  });
}
function getAsync(sql, params=[]){
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err,row)=> err?reject(err):resolve(row));
  });
}
function allAsync(sql, params=[]){
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err,rows)=> err?reject(err):resolve(rows));
  });
}

// JWT middleware
function authenticateToken(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'Missing Authorization' });
  const parts = auth.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') return res.status(401).json({ error: 'Invalid Authorization' });
  const token = parts[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// Routes

// register (multipart or json)
app.post('/api/register', multer().single('avatar'), async (req, res) => {
  try {
    // support both JSON and multipart/form-data
    const body = req.body || {};
    const name = body.name;
    const handle = body.handle;
    const email = body.email;
    const password = body.password;
    if (!name || !handle || !email || !password) return res.status(400).json({ error: 'name, handle, email and password required' });

    // check unique
    const existingEmail = await getAsync('SELECT id FROM users WHERE email = ?', [email]);
    if (existingEmail) return res.status(400).json({ error: 'email already in use' });
    const existingHandle = await getAsync('SELECT id FROM users WHERE handle = ?', [handle]);
    if (existingHandle) return res.status(400).json({ error: 'handle already in use' });

    const password_hash = await bcrypt.hash(password, 10);
    const id = uuidv4();
    const avatar_url = null; // uploading avatar via multipart not implemented here
    await runAsync('INSERT INTO users (id, name, handle, email, password_hash, avatar_url) VALUES (?, ?, ?, ?, ?, ?)', [id, name, handle, email, password_hash, avatar_url]);
    const user = await getAsync('SELECT id, name, handle, email, avatar_url, created_at FROM users WHERE id = ?', [id]);
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'email and password required' });
    const user = await getAsync('SELECT * FROM users WHERE email = ?', [email]);
    if (!user) return res.status(400).json({ error: 'invalid credentials' });
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(400).json({ error: 'invalid credentials' });
    const publicUser = { id: user.id, name: user.name, handle: user.handle, email: user.email, avatar_url: user.avatar_url, created_at: user.created_at };
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: publicUser });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// get posts
app.get('/api/posts', async (req, res) => {
  try {
    const rows = await allAsync(`SELECT p.id, p.user_id, p.text, p.image_url, p.likes, p.created_at, u.name as user_name, u.handle as user_handle, u.avatar_url as user_avatar
      FROM posts p JOIN users u ON p.user_id = u.id ORDER BY p.created_at DESC`);
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// create post (authenticated)
const upload = multer({ dest: UPLOAD_DIR });
app.post('/api/posts', authenticateToken, upload.single('image'), async (req, res) => {
  try {
    const text = (req.body && req.body.text) || '';
    const image_url = req.file ? `/uploads/${req.file.filename}` : null;
    const id = uuidv4();
    await runAsync('INSERT INTO posts (id, user_id, text, image_url, likes) VALUES (?, ?, ?, ?, ?)', [id, req.user.id, text, image_url, 0]);
    const post = await getAsync('SELECT p.id, p.user_id, p.text, p.image_url, p.likes, p.created_at, u.name as user_name, u.handle as user_handle, u.avatar_url as user_avatar FROM posts p JOIN users u ON p.user_id = u.id WHERE p.id = ?', [id]);
    res.status(201).json(post);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// like
app.post('/api/posts/:id/like', authenticateToken, async (req, res) => {
  try {
    const postId = req.params.id;
    await runAsync('UPDATE posts SET likes = COALESCE(likes,0) + 1 WHERE id = ?', [postId]);
    const post = await getAsync('SELECT id, likes FROM posts WHERE id = ?', [postId]);
    res.json(post);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// serve index file
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// auto-create tables if missing
(async function ensureTables(){
  try {
    await runAsync(`CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY, name TEXT NOT NULL, handle TEXT UNIQUE NOT NULL, email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL, avatar_url TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )`);
    await runAsync(`CREATE TABLE IF NOT EXISTS posts (
      id TEXT PRIMARY KEY, user_id TEXT NOT NULL, text TEXT, image_url TEXT, likes INTEGER DEFAULT 0, created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(user_id) REFERENCES users(id)
    )`);
    console.log('✅ Tables ensured.');
  } catch(err){
    console.error('Error ensuring tables:', err);
  }
})();

server.listen(PORT, ()=> console.log(`Server running at http://localhost:${PORT}`));
