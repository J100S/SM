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
const rateLimit = require('express-rate-limit');

const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'replace_this_with_a_secure_random_string';
const DB_FILE = process.env.DB_FILE || path.join(__dirname, 'data', 'db.sqlite');
const UPLOAD_DIR = path.join(__dirname, 'uploads');

// Ensure folders exist
for (const dir of [path.join(__dirname, 'data'), UPLOAD_DIR]) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir);
}

const app = express();
const server = http.createServer(app);

app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(UPLOAD_DIR));
app.use(express.static(path.join(__dirname)));

// Rate limit for auth routes
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  message: { error: 'Too many requests. Try again later.' }
});

const db = new sqlite3.Database(DB_FILE, (err) => {
  if (err) console.error('DB open error:', err.message);
  else console.log('Connected to SQLite database.');
});

// DB helpers
const runAsync = (sql, params = []) => new Promise((res, rej) => db.run(sql, params, function (err) { err ? rej(err) : res(this); }));
const getAsync = (sql, params = []) => new Promise((res, rej) => db.get(sql, params, (err, row) => err ? rej(err) : res(row)));
const allAsync = (sql, params = []) => new Promise((res, rej) => db.all(sql, params, (err, rows) => err ? rej(err) : res(rows)));

// JWT middleware
function authenticateToken(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'Missing Authorization' });
  const [scheme, token] = auth.split(' ');
  if (scheme !== 'Bearer') return res.status(401).json({ error: 'Invalid Authorization' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// Multer setup with file filter
const storage = multer({ dest: UPLOAD_DIR, limits: { fileSize: 2 * 1024 * 1024 } });
const upload = storage.single('image');
const avatarUpload = multer({
  dest: UPLOAD_DIR,
  fileFilter: (req, file, cb) => {
    if (!file.mimetype.startsWith('image/')) cb(new Error('Only image uploads allowed'));
    else cb(null, true);
  }
}).single('avatar');

// Auth routes
app.post('/api/register', authLimiter, avatarUpload, async (req, res) => {
  try {
    const { name, handle, email, password } = req.body;
    if (!name || !handle || !email || !password) return res.status(400).json({ error: 'All fields required' });

    if (await getAsync('SELECT 1 FROM users WHERE email = ?', [email])) return res.status(400).json({ error: 'Email already in use' });
    if (await getAsync('SELECT 1 FROM users WHERE handle = ?', [handle])) return res.status(400).json({ error: 'Handle already in use' });

    const id = uuidv4();
    const password_hash = await bcrypt.hash(password, 12);
    const avatar_url = req.file ? `/uploads/${req.file.filename}` : null;

    await runAsync(
      'INSERT INTO users (id, name, handle, email, password_hash, avatar_url) VALUES (?, ?, ?, ?, ?, ?)',
      [id, name, handle, email, password_hash, avatar_url]
    );

    const user = await getAsync('SELECT id, name, handle, email, avatar_url, created_at FROM users WHERE id = ?', [id]);
    const token = jwt.sign({ id, email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const user = await getAsync('SELECT * FROM users WHERE email = ?', [email]);
    if (!user || !(await bcrypt.compare(password, user.password_hash))) return res.status(400).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({
      token,
      user: { id: user.id, name: user.name, handle: user.handle, email: user.email, avatar_url: user.avatar_url, created_at: user.created_at }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Posts with pagination
app.get('/api/posts', async (req, res) => {
  try {
    const limit = parseInt(req.query.limit || 20);
    const offset = parseInt(req.query.offset || 0);
    const posts = await allAsync(
      `SELECT p.*, u.name as user_name, u.handle as user_handle, u.avatar_url as user_avatar
       FROM posts p JOIN users u ON p.user_id = u.id
       ORDER BY p.created_at DESC LIMIT ? OFFSET ?`,
      [limit, offset]
    );
    res.json(posts);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Trending posts
app.get('/api/posts/trending', async (req, res) => {
  try {
    const posts = await allAsync(
      `SELECT p.*, u.name as user_name, u.handle as user_handle, u.avatar_url as user_avatar
       FROM posts p JOIN users u ON p.user_id = u.id
       WHERE p.created_at >= datetime('now', '-1 day')
       ORDER BY p.likes DESC LIMIT 5`
    );
    res.json(posts);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Comments
app.get('/api/posts/:id/comments', async (req, res) => {
  res.json(await allAsync(`SELECT c.*, u.name, u.handle, u.avatar_url
    FROM comments c JOIN users u ON c.user_id = u.id
    WHERE c.post_id = ? ORDER BY c.created_at ASC`, [req.params.id]));
});

app.post('/api/posts/:id/comments', authenticateToken, async (req, res) => {
  const id = uuidv4();
  await runAsync('INSERT INTO comments (id, post_id, user_id, text) VALUES (?, ?, ?, ?)', [id, req.params.id, req.user.id, req.body.text]);
  res.status(201).json(await getAsync(`SELECT * FROM comments WHERE id = ?`, [id]));
});

// Likes
app.post('/api/posts/:id/like', authenticateToken, async (req, res) => {
  await runAsync('UPDATE posts SET likes = likes + 1 WHERE id = ?', [req.params.id]);
  res.json(await getAsync('SELECT id, likes FROM posts WHERE id = ?', [req.params.id]));
});

// Follow
app.post('/api/users/:id/follow', authenticateToken, async (req, res) => {
  await runAsync('INSERT OR IGNORE INTO follows (follower_id, followed_id) VALUES (?, ?)', [req.user.id, req.params.id]);
  res.json({ success: true });
});

app.delete('/api/users/:id/follow', authenticateToken, async (req, res) => {
  await runAsync('DELETE FROM follows WHERE follower_id = ? AND followed_id = ?', [req.user.id, req.params.id]);
  res.json({ success: true });
});

app.get('/api/users/suggested', authenticateToken, async (req, res) => {
  res.json(await allAsync(
    `SELECT id, name, handle, avatar_url FROM users
     WHERE id != ? AND id NOT IN (SELECT followed_id FROM follows WHERE follower_id = ?)
     LIMIT 5`,
    [req.user.id, req.user.id]
  ));
});

// Profile
app.get('/api/users/:handle', async (req, res) => {
  const user = await getAsync('SELECT id, name, handle, avatar_url, created_at FROM users WHERE handle = ?', [req.params.handle]);
  if (!user) return res.status(404).json({ error: 'User not found' });
  const posts = await allAsync(
    `SELECT p.*, u.name as user_name, u.handle as user_handle, u.avatar_url as user_avatar
     FROM posts p JOIN users u ON p.user_id = u.id
     WHERE u.id = ? ORDER BY p.created_at DESC`,
    [user.id]
  );
  res.json({ user, posts });
});

// Serve index.html
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

// Init tables
(async () => {
  await runAsync(`CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY, name TEXT, handle TEXT UNIQUE, email TEXT UNIQUE,
    password_hash TEXT, avatar_url TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP
  )`);
  await runAsync(`CREATE TABLE IF NOT EXISTS posts (
    id TEXT PRIMARY KEY, user_id TEXT, text TEXT, image_url TEXT,
    likes INTEGER DEFAULT 0, created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);
  await runAsync(`CREATE TABLE IF NOT EXISTS comments (
    id TEXT PRIMARY KEY, post_id TEXT, user_id TEXT, text TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(post_id) REFERENCES posts(id),
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);
  await runAsync(`CREATE TABLE IF NOT EXISTS follows (
    follower_id TEXT, followed_id TEXT,
    PRIMARY KEY (follower_id, followed_id),
    FOREIGN KEY(follower_id) REFERENCES users(id),
    FOREIGN KEY(followed_id) REFERENCES users(id)
  )`);
  console.log('✅ Tables ensured.');
})();

server.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
