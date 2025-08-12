// server.js
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
const JWT_SECRET = process.env.JWT_SECRET || 'replace_with_secure_random_string';
const DB_FILE = process.env.DB_FILE || path.join(__dirname, 'data', 'db.sqlite');
const UPLOAD_DIR = path.join(__dirname, 'uploads');

if (!fs.existsSync(path.join(__dirname, 'data'))) fs.mkdirSync(path.join(__dirname, 'data'));
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR);

const app = express();
const server = http.createServer(app);

// Multer storage for uploads
const storage = multer.diskStorage({
  destination: UPLOAD_DIR,
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname.replace(/\s+/g, '_'))
});
const upload = multer({
  storage,
  fileFilter: (req, file, cb) => {
    if (!file.mimetype.startsWith('image/')) return cb(new Error('Only images allowed'));
    cb(null, true);
  }
});

app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(UPLOAD_DIR));
app.use(express.static(path.join(__dirname))); // serve index.html from root

const db = new sqlite3.Database(DB_FILE, (err) => {
  if (err) console.error('DB open error:', err.message);
  else console.log('Connected to SQLite database.');
});

function runAsync(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) reject(err);
      else resolve(this);
    });
  });
}
function getAsync(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => err ? reject(err) : resolve(row));
  });
}
function allAsync(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => err ? reject(err) : resolve(rows));
  });
}

function authenticateToken(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'Missing Authorization' });
  const parts = auth.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') return res.status(401).json({ error: 'Invalid Authorization' });
  try {
    req.user = jwt.verify(parts[1], JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// -------------------- Routes --------------------

// Register
app.post('/api/register', upload.single('avatar'), async (req, res) => {
  try {
    const { name, handle, email, password } = req.body || {};
    if (!name || !handle || !email || !password) return res.status(400).json({ error: 'Missing fields' });
    if (await getAsync('SELECT id FROM users WHERE email = ?', [email])) return res.status(400).json({ error: 'Email in use' });
    if (await getAsync('SELECT id FROM users WHERE handle = ?', [handle])) return res.status(400).json({ error: 'Handle in use' });

    const password_hash = await bcrypt.hash(password, 10);
    const id = uuidv4();
    const avatar_url = req.file ? `/uploads/${req.file.filename}` : null;
    await runAsync(
      'INSERT INTO users (id, name, handle, email, password_hash, avatar_url) VALUES (?, ?, ?, ?, ?, ?)',
      [id, name, handle, email, password_hash, avatar_url]
    );
    const user = await getAsync('SELECT id, name, handle, email, avatar_url, created_at FROM users WHERE id = ?', [id]);
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const user = await getAsync('SELECT * FROM users WHERE email = ?', [email]);
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }
    const publicUser = { id: user.id, name: user.name, handle: user.handle, email: user.email, avatar_url: user.avatar_url, created_at: user.created_at };
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: publicUser });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get posts with comment_count and likes count
app.get('/api/posts', async (req, res) => {
  try {
    const rows = await allAsync(`
      SELECT p.*, u.name AS user_name, u.handle AS user_handle, u.avatar_url AS user_avatar,
        (SELECT COUNT(*) FROM comments WHERE post_id = p.id) AS comment_count,
        (SELECT COUNT(*) FROM likes WHERE post_id = p.id) AS likes
      FROM posts p JOIN users u ON p.user_id = u.id
      ORDER BY p.created_at DESC
    `);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Create post
app.post('/api/posts', authenticateToken, upload.single('image'), async (req, res) => {
  try {
    const text = req.body.text || '';
    const image_url = req.file ? `/uploads/${req.file.filename}` : null;
    const id = uuidv4();
    await runAsync('INSERT INTO posts (id, user_id, text, image_url) VALUES (?, ?, ?, ?)', [id, req.user.id, text, image_url]);
    const post = await getAsync(`
      SELECT p.*, u.name AS user_name, u.handle AS user_handle, u.avatar_url AS user_avatar
      FROM posts p JOIN users u ON p.user_id = u.id WHERE p.id = ?
    `, [id]);
    res.status(201).json(post);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Delete post
app.delete('/api/posts/:id', authenticateToken, async (req, res) => {
  try {
    const post = await getAsync('SELECT * FROM posts WHERE id = ?', [req.params.id]);
    if (!post) return res.status(404).json({ error: 'Not found' });
    if (post.user_id !== req.user.id) return res.status(403).json({ error: 'Forbidden' });
    await runAsync('DELETE FROM posts WHERE id = ?', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Like toggle
app.post('/api/posts/:id/like', authenticateToken, async (req, res) => {
  try {
    const liked = await getAsync('SELECT 1 FROM likes WHERE user_id = ? AND post_id = ?', [req.user.id, req.params.id]);
    if (liked) {
      await runAsync('DELETE FROM likes WHERE user_id = ? AND post_id = ?', [req.user.id, req.params.id]);
    } else {
      await runAsync('INSERT INTO likes (user_id, post_id) VALUES (?, ?)', [req.user.id, req.params.id]);
    }
    const count = await getAsync('SELECT COUNT(*) AS likes FROM likes WHERE post_id = ?', [req.params.id]);
    res.json({ likes: count.likes });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Comments - get & post
app.get('/api/posts/:id/comments', async (req, res) => {
  try {
    const comments = await allAsync(`
      SELECT c.*, u.name AS user_name, u.handle AS user_handle, u.avatar_url AS user_avatar
      FROM comments c JOIN users u ON c.user_id = u.id
      WHERE post_id = ? ORDER BY c.created_at ASC
    `, [req.params.id]);
    res.json(comments);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
app.post('/api/posts/:id/comments', authenticateToken, async (req, res) => {
  try {
    const text = req.body.text?.trim();
    if (!text) return res.status(400).json({ error: 'Empty comment' });
    const id = uuidv4();
    await runAsync('INSERT INTO comments (id, post_id, user_id, text) VALUES (?, ?, ?, ?)', [id, req.params.id, req.user.id, text]);
    const comment = await getAsync(`
      SELECT c.*, u.name AS user_name, u.handle AS user_handle, u.avatar_url AS user_avatar
      FROM comments c JOIN users u ON c.user_id = u.id WHERE c.id = ?
    `, [id]);
    res.status(201).json(comment);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Suggested users (includes whether current user follows them)
app.get('/api/users/suggested', async (req, res) => {
  try {
    // attempt to read the token; if provided, get user id
    let currentUserId = null;
    const auth = req.headers.authorization;
    if (auth) {
      try {
        const token = auth.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        currentUserId = decoded.id;
      } catch (e) {
        currentUserId = null;
      }
    }

    const rows = await allAsync(`
      SELECT id, name, handle, avatar_url,
        CASE WHEN (? IS NOT NULL AND EXISTS(SELECT 1 FROM follows f WHERE f.follower_id = ? AND f.following_id = users.id)) THEN 1 ELSE 0 END AS is_following
      FROM users
      WHERE id != ?
      ORDER BY RANDOM() LIMIT 8
    `, [currentUserId, currentUserId, currentUserId]);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Follow a user
app.post('/api/users/:id/follow', authenticateToken, async (req, res) => {
  try {
    const targetId = req.params.id;
    if (targetId === req.user.id) return res.status(400).json({ error: "Can't follow yourself" });
    await runAsync('INSERT OR IGNORE INTO follows (follower_id, following_id) VALUES (?, ?)', [req.user.id, targetId]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Unfollow a user
app.post('/api/users/:id/unfollow', authenticateToken, async (req, res) => {
  try {
    const targetId = req.params.id;
    await runAsync('DELETE FROM follows WHERE follower_id = ? AND following_id = ?', [req.user.id, targetId]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get followers
app.get('/api/users/:id/followers', async (req, res) => {
  try {
    const rows = await allAsync(`
      SELECT u.id, u.name, u.handle, u.avatar_url
      FROM follows f JOIN users u ON f.follower_id = u.id
      WHERE f.following_id = ?
    `, [req.params.id]);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get following
app.get('/api/users/:id/following', async (req, res) => {
  try {
    const rows = await allAsync(`
      SELECT u.id, u.name, u.handle, u.avatar_url
      FROM follows f JOIN users u ON f.following_id = u.id
      WHERE f.follower_id = ?
    `, [req.params.id]);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

// -------------------- Tables --------------------
(async function ensureTables() {
  await runAsync(`CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, handle TEXT UNIQUE NOT NULL, email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL, avatar_url TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP
  )`);
  await runAsync(`CREATE TABLE IF NOT EXISTS posts (
    id TEXT PRIMARY KEY, user_id TEXT NOT NULL, text TEXT, image_url TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);
  await runAsync(`CREATE TABLE IF NOT EXISTS comments (
    id TEXT PRIMARY KEY, post_id TEXT NOT NULL, user_id TEXT NOT NULL, text TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(post_id) REFERENCES posts(id), FOREIGN KEY(user_id) REFERENCES users(id)
  )`);
  await runAsync(`CREATE TABLE IF NOT EXISTS likes (
    user_id TEXT NOT NULL, post_id TEXT NOT NULL,
    PRIMARY KEY(user_id, post_id),
    FOREIGN KEY(post_id) REFERENCES posts(id), FOREIGN KEY(user_id) REFERENCES users(id)
  )`);
  await runAsync(`CREATE TABLE IF NOT EXISTS follows (
    follower_id TEXT NOT NULL, following_id TEXT NOT NULL,
    PRIMARY KEY(follower_id, following_id),
    FOREIGN KEY(follower_id) REFERENCES users(id), FOREIGN KEY(following_id) REFERENCES users(id)
  )`);
  console.log('✅ Tables ensured.');
})();

server.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
