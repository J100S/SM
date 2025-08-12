require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const http = require('http');
const sqlite3 = require('sqlite3').verbose();

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

const server = http.createServer(app);

// === DATABASE SETUP ===
const db = new sqlite3.Database('./database.db');

// Create tables if not exists
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        profilePic TEXT
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS posts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        userId INTEGER,
        content TEXT,
        image TEXT,
        createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // NEW: Follows table
    db.run(`CREATE TABLE IF NOT EXISTS follows (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        followerId INTEGER,
        followingId INTEGER,
        UNIQUE(followerId, followingId)
    )`);
});

// === MULTER FILE UPLOADS ===
const upload = multer({ dest: 'uploads/' });

// === USER ROUTES ===
// Create new user
app.post('/users', (req, res) => {
    const { username, profilePic } = req.body;
    db.run(
        `INSERT INTO users (username, profilePic) VALUES (?, ?)`,
        [username, profilePic || null],
        function (err) {
            if (err) return res.status(400).json({ error: err.message });
            res.json({ id: this.lastID, username, profilePic });
        }
    );
});

// Get all users
app.get('/users', (req, res) => {
    db.all(`SELECT * FROM users`, (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// === FOLLOW SYSTEM ROUTES ===
// Follow a user
app.post('/follow/:userId', (req, res) => {
    const followerId = req.body.followerId; // who is following
    const followingId = parseInt(req.params.userId); // who is being followed

    if (followerId === followingId) {
        return res.status(400).json({ error: "You can't follow yourself" });
    }

    db.run(
        `INSERT OR IGNORE INTO follows (followerId, followingId) VALUES (?, ?)`,
        [followerId, followingId],
        function (err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true });
        }
    );
});

// Unfollow a user
app.post('/unfollow/:userId', (req, res) => {
    const followerId = req.body.followerId;
    const followingId = parseInt(req.params.userId);

    db.run(
        `DELETE FROM follows WHERE followerId = ? AND followingId = ?`,
        [followerId, followingId],
        function (err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true });
        }
    );
});

// Get followers of a user
app.get('/followers/:userId', (req, res) => {
    const userId = parseInt(req.params.userId);

    db.all(
        `SELECT u.* FROM follows f
         JOIN users u ON f.followerId = u.id
         WHERE f.followingId = ?`,
        [userId],
        (err, rows) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json(rows);
        }
    );
});

// Get who a user follows
app.get('/following/:userId', (req, res) => {
    const userId = parseInt(req.params.userId);

    db.all(
        `SELECT u.* FROM follows f
         JOIN users u ON f.followingId = u.id
         WHERE f.followerId = ?`,
        [userId],
        (err, rows) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json(rows);
        }
    );
});

// === POST ROUTES ===
app.post('/posts', upload.single('image'), (req, res) => {
    const { userId, content } = req.body;
    const image = req.file ? `/uploads/${req.file.filename}` : null;

    db.run(
        `INSERT INTO posts (userId, content, image) VALUES (?, ?, ?)`,
        [userId, content, image],
        function (err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ id: this.lastID, userId, content, image });
        }
    );
});

app.get('/posts', (req, res) => {
    db.all(
        `SELECT p.*, u.username, u.profilePic
         FROM posts p
         JOIN users u ON p.userId = u.id
         ORDER BY p.createdAt DESC`,
        (err, rows) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json(rows);
        }
    );
});

// === START SERVER ===
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
