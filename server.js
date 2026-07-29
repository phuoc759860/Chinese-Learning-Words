const express = require('express');
const initSqlJs = require('sql.js');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const fs = require('fs');
const path = require('path');

const DB_PATH = path.join(__dirname, 'data.db');
const JWT_SECRET = process.env.JWT_SECRET || 'vocab-quiz-secret-change-in-production';

async function start() {
  const SQL = await initSqlJs();
  let db;
  if (fs.existsSync(DB_PATH)) {
    const buf = fs.readFileSync(DB_PATH);
    db = new SQL.Database(buf);
  } else {
    db = new SQL.Database();
  }

  db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL, created_at TEXT DEFAULT (datetime('now')))");
  db.run("CREATE TABLE IF NOT EXISTS words (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, lang TEXT NOT NULL, ch TEXT NOT NULL, py TEXT DEFAULT '', vi TEXT NOT NULL, level TEXT DEFAULT 'Từ của tôi', created_at TEXT DEFAULT (datetime('now')), UNIQUE(user_id, lang, ch))");

  function save() {
    fs.writeFileSync(DB_PATH, Buffer.from(db.export()));
  }

  function all(sql, params) {
    const stmt = db.prepare(sql);
    if (params) stmt.bind(params);
    const rows = [];
    while (stmt.step()) rows.push(stmt.getAsObject());
    stmt.free();
    return rows;
  }

  function exec(sql, params, returnId) {
    const stmt = db.prepare(sql);
    if (params) stmt.bind(params);
    stmt.run();
    stmt.free();
    const id = db.exec("SELECT last_insert_rowid() as id")[0].values[0][0];
    save();
    if (returnId) return id;
  }

  const app = express();
  app.use(cors());
  app.use(express.json({ limit: '5mb' }));
  app.use(express.static(path.join(__dirname)));

  function auth(req, res, next) {
    const header = req.headers.authorization;
    if (!header) return res.status(401).json({ error: 'Missing token' });
    try {
      const payload = jwt.verify(header.replace('Bearer ', ''), JWT_SECRET);
      req.userId = payload.id;
      next();
    } catch { res.status(401).json({ error: 'Invalid token' }); }
  }

  app.post('/api/register', async (req, res) => {
    try {
      const { username, password } = req.body;
      if (!username || !password || username.length < 2 || password.length < 4)
        return res.status(400).json({ error: 'Username (2+) and password (4+) required' });
      const existing = all('SELECT id FROM users WHERE username = ?', [username]);
      if (existing.length) return res.status(409).json({ error: 'Username already exists' });
      const hash = await bcrypt.hash(password, 10);
      const userId = exec('INSERT INTO users (username, password) VALUES (?, ?)', [username, hash], true);
      const token = jwt.sign({ id: userId }, JWT_SECRET, { expiresIn: '30d' });
      res.json({ token, username });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  app.post('/api/login', async (req, res) => {
    try {
      const { username, password } = req.body;
      const users = all('SELECT * FROM users WHERE username = ?', [username]);
      if (!users.length) return res.status(401).json({ error: 'Invalid credentials' });
      const ok = await bcrypt.compare(password, users[0].password);
      if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
      const token = jwt.sign({ id: users[0].id }, JWT_SECRET, { expiresIn: '30d' });
      res.json({ token, username: users[0].username });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  app.get('/api/words/:lang', auth, (req, res) => {
    try {
      const rows = all('SELECT id, ch, py, vi FROM words WHERE user_id = ? AND lang = ? ORDER BY id', [req.userId, req.params.lang]);
      res.json(rows);
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  app.post('/api/words/:lang', auth, (req, res) => {
    try {
      const { ch, py, vi } = req.body;
      if (!ch || !vi) return res.status(400).json({ error: 'ch and vi required' });
      const existing = all('SELECT id FROM words WHERE user_id = ? AND lang = ? AND ch = ?', [req.userId, req.params.lang, ch]);
      if (existing.length) return res.status(409).json({ error: 'Word already exists' });
      const wordId = exec('INSERT INTO words (user_id, lang, ch, py, vi) VALUES (?, ?, ?, ?, ?)', [req.userId, req.params.lang, ch, py || '', vi], true);
      res.json({ id: wordId, ch, py: py || '', vi });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  app.delete('/api/words/:lang/:ch', auth, (req, res) => {
    try {
      exec('DELETE FROM words WHERE user_id = ? AND lang = ? AND ch = ?', [req.userId, req.params.lang, req.params.ch]);
      res.json({ ok: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  app.post('/api/words/:lang/import', auth, (req, res) => {
    try {
      const { words } = req.body;
      if (!Array.isArray(words)) return res.status(400).json({ error: 'words array required' });
      let added = 0, skipped = 0;
      for (const w of words) {
        if (!w.ch || !w.vi) continue;
        const existing = all('SELECT id FROM words WHERE user_id = ? AND lang = ? AND ch = ?', [req.userId, req.params.lang, w.ch]);
        if (existing.length) { skipped++; continue; }
        exec('INSERT INTO words (user_id, lang, ch, py, vi) VALUES (?, ?, ?, ?, ?)', [req.userId, req.params.lang, w.ch, w.py || '', w.vi]);
        added++;
      }
      res.json({ added, skipped });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  app.post('/api/words/:lang/sync', auth, (req, res) => {
    try {
      const { words } = req.body;
      if (!Array.isArray(words)) return res.status(400).json({ error: 'words array required' });
      const existing = all('SELECT ch FROM words WHERE user_id = ? AND lang = ?', [req.userId, req.params.lang]);
      const existingSet = new Set(existing.map(r => r.ch));
      let added = 0, skipped = 0;
      for (const w of words) {
        if (!w.ch || !w.vi) continue;
        if (existingSet.has(w.ch)) { skipped++; continue; }
        exec('INSERT INTO words (user_id, lang, ch, py, vi) VALUES (?, ?, ?, ?, ?)', [req.userId, req.params.lang, w.ch, w.py || '', w.vi]);
        added++;
      }
      const rows = all('SELECT id, ch, py, vi FROM words WHERE user_id = ? AND lang = ? ORDER BY id', [req.userId, req.params.lang]);
      res.json({ added, skipped, words: rows });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  app.delete('/api/account', auth, (req, res) => {
    try {
      exec('DELETE FROM words WHERE user_id = ?', [req.userId]);
      exec('DELETE FROM users WHERE id = ?', [req.userId]);
      res.json({ ok: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  const PORT = process.env.PORT || 3000;
  app.listen(PORT, '0.0.0.0', () => {
    console.log('Server running on http://0.0.0.0:' + PORT);
  });
}

start().catch(err => { console.error(err); process.exit(1); });
