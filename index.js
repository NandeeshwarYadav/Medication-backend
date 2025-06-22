const express = require('express');
const Database = require('better-sqlite3');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const dayjs = require('dayjs');
const path = require('path');

const app = express();
const PORT = 3001;
const SECRET_KEY = 'your_secret_key';
const dbPath = path.join(__dirname, 'medication_app.db');
const db = new Database(dbPath);

app.use(cors());
app.use(bodyParser.json());

app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// Initialize tables
db.exec(`
  PRAGMA foreign_keys = ON;

  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    email TEXT UNIQUE,
    password TEXT,
    phone TEXT,
    role TEXT CHECK(role IN ('patient', 'caretaker'))
  );

  CREATE TABLE IF NOT EXISTS assignments (
    patient_id INTEGER UNIQUE,
    caretaker_id INTEGER UNIQUE,
    FOREIGN KEY(patient_id) REFERENCES users(id),
    FOREIGN KEY(caretaker_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS medications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id INTEGER,
    name TEXT,
    dosage TEXT,
    frequency TEXT,
    UNIQUE(patient_id, name),
    FOREIGN KEY(patient_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS medication_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id INTEGER,
    date TEXT,
    status TEXT,
    UNIQUE(patient_id, date),
    FOREIGN KEY(patient_id) REFERENCES users(id)
  );
`);

function authenticate(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Missing token' });

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
}

function fillMissedLogsForPast30Days(patientId) {
  const today = dayjs();
  for (let i = 1; i < 30; i++) {
    const date = today.subtract(i, 'day').format('YYYY-MM-DD');
    const row = db.prepare(`SELECT 1 FROM medication_logs WHERE patient_id = ? AND date = ?`).get(patientId, date);
    if (!row) {
      db.prepare(`INSERT INTO medication_logs (patient_id, date, status) VALUES (?, ?, 'missed')`).run(patientId, date);
    }
  }
}

// Signup
app.post('/signup', async (req, res) => {
  try {
    const { name, email, password, phone, role } = req.body;
    if (!name || !email || !password || !phone || !role) {
      return res.status(400).json({ error: 'Missing fields' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    if (role === 'patient') {
      const caretaker = db.prepare(`
        SELECT id FROM users WHERE role = 'caretaker' AND id NOT IN 
        (SELECT caretaker_id FROM assignments) LIMIT 1
      `).get();

      if (!caretaker) return res.status(400).json({ error: 'No available caretakers' });

      const insert = db.prepare(`
        INSERT INTO users (name, email, password, phone, role)
        VALUES (?, ?, ?, ?, ?)
      `);

      const info = insert.run(name, email, hashedPassword, phone, role);
      const userId = info.lastInsertRowid;

      db.prepare(`
        INSERT INTO assignments (patient_id, caretaker_id)
        VALUES (?, ?)
      `).run(userId, caretaker.id);

      return res.status(201).json({ message: 'Patient registered and assigned to caretaker' });

    } else {
      db.prepare(`
        INSERT INTO users (name, email, password, phone, role)
        VALUES (?, ?, ?, ?, ?)
      `).run(name, email, hashedPassword, phone, role);

      return res.status(201).json({ message: 'Caretaker registered' });
    }
  } catch (err) {
    console.error(err);
    return res.status(400).json({ error: 'User already exists or invalid data' });
  }
});

// Login
app.post('/login', async (req, res) => {
  try {
    const { email, password, role } = req.body;
    if (!email || !password || !role) return res.status(400).json({ error: 'Missing fields' });

    const user = db.prepare(`SELECT * FROM users WHERE email = ? AND role = ?`).get(email, role);
    if (!user) return res.status(401).json({ error: 'User not found' });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

    if (role === 'caretaker') {
      const assignment = db.prepare(`SELECT * FROM assignments WHERE caretaker_id = ?`).get(user.id);
      if (!assignment) return res.status(403).json({ error: 'No patient assigned to this caretaker' });
    }

    const token = jwt.sign({ userId: user.id, role: user.role }, SECRET_KEY, { expiresIn: '2h' });
    res.json({ token, userId: user.id, role: user.role });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Add medication
app.post('/medications', authenticate, (req, res) => {
  if (req.user.role !== 'patient') return res.status(403).json({ error: 'Only patients can add medications' });

  const { name, dosage, frequency } = req.body;
  if (!name || !dosage || !frequency) return res.status(400).json({ error: 'Missing fields' });

  const exists = db.prepare(`
    SELECT 1 FROM medications WHERE patient_id = ? AND LOWER(name) = LOWER(?)
  `).get(req.user.userId, name);

  if (exists) return res.status(400).json({ error: 'Medication already exists' });

  db.prepare(`
    INSERT INTO medications (patient_id, name, dosage, frequency)
    VALUES (?, ?, ?, ?)
  `).run(req.user.userId, name, dosage, frequency);

  res.status(201).json({ message: 'Medication added' });
});

// Mark medication
app.post('/medications/mark', authenticate, (req, res) => {
  if (req.user.role !== 'patient') return res.status(403).json({ error: 'Only patients can mark medication' });

  const today = dayjs().format('YYYY-MM-DD');
  db.prepare(`
    INSERT OR REPLACE INTO medication_logs (patient_id, date, status)
    VALUES (?, ?, 'taken')
  `).run(req.user.userId, today);

  res.json({ message: 'Medication marked as taken for today' });
});

// Patient Dashboard
app.get('/dashboard/patient', authenticate, (req, res) => {
  if (req.user.role !== 'patient') return res.status(403).json({ error: 'Access denied' });

  const patientId = req.user.userId;
  fillMissedLogsForPast30Days(patientId);

  const patient = db.prepare(`SELECT name FROM users WHERE id = ?`).get(patientId);
  const assignment = db.prepare(`
    SELECT users.name as caretakerName FROM users
    JOIN assignments ON users.id = assignments.caretaker_id
    WHERE assignments.patient_id = ?
  `).get(patientId);

  const logs = db.prepare(`
    SELECT date, status FROM medication_logs
    WHERE patient_id = ? AND date >= DATE('now', '-30 day')
    ORDER BY date
  `).all(patientId);

  const medications = db.prepare(`
    SELECT name, dosage, frequency FROM medications WHERE patient_id = ?
  `).all(patientId);

  const takenCount = logs.filter(l => l.status === 'taken').length;
  const adherenceRate = logs.length ? ((takenCount / logs.length) * 100).toFixed(1) : '0.0';
  let streak = 0;
  for (let i = logs.length - 1; i >= 0; i--) {
    if (logs[i].status === 'taken') streak++;
    else break;
  }

  const today = dayjs().format('YYYY-MM-DD');
  const todayLog = logs.find(l => l.date === today);
  const todayStatus = todayLog ? todayLog.status : 'not marked';

  res.json({
    patientName: patient.name,
    caretakerName: assignment?.caretakerName || 'Not assigned',
    adherenceRate,
    streak,
    todayStatus,
    logs,
    medications
  });
});

// Caretaker Dashboard
app.get('/dashboard/caretaker', authenticate, (req, res) => {
  if (req.user.role !== 'caretaker') return res.status(403).json({ error: 'Access denied' });

  const caretakerId = req.user.userId;
  const assignment = db.prepare(`SELECT patient_id FROM assignments WHERE caretaker_id = ?`).get(caretakerId);
  if (!assignment) return res.status(404).json({ error: 'No assigned patient found' });

  const patientId = assignment.patient_id;
  fillMissedLogsForPast30Days(patientId);

  const patient = db.prepare(`SELECT name FROM users WHERE id = ?`).get(patientId);
  const caretaker = db.prepare(`SELECT name FROM users WHERE id = ?`).get(caretakerId);

  const logs = db.prepare(`
    SELECT date, status FROM medication_logs
    WHERE patient_id = ? AND date >= DATE('now', '-30 day')
    ORDER BY date
  `).all(patientId);

  const takenCount = logs.filter(l => l.status === 'taken').length;
  const adherenceRate = logs.length ? ((takenCount / logs.length) * 100).toFixed(1) : '0.0';
  let streak = 0;
  for (let i = logs.length - 1; i >= 0; i--) {
    if (logs[i].status === 'taken') streak++;
    else break;
  }

  const today = dayjs().format('YYYY-MM-DD');
  const todayLog = logs.find(l => l.date === today);
  const todayStatus = todayLog ? todayLog.status : 'not marked';
  const takenInWeek = logs.slice(-7).filter(l => l.status === 'taken').length;
  const missedInMonth = logs.filter(l => l.status !== 'taken').length;

  res.json({
    caretakerName: caretaker.name,
    patient: patient.name,
    adherenceRate,
    streak,
    takenInWeek,
    missedInMonth,
    todayStatus,
    logs
  });
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
