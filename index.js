// server.js
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const dayjs = require('dayjs');

const app = express();
const PORT = 3001;
const SECRET_KEY = 'your_secret_key';


app.use(cors());
app.use(bodyParser.json());

app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

const db = new sqlite3.Database('./medication_app.db', (err) => {
  if (err) return console.error(err.message);
  console.log('Connected to SQLite database.');
});

db.serialize(() => {
  db.run(`PRAGMA foreign_keys = ON`);

  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    email TEXT UNIQUE,
    password TEXT,
    phone TEXT,
    role TEXT CHECK(role IN ('patient', 'caretaker'))
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS assignments (
    patient_id INTEGER UNIQUE,
    caretaker_id INTEGER UNIQUE,
    FOREIGN KEY(patient_id) REFERENCES users(id),
    FOREIGN KEY(caretaker_id) REFERENCES users(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS medications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id INTEGER,
    name TEXT,
    dosage TEXT,
    frequency TEXT,
    UNIQUE(patient_id, name),
    FOREIGN KEY(patient_id) REFERENCES users(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS medication_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id INTEGER,
    date TEXT,
    status TEXT,
    UNIQUE(patient_id, date),
    FOREIGN KEY(patient_id) REFERENCES users(id)
  )`);
});

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
  const dates = [];
  for (let i = 1; i < 30; i++) {
    dates.push(today.subtract(i, 'day').format('YYYY-MM-DD'));
  }

  dates.forEach(date => {
    db.get(`SELECT 1 FROM medication_logs WHERE patient_id = ? AND date = ?`, [patientId, date], (err, row) => {
      if (err) return;
      if (!row) {
        db.run(`INSERT INTO medication_logs (patient_id, date, status) VALUES (?, ?, 'missed')`, [patientId, date]);
      }
    });
  });
}

app.post('/signup', async (req, res) => {
  try {
    const { name, email, password, phone, role } = req.body;
    if (!name || !email || !password || !phone || !role)
      return res.status(400).json({ error: 'Missing fields' });

    const hashedPassword = await bcrypt.hash(password, 10);

    if (role === 'patient') {
      db.get(
        `SELECT id FROM users WHERE role = 'caretaker' AND id NOT IN (SELECT caretaker_id FROM assignments) LIMIT 1`,
        [],
        (err, row) => {
          if (err) return res.status(500).json({ error: 'Database error' });
          if (!row) return res.status(400).json({ error: 'No available caretakers' });

          db.run(
            `INSERT INTO users (name, email, password, phone, role) VALUES (?, ?, ?, ?, ?)`,
            [name, email, hashedPassword, phone, role],
            function (err) {
              if (err)
                return res.status(400).json({ error: 'User already exists or invalid data' });

              const userId = this.lastID;

              db.run(
                `INSERT INTO assignments (patient_id, caretaker_id) VALUES (?, ?)`,
                [userId, row.id],
                err => {
                  if (err)
                    return res.status(500).json({ error: 'Assignment failed after registration' });

                  res.status(201).json({
                    message: 'Patient registered and assigned to caretaker',
                  });
                }
              );
            }
          );
        }
      );
    } else {
      db.run(
        `INSERT INTO users (name, email, password, phone, role) VALUES (?, ?, ?, ?, ?)`,
        [name, email, hashedPassword, phone, role],
        function (err) {
          if (err)
            return res.status(400).json({ error: 'User already exists or invalid data' });

          res.status(201).json({ message: 'Caretaker registered' });
        }
      );
    }
  } catch (err) {
    res.status(500).json({ error: 'Internal Server Error' });
  }
});


app.post('/login', async (req, res) => {
  try {
    const { email, password, role } = req.body;

    if (!email || !password || !role) {
      return res.status(400).json({ error: 'Missing fields' });
    }

    db.get(`SELECT * FROM users WHERE email = ? AND role = ?`, [email, role], async (err, user) => {
      if (err || !user) {
        return res.status(401).json({ error: 'User Not Found' });
      }

      const valid = await bcrypt.compare(password, user.password);
      if (!valid) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      const payload = { userId: user.id, role: user.role };
      const token = jwt.sign(payload, SECRET_KEY, { expiresIn: '2h' });

      // Extra check only for caretakers
      if (role === 'caretaker') {
        db.get(`SELECT * FROM assignments WHERE caretaker_id = ?`, [user.id], (err, assignment) => {
          if (err || !assignment) {
            return res.status(403).json({ error: 'No patient assigned to this caretaker' });
          }

          // Success response
          res.json({ token, userId: user.id, role: user.role });
        });
      } else {
        // Success response for patient
        res.json({ token, userId: user.id, role: user.role });
      }
    });
  } catch (err) {
    res.status(500).json({ error: 'Internal Server Error' });
  }
});


app.post('/medications', authenticate, (req, res) => {
  try {
    if (req.user.role !== 'patient') {
      return res.status(403).json({ error: 'Only patients can add medications' });
    }

    const { name, dosage, frequency } = req.body;
    if (!name || !dosage || !frequency) {
      return res.status(400).json({ error: 'Missing fields' });
    }

    // Case-insensitive check for existing medication
    db.get(`
      SELECT * FROM medications 
      WHERE patient_id = ? AND LOWER(name) = LOWER(?)
    `, [req.user.userId, name], (err, existingMed) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      if (existingMed) {
        return res.status(400).json({ error: 'Medication already exists' });
      }

      // If not found, insert
      db.run(`
        INSERT INTO medications (patient_id, name, dosage, frequency) 
        VALUES (?, ?, ?, ?)`,
        [req.user.userId, name, dosage, frequency],
        function (err) {
          if (err) return res.status(400).json({ error: 'Failed to add medication' });
          res.status(201).json({ message: 'Medication added' });
        }
      );
    });
  } catch (err) {
    res.status(500).json({ error: 'Internal Server Error' });
  }
});


app.post('/medications/mark', authenticate, (req, res) => {
  try {
    if (req.user.role !== 'patient') return res.status(403).json({ error: 'Only patients can mark medication' });

    const today = new Date().toISOString().split('T')[0];
    db.run(`INSERT OR REPLACE INTO medication_logs (patient_id, date, status) VALUES (?, ?, 'taken')`,
      [req.user.userId, today], (err) => {
        if (err) return res.status(500).json({ error: 'Failed to mark medication' });
        res.json({ message: 'Medication marked as taken for today' });
      });
  } catch (err) {
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.get('/dashboard/patient', authenticate, (req, res) => {
  try {
    if (req.user.role !== 'patient') return res.status(403).json({ error: 'Access denied' });
    const patientId = req.user.userId;

    fillMissedLogsForPast30Days(patientId);

    db.get(`
      SELECT name FROM users WHERE id = ?
    `, [patientId], (err, patientRow) => {
      if (err || !patientRow) return res.status(404).json({ error: 'Patient not found' });

      const patientName = patientRow.name;

      db.get(`
        SELECT users.name as caretakerName FROM users
        JOIN assignments ON users.id = assignments.caretaker_id
        WHERE assignments.patient_id = ?
      `, [patientId], (err, assignmentRow) => {
        if (err || !assignmentRow) return res.status(404).json({ error: 'Caretaker not found' });

        db.all(`
          SELECT date, status FROM medication_logs 
          WHERE patient_id = ? AND date >= DATE('now', '-30 day') 
          ORDER BY date
        `, [patientId], (err, logs) => {
          if (err) return res.status(500).json({ error: 'Failed to fetch logs' });

          const takenCount = logs.filter(log => log.status === 'taken').length;
          const adherenceRate = logs.length ? ((takenCount / logs.length) * 100).toFixed(1) : '0.0';

          let streak = 0;
          for (let i = logs.length - 1; i >= 0; i--) {
            if (logs[i].status === 'taken') streak++;
            else break;
          }

          const today = new Date().toISOString().split('T')[0];
          const todayLog = logs.find(log => log.date === today);
          const todayStatus = todayLog ? todayLog.status : 'not marked';

          db.all(`
            SELECT name, dosage, frequency FROM medications WHERE patient_id = ?
          `, [patientId], (err, medications) => {
            if (err) return res.status(500).json({ error: 'Failed to fetch medications' });

            res.json({
              patientName,
              caretakerName: assignmentRow.caretakerName,
              adherenceRate,
              streak,
              todayStatus,
              logs,
              medications
            });
          });
        });
      });
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});


app.get('/dashboard/caretaker', authenticate, (req, res) => {
  try {
    if (req.user.role !== 'caretaker') return res.status(403).json({ error: 'Access denied' });
    const caretakerId = req.user.userId;

    db.get(`SELECT patient_id FROM assignments WHERE caretaker_id = ?`, [caretakerId], (err, assignment) => {
      if (err || !assignment) return res.status(404).json({ error: 'No assigned patient found' });

      const patientId = assignment.patient_id;

      fillMissedLogsForPast30Days(patientId);

      db.get(`SELECT name FROM users WHERE id = ?`, [patientId], (err, patientRow) => {
        if (err || !patientRow) return res.status(404).json({ error: 'Patient not found' });

        db.get(`SELECT name FROM users WHERE id = ?`, [caretakerId], (err, caretakerRow) => {
          if (err || !caretakerRow) return res.status(404).json({ error: 'Caretaker not found' });

          const caretakerName = caretakerRow.name;

          db.all(`
            SELECT date, status FROM medication_logs 
            WHERE patient_id = ? AND date >= DATE('now', '-30 day') 
            ORDER BY date
          `, [patientId], (err, logs) => {
            if (err) return res.status(500).json({ error: 'Failed to fetch logs' });

            const takenCount = logs.filter(log => log.status === 'taken').length;
            const adherenceRate = logs.length ? ((takenCount / logs.length) * 100).toFixed(1) : '0.0';

            let streak = 0;
            for (let i = logs.length - 1; i >= 0; i--) {
              if (logs[i].status === 'taken') streak++;
              else break;
            }

            const today = new Date().toISOString().split('T')[0];
            const todayLog = logs.find(log => log.date === today);
            const todayStatus = todayLog ? todayLog.status : 'not marked';

            const takenInWeek = logs.slice(-7).filter(log => log.status === 'taken').length;
            const missedInMonth = logs.filter(log => log.status !== 'taken').length;

            res.json({
              caretakerName,
              patient: patientRow.name,
              adherenceRate,
              streak,
              takenInWeek,
              missedInMonth,
              todayStatus,
              logs
            });
          });
        });
      });
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});


app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
