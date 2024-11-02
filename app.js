const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const port = 3000;

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// SQLite Database
const db = new sqlite3.Database('./TaskManager.db', (err) => {
    if (err) {
        console.error('Database connection error:', err.message);
    } else {
        console.log('Connected to SQLite database.');
        db.serialize(() => {
            db.run(`
                CREATE TABLE IF NOT EXISTS Users (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    Name TEXT NOT NULL,
                    Email TEXT NOT NULL UNIQUE,
                    Password TEXT NOT NULL
                );`);

            db.run(`
                CREATE TABLE IF NOT EXISTS Tasks (
                    Id INTEGER PRIMARY KEY AUTOINCREMENT,
                    Title TEXT NOT NULL,
                    Priority TEXT NOT NULL,
                    AssignedTo INTEGER,
                    IsBacklog BOOLEAN DEFAULT 0,
                    IsTodo BOOLEAN DEFAULT 0,
                    IsInProgress BOOLEAN DEFAULT 0,
                    IsDone BOOLEAN DEFAULT 0,
                    DueDate TEXT NULL,
                    CreatedAt TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (AssignedTo) REFERENCES Users(Id)
                );`);
        });
    }
});

// Utility function to authenticate token
function authenticateToken(req, res, next) {
    const token = req.headers['authorization'];
    if (!token) return res.sendStatus(401);

    jwt.verify(token, 'secret_key', (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

// Register User
app.post('/api/register', (req, res) => {
    const { name, email, password } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 10);

    db.run(`INSERT INTO Users (Name, Email, Password) VALUES (?, ?, ?)`, [name, email, hashedPassword], function (err) {
        if (err) {
            return res.status(400).json({ error: err.message });
        }
        res.status(201).json({ id: this.lastID });
    });
});

// Login User
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;

    db.get(`SELECT * FROM Users WHERE Email = ?`, [email], (err, user) => {
        if (err || !user) {
            return res.status(400).json({ error: 'Invalid email or password' });
        }
        if (bcrypt.compareSync(password, user.Password)) {
            const token = jwt.sign({ id: user.Id }, 'secret_key', { expiresIn: '1h' });
            res.json({ token });
        } else {
            res.status(400).json({ error: 'Invalid email or password' });
        }
    });
});

// Create Task
app.post('/api/tasks', authenticateToken, (req, res) => {
    const { title, priority, assignedTo, dueDate } = req.body;

    db.run(`INSERT INTO Tasks (Title, Priority, AssignedTo, DueDate) VALUES (?, ?, ?, ?)`, [title, priority, assignedTo, dueDate], function (err) {
        if (err) {
            return res.status(400).json({ error: err.message });
        }
        res.status(201).json({ id: this.lastID });
    });
});

// Filter Tasks
app.get('/api/tasks/filter/:timeframe', authenticateToken, (req, res) => {
    const { timeframe } = req.params;
    let query = 'SELECT * FROM Tasks WHERE 1=1';

    if (timeframe === 'today') {
        query += " AND DATE(CreatedAt) = DATE('now')";
    } else if (timeframe === 'this_week') {
        query += " AND DATE(CreatedAt) >= DATE('now', '-6 days')";
    } else if (timeframe === 'this_month') {
        query += " AND strftime('%Y-%m', CreatedAt) = strftime('%Y-%m', 'now')";
    } else if (timeframe === 'this_year') {
        query += " AND strftime('%Y', CreatedAt) = strftime('%Y', 'now')";
    } else {
        return res.status(400).json({ error: 'Invalid timeframe' });
    }

    db.all(query, [], (err, rows) => {
        if (err) {
            return res.status(400).json({ error: err.message });
        }
        res.json(rows);
    });
});

// Start the server
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
