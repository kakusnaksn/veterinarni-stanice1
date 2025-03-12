const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');
const app = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

const db = new sqlite3.Database('./reservations.db', (err) => {
    if (err) console.error(err.message);
    console.log('Připojeno k databázi.');
});

// Vytvoření tabulek
db.run(`CREATE TABLE IF NOT EXISTS reservations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    date TEXT NOT NULL,
    time TEXT NOT NULL,
    timeEnd TEXT,
    zakaznik TEXT NOT NULL,
    zvire TEXT NOT NULL,
    duvod TEXT NOT NULL,
    telefon TEXT,
    email TEXT,
    userId INTEGER NOT NULL,
    approved INTEGER DEFAULT 0
)`);

db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    telefon TEXT NOT NULL,
    password TEXT NOT NULL,
    isAdmin INTEGER DEFAULT 0
)`);

// Přidání admina
const initUsers = async () => {
    const hashedPassword = await bcrypt.hash('12345', 10);
    db.run('INSERT OR IGNORE INTO users (username, email, telefon, password, isAdmin) VALUES (?, ?, ?, ?, ?)', 
        ['mracek', 'mracek@veterina.cz', '123456789', hashedPassword, 1], 
        (err) => { if (err) console.error('Chyba při vkládání admina:', err); }
    );
};
initUsers();

const SECRET_KEY = process.env.JWT_SECRET || 'tajny-klic-pro-jwt';

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Přístup odepřen – chybí token' });

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ error: 'Neplatný token' });
        req.user = user;
        next();
    });
}

// Registrace
app.post('/register', async (req, res) => {
    const { jmeno, email, telefon, heslo } = req.body;
    const hashedPassword = await bcrypt.hash(heslo, 10);
    db.run('INSERT INTO users (username, email, telefon, password, isAdmin) VALUES (?, ?, ?, ?, 0)', 
        [jmeno, email, telefon, hashedPassword], 
        function(err) {
            if (err) {
                if (err.code === 'SQLITE_CONSTRAINT') {
                    return res.status(400).json({ success: false, message: 'Uživatelské jméno nebo e-mail už existuje.' });
                }
                return res.status(500).json({ success: false, message: 'Chyba při registraci.' });
            }
            res.json({ success: true });
        });
});

// Přihlášení
app.post('/login', async (req, res) => {
    const { jmeno, heslo } = req.body;
    db.get('SELECT * FROM users WHERE username = ?', [jmeno], async (err, user) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!user || !(await bcrypt.compare(heslo, user.password))) {
            return res.status(401).json({ success: false, message: 'Špatné jméno nebo heslo' });
        }
        const token = jwt.sign({ id: user.id, username: user.username, isAdmin: user.isAdmin }, SECRET_KEY, { expiresIn: '1h' });
        res.json({ success: true, token, userId: user.id, isAdmin: user.isAdmin });
    });
});

// API endpointy
app.get('/reservations/:date', (req, res) => {
    const date = req.params.date;
    db.all('SELECT * FROM reservations WHERE date = ?', [date], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.post('/reservations', authenticateToken, (req, res) => {
    const { date, time, timeEnd, zakaznik, zvire, duvod, telefon, email } = req.body;
    const approved = req.user.isAdmin ? 1 : 0; // Adminovy rezervace jsou automaticky schválené
    db.run('INSERT INTO reservations (date, time, timeEnd, zakaznik, zvire, duvod, telefon, email, userId, approved) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [date, time, timeEnd || null, zakaznik, zvire, duvod, telefon || null, email || null, req.user.id, approved],
        function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ id: this.lastID });
        });
});

app.put('/reservations/:id', authenticateToken, (req, res) => {
    const { time, timeEnd, zakaznik, zvire, duvod, telefon, email } = req.body;
    const id = req.params.id;
    db.get('SELECT userId FROM reservations WHERE id = ?', [id], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!row || (!req.user.isAdmin && row.userId !== req.user.id)) {
            return res.status(403).json({ error: 'Nemáte oprávnění upravit tuto rezervaci.' });
        }
        db.run('UPDATE reservations SET time = ?, timeEnd = ?, zakaznik = ?, zvire = ?, duvod = ?, telefon = ?, email = ? WHERE id = ?',
            [time, timeEnd || null, zakaznik, zvire, duvod, telefon || null, email || null, id],
            function(err) {
                if (err) return res.status(500).json({ error: err.message });
                res.json({ updated: this.changes });
            });
    });
});

app.put('/reservations/:id/approve', authenticateToken, (req, res) => {
    if (!req.user.isAdmin) return res.status(403).json({ error: 'Pouze admin může schvalovat rezervace.' });
    const id = req.params.id;
    db.run('UPDATE reservations SET approved = 1 WHERE id = ?', [id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ approved: this.changes });
    });
});

app.delete('/reservations/:id', authenticateToken, (req, res) => {
    const id = req.params.id;
    db.get('SELECT userId FROM reservations WHERE id = ?', [id], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!row || (!req.user.isAdmin && row.userId !== req.user.id)) {
            return res.status(403).json({ error: 'Nemáte oprávnění smazat tuto rezervaci.' });
        }
        db.run('DELETE FROM reservations WHERE id = ?', [id], function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ deleted: this.changes });
        });
    });
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(port, () => {
    console.log(`Server běží na portu ${port}`);
});
