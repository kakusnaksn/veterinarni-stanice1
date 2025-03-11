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
app.use(express.static(__dirname)); // Slouží statické soubory (index.html)

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
    email TEXT
)`);

db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL
)`);

// Přidání uživatele (pouze poprvé, heslo zahashované)
const initUsers = async () => {
    const hashedPassword = await bcrypt.hash('12345', 10); // Heslo "12345"
    db.run('INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)', ['mracek', hashedPassword], (err) => {
        if (err) console.error('Chyba při vkládání uživatele:', err);
    });
};
initUsers();

const SECRET_KEY = process.env.JWT_SECRET || 'tajny-klic-pro-jwt'; // Použije JWT_SECRET z Renderu

// Middleware pro ověření JWT s logováním
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    console.log('Authorization Header:', authHeader); // Log hlavičky
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) {
        console.log('No token provided');
        return res.status(401).json({ error: 'Přístup odepřen – chybí token' });
    }

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) {
            console.log('JWT Verify Error:', err.message); // Log chyby
            return res.status(403).json({ error: 'Neplatný token' });
        }
        console.log('Token ověřen, uživatel:', user); // Log úspěšného ověření
        req.user = user;
        next();
    });
}

// Přihlášení
app.post('/login', async (req, res) => {
    const { jmeno, heslo } = req.body;
    db.get('SELECT * FROM users WHERE username = ?', [jmeno], async (err, user) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!user || !(await bcrypt.compare(heslo, user.password))) {
            console.log('Přihlášení selhalo: špatné jméno nebo heslo');
            return res.status(401).json({ success: false, message: 'Špatné jméno nebo heslo' });
        }
        const token = jwt.sign({ id: user.id, username: user.username }, SECRET_KEY, { expiresIn: '1h' });
        console.log('Přihlášení úspěšné, token vygenerován');
        res.json({ success: true, token });
    });
});

// API endpoints
app.get('/reservations/:date', (req, res) => {
    const date = req.params.date;
    db.all('SELECT * FROM reservations WHERE date = ?', [date], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.post('/reservations', authenticateToken, (req, res) => {
    const { date, time, timeEnd, zakaznik, zvire, duvod, telefon, email } = req.body;
    db.run('INSERT INTO reservations (date, time, timeEnd, zakaznik, zvire, duvod, telefon, email) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        [date, time, timeEnd || null, zakaznik, zvire, duvod, telefon || null, email || null],
        function(err) {
            if (err) return res.status(500).json({ error: err.message });
            console.log('Rezervace uložena, ID:', this.lastID);
            res.json({ id: this.lastID });
        });
});

app.put('/reservations/:id', authenticateToken, (req, res) => {
    const { time, timeEnd, zakaznik, zvire, duvod, telefon, email } = req.body;
    const id = req.params.id;
    db.run('UPDATE reservations SET time = ?, timeEnd = ?, zakaznik = ?, zvire = ?, duvod = ?, telefon = ?, email = ? WHERE id = ?',
        [time, timeEnd || null, zakaznik, zvire, duvod, telefon || null, email || null, id],
        function(err) {
            if (err) return res.status(500).json({ error: err.message });
            console.log('Rezervace upravena, ID:', id);
            res.json({ updated: this.changes });
        });
});

app.delete('/reservations/:id', authenticateToken, (req, res) => {
    const id = req.params.id;
    db.run('DELETE FROM reservations WHERE id = ?', [id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        console.log('Rezervace smazána, ID:', id);
        res.json({ deleted: this.changes });
    });
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(port, () => {
    console.log(`Server běží na portu ${port}`);
});
