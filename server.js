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
    zvire TEXT,
    duvod TEXT NOT NULL,
    telefon TEXT,
    email TEXT,
    userId INTEGER NOT NULL,
    approved INTEGER DEFAULT 0,
    deleted INTEGER DEFAULT 0,
    note TEXT,
    internalNote TEXT
)`);

db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    telefon TEXT NOT NULL,
    password TEXT NOT NULL,
    isAdmin INTEGER DEFAULT 0,
    pets TEXT DEFAULT '[]',
    notes TEXT DEFAULT '[]'
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
    db.run('INSERT INTO users (username, email, telefon, password) VALUES (?, ?, ?, ?)', 
        [jmeno, email, telefon, hashedPassword], 
        function(err) {
            if (err) {
                if (err.code === 'SQLITE_CONSTRAINT' && err.message.includes('email')) {
                    return res.status(400).json({ success: false, message: 'E-mail už existuje.' });
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

// Profil
app.get('/profile', authenticateToken, (req, res) => {
    db.get('SELECT username, email, telefon, pets, notes FROM users WHERE id = ?', [req.user.id], (err, user) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({
            username: user.username,
            email: user.email,
            telefon: user.telefon,
            pets: JSON.parse(user.pets),
            notes: JSON.parse(user.notes)
        });
    });
});

app.post('/profile/pets', authenticateToken, (req, res) => {
    if (req.user.isAdmin) return res.status(403).json({ error: 'Admin nemůže přidávat mazlíčky.' });
    const { name, species } = req.body;
    if (!name || !species) return res.status(400).json({ error: 'Jméno a druh jsou povinné.' });
    db.get('SELECT pets FROM users WHERE id = ?', [req.user.id], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        const pets = JSON.parse(row.pets);
        pets.push({ name, species });
        db.run('UPDATE users SET pets = ? WHERE id = ?', [JSON.stringify(pets), req.user.id], (err) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true });
        });
    });
});

// Správa uživatelů (admin)
app.get('/users', authenticateToken, (req, res) => {
    if (!req.user.isAdmin) return res.status(403).json({ error: 'Pouze admin.' });
    const search = req.query.search || '';
    db.all('SELECT id, username, email FROM users WHERE username LIKE ? OR email LIKE ?', [`%${search}%`, `%${search}%`], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.get('/users/:id', authenticateToken, (req, res) => {
    if (!req.user.isAdmin) return res.status(403).json({ error: 'Pouze admin.' });
    db.get('SELECT username, email, telefon, notes, pets FROM users WHERE id = ?', [req.params.id], (err, user) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!user) return res.status(404).json({ error: 'Uživatel nenalezen.' });
        res.json({
            username: user.username,
            email: user.email,
            telefon: user.telefon,
            notes: JSON.parse(user.notes),
            pets: JSON.parse(user.pets)
        });
    });
});

app.put('/users/:id/password', authenticateToken, async (req, res) => {
    if (!req.user.isAdmin) return res.status(403).json({ error: 'Pouze admin.' });
    const { password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    db.run('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, req.params.id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ success: true });
    });
});

app.post('/users/:id/notes', authenticateToken, (req, res) => {
    if (!req.user.isAdmin) return res.status(403).json({ error: 'Pouze admin.' });
    const { note } = req.body;
    db.get('SELECT notes FROM users WHERE id = ?', [req.params.id], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        const notes = JSON.parse(row.notes);
        notes.push({ author: req.user.username, text: note });
        db.run('UPDATE users SET notes = ? WHERE id = ?', [JSON.stringify(notes), req.params.id], (err) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ success: true });
        });
    });
});

app.get('/users/:id/reservations', authenticateToken, (req, res) => {
    const userId = req.params.id;
    if (!req.user.isAdmin && req.user.id != userId) return res.status(403).json({ error: 'Nemáte oprávnění.' });
    db.all('SELECT * FROM reservations WHERE userId = ? ORDER BY date, time', [userId], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

// Rezervace
app.get('/reservations/:date', authenticateToken, (req, res) => {
    const date = req.params.date;
    db.all('SELECT * FROM reservations WHERE date = ?', [date], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        // Filtrování internalNote pro ne-adminy
        const filteredRows = rows.map(row => {
            if (!req.user.isAdmin) delete row.internalNote;
            return row;
        });
        res.json(filteredRows);
    });
});

app.get('/reservations/deleted', authenticateToken, (req, res) => {
    if (!req.user.isAdmin) return res.status(403).json({ error: 'Pouze admin.' });
    db.all('SELECT * FROM reservations WHERE deleted = 1', (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.post('/reservations', authenticateToken, async (req, res) => {
    const { date, time, timeEnd, zakaznik, zvire, duvod, telefon, email, note, internalNote, userId } = req.body;
    const approved = req.user.isAdmin ? 1 : 0;
    let finalUserId = userId || req.user.id;
    const finalInternalNote = req.user.isAdmin ? (internalNote || null) : null; // Jen admin může přidat internalNote

    if (req.user.isAdmin && !userId) {
        const username = zakaznik || `zakaznik_${Date.now()}`;
        const userEmail = email || `${username}@example.com`;
        const userTelefon = telefon || '000000000';
        const hashedPassword = await bcrypt.hash('default123', 10);

        db.run('INSERT OR IGNORE INTO users (username, email, telefon, password) VALUES (?, ?, ?, ?)',
            [username, userEmail, userTelefon, hashedPassword],
            function(err) {
                if (err) {
                    if (err.code === 'SQLITE_CONSTRAINT' && err.message.includes('email')) {
                        db.get('SELECT id FROM users WHERE email = ?', [userEmail], (err, row) => {
                            if (err) return res.status(500).json({ error: err.message });
                            finalUserId = row.id;
                            vlozitRezervaci(finalUserId);
                        });
                    } else {
                        return res.status(500).json({ error: err.message });
                    }
                } else {
                    finalUserId = this.lastID;
                    vlozitRezervaci(finalUserId);
                }
            });
    } else {
        vlozitRezervaci(finalUserId);
    }

    function vlozitRezervaci(userId) {
        db.run('INSERT INTO reservations (date, time, timeEnd, zakaznik, zvire, duvod, telefon, email, userId, approved, note, internalNote) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [date, time, timeEnd || null, zakaznik, zvire || null, duvod, telefon || null, email || null, userId, approved, note || null, finalInternalNote],
            function(err) {
                if (err) return res.status(500).json({ error: err.message });
                res.json({ id: this.lastID });
            });
    }
});

app.put('/reservations/:id', authenticateToken, (req, res) => {
    const { time, timeEnd, zakaznik, zvire, duvod, telefon, email, note, internalNote } = req.body;
    const id = req.params.id;
    db.get('SELECT userId, internalNote AS currentInternalNote FROM reservations WHERE id = ?', [id], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!row || (!req.user.isAdmin && row.userId !== req.user.id)) {
            return res.status(403).json({ error: 'Nemáte oprávnění upravit tuto rezervaci.' });
        }
        const finalInternalNote = req.user.isAdmin ? (internalNote || null) : row.currentInternalNote; // Jen admin může měnit internalNote
        db.run('UPDATE reservations SET time = ?, timeEnd = ?, zakaznik = ?, zvire = ?, duvod = ?, telefon = ?, email = ?, note = ?, internalNote = ? WHERE id = ?',
            [time, timeEnd || null, zakaznik, zvire || null, duvod, telefon || null, email || null, note || null, finalInternalNote, id],
            function(err) {
                if (err) return res.status(500).json({ error: err.message });
                res.json({ updated: this.changes });
            });
    });
});

app.put('/reservations/:id/approve', authenticateToken, (req, res) => {
    if (!req.user.isAdmin) return res.status(403).json({ error: 'Pouze admin může schvalovat rezervace.' });
    db.run('UPDATE reservations SET approved = 1 WHERE id = ?', [req.params.id], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ approved: this.changes });
    });
});

app.delete('/reservations/:id', authenticateToken, (req, res) => {
    const id = req.params.id;
    db.get('SELECT userId, deleted FROM reservations WHERE id = ?', [id], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!row || (!req.user.isAdmin && row.userId !== req.user.id)) {
            return res.status(403).json({ error: 'Nemáte oprávnění smazat tuto rezervaci.' });
        }
        if (row.deleted && !req.user.isAdmin) {
            return res.status(403).json({ error: 'Rezervace již byla smazána.' });
        }
        if (req.user.isAdmin) {
            // Admin maže úplně
            db.run('DELETE FROM reservations WHERE id = ?', [id], function(err) {
                if (err) return res.status(500).json({ error: err.message });
                res.json({ deleted: this.changes });
            });
        } else {
            // Zákazník označí jako smazané
            db.run('UPDATE reservations SET deleted = 1 WHERE id = ?', [id], function(err) {
                if (err) return res.status(500).json({ error: err.message });
                res.json({ markedDeleted: this.changes });
            });
        }
    });
});

// Routy pro stránky
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'home.html'));
});

app.get('/reservations', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(port, () => {
    console.log(`Server běží na portu ${port}`);
});
