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
app.use(express.static(__dirname)); // Statické soubory (index.html, scissors.glb)

// Inicializace SQLite databáze
const db = new sqlite3.Database('./reservations.db', (err) => {
    if (err) {
        console.error('Chyba při připojení k databázi:', err.message);
        process.exit(1);
    }
    console.log('Připojeno k databázi.');
});

// Vytvoření tabulek
db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS reservations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT NOT NULL,
            time TEXT NOT NULL,
            timeEnd TEXT,
            zakaznik TEXT NOT NULL,
            serviceType TEXT NOT NULL,
            telefon TEXT,
            email TEXT,
            userId INTEGER NOT NULL,
            approved INTEGER DEFAULT 0,
            deleted INTEGER DEFAULT 0,
            note TEXT,
            internalNote TEXT,
            createdAt TEXT DEFAULT CURRENT_TIMESTAMP,
            updatedAt TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);

    db.run(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            telefon TEXT NOT NULL,
            password TEXT NOT NULL,
            isAdmin INTEGER DEFAULT 0,
            notes TEXT DEFAULT '[]',
            createdAt TEXT DEFAULT CURRENT_TIMESTAMP
        )
    `);

    // Přidání admina při startu serveru
    const initUsers = async () => {
        const hashedPassword = await bcrypt.hash('12345', 10);
        db.run(
            'INSERT OR IGNORE INTO users (username, email, telefon, password, isAdmin) VALUES (?, ?, ?, ?, ?)',
            ['mracek', 'mracek@salon.cz', '123456789', hashedPassword, 1],
            (err) => {
                if (err) {
                    console.error('Chyba při vkládání admina:', err);
                } else {
                    console.log('Vytvořen výchozí admin: username=mracek, heslo=12345');
                }
            }
        );
    };
    initUsers();
});

const SECRET_KEY = process.env.JWT_SECRET || 'tajny-klic-pro-jwt';

// Middleware pro autentizaci tokenu
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) {
        req.user = null; // Bez tokenu pokračujeme jako nepřihlášený
        return next();
    }

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Neplatný token' });
        }
        req.user = user;
        next();
    });
}

// Middleware pro ověření admina
function requireAdmin(req, res, next) {
    if (!req.user || !req.user.isAdmin) {
        return res.status(403).json({ error: 'Pouze admin může provádět tuto akci.' });
    }
    next();
}

// Registrace
app.post('/register', async (req, res) => {
    const { jmeno, email, telefon, heslo } = req.body;
    if (!jmeno || !email || !telefon || !heslo) {
        return res.status(400).json({ success: false, message: 'Vyplňte všechna pole!' });
    }

    try {
        const hashedPassword = await bcrypt.hash(heslo, 10);
        db.run(
            'INSERT INTO users (username, email, telefon, password) VALUES (?, ?, ?, ?)',
            [jmeno, email, telefon, hashedPassword],
            function (err) {
                if (err) {
                    if (err.code === 'SQLITE_CONSTRAINT' && err.message.includes('email')) {
                        return res.status(400).json({ success: false, message: 'E-mail už existuje.' });
                    }
                    if (err.code === 'SQLITE_CONSTRAINT' && err.message.includes('username')) {
                        return res.status(400).json({ success: false, message: 'Uživatelské jméno už existuje.' });
                    }
                    console.error('Chyba při registraci:', err);
                    return res.status(500).json({ success: false, message: 'Chyba při registraci.' });
                }
                res.json({ success: true, userId: this.lastID });
            }
        );
    } catch (error) {
        console.error('Chyba při hashování hesla:', error);
        res.status(500).json({ success: false, message: 'Chyba při registraci.' });
    }
});

// Přihlášení
app.post('/login', async (req, res) => {
    const { jmeno, heslo } = req.body;
    if (!jmeno || !heslo) {
        return res.status(400).json({ success: false, message: 'Vyplňte všechna pole!' });
    }

    db.get('SELECT * FROM users WHERE username = ?', [jmeno], async (err, user) => {
        if (err) {
            console.error('Chyba při přihlášení:', err);
            return res.status(500).json({ error: err.message });
        }
        if (!user || !(await bcrypt.compare(heslo, user.password))) {
            return res.status(401).json({ success: false, message: 'Špatné jméno nebo heslo' });
        }
        const token = jwt.sign({ id: user.id, username: user.username, isAdmin: user.isAdmin }, SECRET_KEY, { expiresIn: '1h' });
        res.json({ success: true, token, userId: user.id, isAdmin: user.isAdmin });
    });
});

// Profil uživatele
app.get('/profile', authenticateToken, (req, res) => {
    if (!req.user) return res.status(401).json({ error: 'Přihlášení je vyžadováno.' });
    db.get('SELECT username, email, telefon FROM users WHERE id = ?', [req.user.id], (err, user) => {
        if (err) {
            console.error('Chyba při načítání profilu:', err);
            return res.status(500).json({ error: err.message });
        }
        if (!user) return res.status(404).json({ error: 'Uživatel nenalezen.' });
        res.json({
            username: user.username,
            email: user.email,
            telefon: user.telefon
        });
    });
});

// Správa uživatelů (admin)
app.get('/users', authenticateToken, requireAdmin, (req, res) => {
    const search = req.query.search || '';
    db.all(
        'SELECT id, username, email, telefon, isAdmin FROM users WHERE username LIKE ? OR email LIKE ?',
        [`%${search}%`, `%${search}%`],
        (err, rows) => {
            if (err) {
                console.error('Chyba při načítání uživatelů:', err);
                return res.status(500).json({ error: err.message });
            }
            res.json(rows);
        }
    );
});

app.get('/users/:id', authenticateToken, requireAdmin, (req, res) => {
    db.get(
        'SELECT id, username, email, telefon, notes, isAdmin FROM users WHERE id = ?',
        [req.params.id],
        (err, user) => {
            if (err) {
                console.error('Chyba při načítání uživatele:', err);
                return res.status(500).json({ error: err.message });
            }
            if (!user) return res.status(404).json({ error: 'Uživatel nenalezen.' });
            res.json({
                id: user.id,
                username: user.username,
                email: user.email,
                telefon: user.telefon,
                notes: JSON.parse(user.notes),
                isAdmin: user.isAdmin
            });
        }
    );
});

app.put('/users/:id/password', authenticateToken, requireAdmin, async (req, res) => {
    const { password } = req.body;
    if (!password) return res.status(400).json({ error: 'Heslo je povinné.' });

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        db.run('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, req.params.id], function (err) {
            if (err) {
                console.error('Chyba při změně hesla:', err);
                return res.status(500).json({ error: err.message });
            }
            if (this.changes === 0) return res.status(404).json({ error: 'Uživatel nenalezen.' });
            res.status(200).json({ success: true });
        });
    } catch (error) {
        console.error('Chyba při hashování hesla:', error);
        res.status(500).json({ error: 'Chyba při změně hesla.' });
    }
});

app.post('/users/:id/notes', authenticateToken, requireAdmin, (req, res) => {
    const { note } = req.body;
    if (!note) return res.status(400).json({ error: 'Poznámka je povinná.' });

    db.get('SELECT notes FROM users WHERE id = ?', [req.params.id], (err, row) => {
        if (err) {
            console.error('Chyba při načítání uživatele:', err);
            return res.status(500).json({ error: err.message });
        }
        if (!row) return res.status(404).json({ error: 'Uživatel nenalezen.' });

        const notes = JSON.parse(row.notes);
        notes.push({ author: req.user.username, text: note, timestamp: new Date().toLocaleString('cs-CZ') });
        db.run('UPDATE users SET notes = ? WHERE id = ?', [JSON.stringify(notes), req.params.id], (err) => {
            if (err) {
                console.error('Chyba při ukládání poznámky:', err);
                return res.status(500).json({ error: err.message });
            }
            res.status(200).json({ success: true });
        });
    });
});

app.get('/users/:id/reservations', authenticateToken, (req, res) => {
    if (!req.user) return res.status(401).json({ error: 'Přihlášení je vyžadováno.' });
    const userId = req.params.id;
    if (!req.user.isAdmin && req.user.id != userId) return res.status(403).json({ error: 'Nemáte oprávnění.' });

    db.all('SELECT * FROM reservations WHERE userId = ? ORDER BY date, time', [userId], (err, rows) => {
        if (err) {
            console.error('Chyba při načítání rezervací uživatele:', err);
            return res.status(500).json({ error: err.message });
        }
        res.json(rows);
    });
});

app.put('/users/:id/toggle-admin', authenticateToken, requireAdmin, (req, res) => {
    const userId = req.params.id;
    if (userId == req.user.id) return res.status(403).json({ error: 'Nemůžete změnit vlastní roli.' });

    db.get('SELECT isAdmin FROM users WHERE id = ?', [userId], (err, row) => {
        if (err) {
            console.error('Chyba při načítání uživatele:', err);
            return res.status(500).json({ error: err.message });
        }
        if (!row) return res.status(404).json({ error: 'Uživatel nenalezen.' });

        const newIsAdmin = row.isAdmin ? 0 : 1;
        db.run('UPDATE users SET isAdmin = ? WHERE id = ?', [newIsAdmin, userId], function (err) {
            if (err) {
                console.error('Chyba při změně role:', err);
                return res.status(500).json({ error: err.message });
            }
            res.status(200).json({ success: true, isAdmin: newIsAdmin });
        });
    });
});

app.delete('/users/:id', authenticateToken, requireAdmin, (req, res) => {
    const userId = req.params.id;
    if (userId == req.user.id) return res.status(403).json({ error: 'Nemůžete smazat vlastní účet.' });

    db.run('DELETE FROM reservations WHERE userId = ?', [userId], (err) => {
        if (err) {
            console.error('Chyba při mazání rezervací uživatele:', err);
            return res.status(500).json({ error: err.message });
        }
        db.run('DELETE FROM users WHERE id = ?', [userId], function (err) {
            if (err) {
                console.error('Chyba při mazání uživatele:', err);
                return res.status(500).json({ error: err.message });
            }
            if (this.changes === 0) return res.status(404).json({ error: 'Uživatel nenalezen.' });
            res.status(200).json({ success: true });
        });
    });
});

// Rezervace – veřejné i autentizované zobrazení
app.get('/reservations/:date', authenticateToken, (req, res) => {
    const date = req.params.date;
    db.all('SELECT * FROM reservations WHERE date = ?', [date], (err, rows) => {
        if (err) {
            console.error('Chyba při načítání rezervací:', err);
            return res.status(500).json({ error: err.message });
        }

        const filteredRows = rows.map(row => {
            const publicData = {
                id: row.id,
                date: row.date,
                time: row.time,
                timeEnd: row.timeEnd,
                zakaznik: row.zakaznik,
                serviceType: row.serviceType,
                approved: row.approved,
                deleted: row.deleted
            };
            if (req.user) {
                publicData.userId = row.userId;
                publicData.note = row.note;
                if (req.user.isAdmin) {
                    publicData.internalNote = row.internalNote;
                    publicData.telefon = row.telefon;
                    publicData.email = row.email;
                } else if (req.user.id === row.userId) {
                    publicData.telefon = row.telefon;
                    publicData.email = row.email;
                }
            }
            return publicData;
        });

        if (!req.user) {
            res.json(filteredRows.filter(r => r.approved && !r.deleted));
        } else if (req.user.isAdmin) {
            res.json(filteredRows);
        } else {
            res.json(filteredRows.filter(r => r.approved || r.userId === req.user.id));
        }
    });
});

app.get('/reservations/deleted', authenticateToken, requireAdmin, (req, res) => {
    db.all('SELECT * FROM reservations WHERE deleted = 1', (err, rows) => {
        if (err) {
            console.error('Chyba při načítání smazaných rezervací:', err);
            return res.status(500).json({ error: err.message });
        }
        res.json(rows);
    });
});

app.post('/reservations', authenticateToken, async (req, res) => {
    if (!req.user) return res.status(401).json({ error: 'Přihlášení je vyžadováno.' });

    const { date, time, timeEnd, zakaznik, serviceType, telefon, email, note, internalNote, userId } = req.body;
    const approved = req.user.isAdmin ? 1 : 0;
    let finalUserId = userId || req.user.id;
    const finalInternalNote = req.user.isAdmin ? (internalNote || null) : null;

    if (!date || !time || !zakaznik || !serviceType) {
        return res.status(400).json({ error: 'Datum, čas, jméno zákazníka a typ služby jsou povinné.' });
    }

    // Kontrola, zda čas není obsazený
    db.get(
        'SELECT id FROM reservations WHERE date = ? AND time = ? AND deleted = 0 AND approved = 1',
        [date, time],
        (err, row) => {
            if (err) {
                console.error('Chyba při kontrole časového slotu:', err);
                return res.status(500).json({ error: err.message });
            }
            if (row) return res.status(400).json({ error: 'Tento čas je již obsazen.' });

            // Pokud admin vytváří rezervaci pro nového uživatele
            if (req.user.isAdmin && !userId) {
                const username = zakaznik || `zakaznik_${Date.now()}`;
                const userEmail = email || `${username}@example.com`;
                const userTelefon = telefon || '000000000';
                const hashedPassword = bcrypt.hashSync('default123', 10);

                db.run(
                    'INSERT OR IGNORE INTO users (username, email, telefon, password) VALUES (?, ?, ?, ?)',
                    [username, userEmail, userTelefon, hashedPassword],
                    function (err) {
                        if (err) {
                        if (err.code === 'SQLITE_CONSTRAINT' && err.message.includes('email')) {
                            db.get('SELECT id FROM users WHERE email = ?', [userEmail], (err, row) => {
                                if (err) {
                                    console.error('Chyba při hledání uživatele podle e-mailu:', err);
                                    return res.status(500).json({ error: err.message });
                                }
                                finalUserId = row.id;
                                vlozitRezervaci(finalUserId);
                            });
                        } else {
                            console.error('Chyba při vytváření nového uživatele:', err);
                            return res.status(500).json({ error: err.message });
                        }
                    } else {
                        finalUserId = this.lastID;
                        vlozitRezervaci(finalUserId);
                    }
                }
            );
        } else {
            vlozitRezervaci(finalUserId);
        }
    });

    function vlozitRezervaci(userId) {
        db.run(
            'INSERT INTO reservations (date, time, timeEnd, zakaznik, serviceType, telefon, email, userId, approved, note, internalNote) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [date, time, timeEnd || null, zakaznik, serviceType, telefon || null, email || null, userId, approved, note || null, finalInternalNote],
            function (err) {
                if (err) {
                    console.error('Chyba při ukládání rezervace:', err);
                    return res.status(500).json({ error: err.message });
                }
                res.status(201).json({ id: this.lastID });
            }
        );
    }
});

app.put('/reservations/:id', authenticateToken, (req, res) => {
    if (!req.user) return res.status(401).json({ error: 'Přihlášení je vyžadováno.' });

    const { date, time, timeEnd, zakaznik, serviceType, telefon, email, note, internalNote, approved } = req.body;
    const id = req.params.id;

    db.get('SELECT userId, time, internalNote AS currentInternalNote, approved AS currentApproved FROM reservations WHERE id = ?', [id], (err, row) => {
        if (err) {
            console.error('Chyba při načítání rezervace:', err);
            return res.status(500).json({ error: err.message });
        }
        if (!row || (!req.user.isAdmin && row.userId !== req.user.id)) {
            return res.status(403).json({ error: 'Nemáte oprávnění upravit tuto rezervaci.' });
        }

        const finalInternalNote = req.user.isAdmin ? (internalNote !== undefined ? internalNote : row.currentInternalNote) : row.currentInternalNote;
        const finalApproved = req.user.isAdmin ? (approved !== undefined ? approved : row.currentApproved) : row.currentApproved;

        // Kontrola, zda nový čas není obsazený (pokud se mění)
        if (time && time !== row.time) {
            db.get(
                'SELECT id FROM reservations WHERE date = ? AND time = ? AND deleted = 0 AND approved = 1 AND id != ?',
                [date || row.date, time, id],
                (err, conflict) => {
                    if (err) {
                        console.error('Chyba při kontrole časového slotu:', err);
                        return res.status(500).json({ error: err.message });
                    }
                    if (conflict) return res.status(400).json({ error: 'Nový čas je již obsazen.' });
                    provedUpravu(finalInternalNote, finalApproved);
                }
            );
        } else {
            provedUpravu(finalInternalNote, finalApproved);
        }

        function provedUpravu(finalInternalNote, finalApproved) {
            db.run(
                'UPDATE reservations SET date = ?, time = ?, timeEnd = ?, zakaznik = ?, serviceType = ?, telefon = ?, email = ?, note = ?, internalNote = ?, approved = ?, updatedAt = CURRENT_TIMESTAMP WHERE id = ?',
                [
                    date || row.date,
                    time || row.time,
                    timeEnd !== undefined ? timeEnd : row.timeEnd,
                    zakaznik || row.zakaznik,
                    serviceType || row.serviceType,
                    telefon !== undefined ? telefon : row.telefon,
                    email !== undefined ? email : row.email,
                    note !== undefined ? note : row.note,
                    finalInternalNote,
                    finalApproved,
                    id
                ],
                function (err) {
                    if (err) {
                        console.error('Chyba při úpravě rezervace:', err);
                        return res.status(500).json({ error: err.message });
                    }
                    if (this.changes === 0) return res.status(404).json({ error: 'Rezervace nenalezena.' });
                    res.status(200).json({ updated: this.changes });
                }
            );
        }
    });
});

app.put('/reservations/:id/approve', authenticateToken, requireAdmin, (req, res) => {
    db.run('UPDATE reservations SET approved = 1, updatedAt = CURRENT_TIMESTAMP WHERE id = ?', [req.params.id], function (err) {
        if (err) {
            console.error('Chyba při schvalování rezervace:', err);
            return res.status(500).json({ error: err.message });
        }
        if (this.changes === 0) return res.status(404).json({ error: 'Rezervace nenalezena.' });
        res.status(200).json({ approved: this.changes });
    });
});

app.delete('/reservations/:id', authenticateToken, (req, res) => {
    if (!req.user) return res.status(401).json({ error: 'Přihlášení je vyžadováno.' });
    const id = req.params.id;

    db.get('SELECT userId, deleted FROM reservations WHERE id = ?', [id], (err, row) => {
        if (err) {
            console.error('Chyba při načítání rezervace:', err);
            return res.status(500).json({ error: err.message });
        }
        if (!row || (!req.user.isAdmin && row.userId !== req.user.id)) {
            return res.status(403).json({ error: 'Nemáte oprávnění smazat tuto rezervaci.' });
        }
        if (row.deleted && !req.user.isAdmin) {
            return res.status(403).json({ error: 'Rezervace již byla smazána.' });
        }

        if (req.user.isAdmin) {
            db.run('DELETE FROM reservations WHERE id = ?', [id], function (err) {
                if (err) {
                    console.error('Chyba při mazání rezervace:', err);
                    return res.status(500).json({ error: err.message });
                }
                if (this.changes === 0) return res.status(404).json({ error: 'Rezervace nenalezena.' });
                res.status(200).json({ deleted: this.changes });
            });
        } else {
            db.run('UPDATE reservations SET deleted = 1, updatedAt = CURRENT_TIMESTAMP WHERE id = ?', [id], function (err) {
                if (err) {
                    console.error('Chyba při označení rezervace jako smazané:', err);
                    return res.status(500).json({ error: err.message });
                }
                if (this.changes === 0) return res.status(404).json({ error: 'Rezervace nenalezena.' });
                res.status(200).json({ markedDeleted: this.changes });
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

// Spuštění serveru
app.listen(port, () => {
    console.log(`Server běží na portu ${port}`);
});

// Uzavření databáze při ukončení serveru
process.on('SIGINT', () => {
    db.close((err) => {
        if (err) {
            console.error('Chyba při uzavírání databáze:', err.message);
        }
        console.log('Databáze uzavřena.');
        process.exit(0);
    });
});
