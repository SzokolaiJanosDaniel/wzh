const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const methodOverride = require('method-override');
const expressLayouts = require('express-ejs-layouts');

const app = express();

// ---------- ADATBÁZIS KAPCSOLAT ----------
// IDE KELL AZ ADATBÁZIS FÁJL NEVE. A projekt gyökerében legyen a db.sqlite.
// Ha más a neve vagy máshol van, itt kell átírni.
const db = new sqlite3.Database('./db.sqlite', (err) => {
  if (err) {
    console.error('Nem sikerült csatlakozni az adatbázishoz:', err);
  } else {
    console.log('SQLite adatbázis csatlakoztatva.');
  }
});

// Ha szeretnéd, itt is létrehozhatod a táblákat programból (ha még nem léteznek).
// Így biztos lehetsz benne, hogy futáskor megvannak.
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('user','admin'))
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    message TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    price REAL NOT NULL,
    description TEXT
  )`);

  // ADMIN FELHASZNÁLÓ LÉTREHOZÁSA EGYSZER (ha még nincs)
  const adminUsername = 'admin';
  const adminPassword = 'admin123'; // Ezt majd bejelentkezéshez használod
  const adminRole = 'admin';

  db.get('SELECT * FROM users WHERE username = ?', [adminUsername], (err, row) => {
    if (err) {
      console.error('Hiba admin keresésekor:', err);
    } else if (!row) {
      const hash = bcrypt.hashSync(adminPassword, 10);
      db.run(
        'INSERT INTO users (username, password_hash, role) VALUES (?,?,?)',
        [adminUsername, hash, adminRole],
        (err2) => {
          if (err2) {
            console.error('Hiba admin létrehozásakor:', err2);
          } else {
            console.log('Admin felhasználó létrehozva (admin / admin123).');
          }
        }
      );
    }
  });
});

// ---------- ALKALMAZÁS BEÁLLÍTÁSOK ----------

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(expressLayouts);
app.set('layout', 'layout');

app.use(express.urlencoded({ extended: true }));
app.use(methodOverride('_method'));

// IDE MÁSOLD A HTML5UP TÉMA STATIKUS FÁJLAIT (css, js, képek)
// pl. public/assets/css, public/assets/js, public/assets/images...
app.use(express.static(path.join(__dirname, 'public')));

// SESSION BEÁLLÍTÁS – KÖTELEZŐEN EZT A SECRET-ET HASZNÁLJUK
app.use(
  session({
    secret: 'Mondd_hogy_jobarat_es_lepj_be', // <-- kért session secret
    resave: false,
    saveUninitialized: false
  })
);

// Saját middleware: a bejelentkezett user elérhető legyen a nézetekben
app.use((req, res, next) => {
  res.locals.currentUser = req.session.user || null;
  next();
});

// ---------- SZEREPKÖR ELLENŐRZŐ MIDDLEWARE-EK ----------

function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.status(403).send('Nincs jogosultságod ehhez az oldalhoz.');
  }
  next();
}

// ---------- ROUTE-OK ----------

// 3. Főoldal menü: Név, Neptun-kód
app.get('/', (req, res) => {
  // Itt írd be a saját neved és neptun kódod a view-ban (index.ejs)
  res.render('index');
});

// AUTH: REGISZTRÁCIÓ
app.get('/register', (req, res) => {
  res.render('register', { error: null });
});

app.post('/register', (req, res) => {
  const { username, password } = req.body;
  const hashed = bcrypt.hashSync(password, 10);

  // A regisztrált felhasználó szerepe: 'user' (regisztrált látogató)
  db.run(
    'INSERT INTO users (username, password_hash, role) VALUES (?,?,?)',
    [username, hashed, 'user'],
    (err) => {
      if (err) {
        console.error(err);
        return res.render('register', { error: 'Felhasználónév már létezik vagy hiba történt.' });
      }
      res.redirect('/login');
    }
  );
});

// AUTH: LOGIN
app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (err || !user) {
      return res.render('login', { error: 'Hibás felhasználónév vagy jelszó.' });
    }
    const valid = bcrypt.compareSync(password, user.password_hash);
    if (!valid) {
      return res.render('login', { error: 'Hibás felhasználónév vagy jelszó.' });
    }
    // session-be mentjük a user-t
    req.session.user = { id: user.id, username: user.username, role: user.role };
    res.redirect('/');
  });
});

// AUTH: LOGOUT
app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/');
  });
});

// 4. Adatbázis menü: 3 tábla adatai
app.get('/database', (req, res) => {
  // Itt egyszerre kérdezünk le 3 táblából néhány adatot.

  const data = {};

  db.all('SELECT id, username, role FROM users', [], (err, users) => {
    data.users = users || [];
    db.all('SELECT id, name, email, message, created_at FROM messages ORDER BY created_at DESC', [], (err2, messages) => {
      data.messages = messages || [];
      db.all('SELECT id, name, price, description FROM products', [], (err3, products) => {
        data.products = products || [];
        res.render('database', { data });
      });
    });
  });
});

// 5. Kapcsolat menü – kapcsolat űrlap (csak bejelentkezett küldhet)
app.get('/contact', (req, res) => {
  res.render('contact', { error: null, success: null });
});

app.post('/contact', requireLogin, (req, res) => {
  const { name, email, message } = req.body;
  const userId = req.session.user.id;

  db.run(
    'INSERT INTO messages (user_id, name, email, message) VALUES (?,?,?,?)',
    [userId, name, email, message],
    (err) => {
      if (err) {
        console.error(err);
        return res.render('contact', { error: 'Hiba történt az üzenet mentésekor.', success: null });
      }
      res.render('contact', { error: null, success: 'Üzenet sikeresen elküldve és elmentve az adatbázisba.' });
    }
  );
});

// 6. Üzenetek menü – csak bejelentkezett felhasználó láthatja
app.get('/messages', requireLogin, (req, res) => {
  db.all(
    'SELECT m.id, m.name, m.email, m.message, m.created_at, u.username ' +
    'FROM messages m LEFT JOIN users u ON m.user_id = u.id ' +
    'ORDER BY m.created_at DESC',
    [],
    (err, rows) => {
      if (err) {
        console.error(err);
        return res.send('Hiba történt az üzenetek lekérdezésekor.');
      }
      res.render('messages', { messages: rows });
    }
  );
});

// Üzenet törlése – csak admin
app.post('/messages/:id/delete', requireAdmin, (req, res) => {
  const id = req.params.id;
  db.run('DELETE FROM messages WHERE id = ?', [id], (err) => {
    if (err) {
      console.error(err);
    }
    res.redirect('/messages');
  });
});

// 7. CRUD menü: PRODUCTS tábla (csak admin)
app.get('/crud', requireAdmin, (req, res) => {
  db.all('SELECT * FROM products', [], (err, products) => {
    if (err) {
      console.error(err);
      return res.send('Hiba történt a termékek lekérdezésekor.');
    }
    res.render('crud', { products });
  });
});

// Új rekord létrehozása
app.post('/crud', requireAdmin, (req, res) => {
  const { name, price, description } = req.body;
  db.run(
    'INSERT INTO products (name, price, description) VALUES (?,?,?)',
    [name, price, description],
    (err) => {
      if (err) {
        console.error(err);
      }
      res.redirect('/crud');
    }
  );
});

// Rekord módosítása
app.post('/crud/:id/update', requireAdmin, (req, res) => {
  const id = req.params.id;
  const { name, price, description } = req.body;
  db.run(
    'UPDATE products SET name = ?, price = ?, description = ? WHERE id = ?',
    [name, price, description, id],
    (err) => {
      if (err) {
        console.error(err);
      }
      res.redirect('/crud');
    }
  );
});

// Rekord törlése
app.post('/crud/:id/delete', requireAdmin, (req, res) => {
  const id = req.params.id;
  db.run('DELETE FROM products WHERE id = ?', [id], (err) => {
    if (err) {
      console.error(err);
    }
    res.redirect('/crud');
  });
});

// 8. Admin menü – csak admin láthatja
app.get('/admin', requireAdmin, (req, res) => {
  res.render('admin');
});

// ---------- SZERVER INDÍTÁSA ----------
const PORT = 3000;
app.listen(PORT, () => {
  console.log('Szerver fut a http://localhost:' + PORT + ' címen');
});
