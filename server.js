require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const db = require('./sqliteConnection'); // SQLite connection
const { requireAdmin } = require('./middlewares/role'); // Role middleware

const app = express();
app.use(cors());
app.use(express.json());

const SECRET_KEY = process.env.JWT_SECRET;

// 🔐 JWT Middleware
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(403).json({ error: "Access Denied" });

    jwt.verify(token.split(" ")[1], SECRET_KEY, (err, decoded) => {
        if (err) return res.status(403).json({ error: "Invalid Token" });
        req.user = decoded;
        next();
    });
};

// ✅ API Health
app.get('/', (req, res) => {
    res.send({ message: 'E_Library API is running!' });
});

// ✅ Signup
app.post('/signup', async (req, res) => {
    const { username, password, fName, lName, role } = req.body;

    if (!username || !password || !fName || !lName) {
        return res.status(400).json({ error: "Missing required fields" });
    }

    const userRole = role || 'user';
    const hashedPassword = await bcrypt.hash(password, 10);

    const sql = 'INSERT INTO user (Username, Password, FName, LName, Role) VALUES (?, ?, ?, ?, ?)';
    db.run(sql, [username, hashedPassword, fName, lName, userRole], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        res.status(201).json({ message: 'User created successfully!', userId: this.lastID });
    });
});

// ✅ Signin
app.post('/signin', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: "Missing username or password" });

    const sql = 'SELECT * FROM user WHERE Username = ?';
    db.get(sql, [username], (err, user) => {
        if (err) return res.status(500).json({ error: "Internal server error" });
        if (!user) return res.status(401).json({ error: "Invalid username or password" });

        bcrypt.compare(password, user.Password, (err, isMatch) => {
            if (err) return res.status(500).json({ error: "Authentication failed" });
            if (!isMatch) return res.status(401).json({ error: "Invalid username or password" });

            const token = jwt.sign(
                { userId: user.Id, username: user.Username, role: user.Role || 'user' },
                SECRET_KEY,
                { expiresIn: "1h" }
            );
            res.json({ message: "Login successful", token, role: user.Role || 'user' });
        });
    });
});

// ✅ Protected route
app.get('/dashboard', verifyToken, (req, res) => {
    res.json({ message: `Welcome ${req.user.username}, this is a protected dashboard!` });
});







// ✅ Only Admins Can Delete a Book
app.delete('/book/:id', verifyToken, requireAdmin, (req, res) => {
  const bookId = req.params.id;
  db.run('DELETE FROM Book WHERE Id = ?', [bookId], function (err) {
    if (err) return res.status(500).json({ error: 'Error deleting book' });
    if (this.changes === 0) return res.status(404).json({ error: 'Book not found' });
    res.json({ message: 'Book deleted successfully!' });
  });
});

// ✅ Public search by book title
app.get('/books/search', (req, res) => {
  const { q } = req.query;
  if (!q || q.trim() === '') return res.status(400).json({ error: "Search query is required" });

  const searchTerm = `%${q}%`;
  const sql = `
    SELECT b.Id, b.Title, b.Type, b.Price,
           p.PName AS Publisher,
           a.FName AS AuthorFirst, a.LName AS AuthorLast
    FROM Book b
    JOIN Publisher p ON b.PubId = p.Id
    JOIN Author a ON b.AuthorId = a.Id
    WHERE b.Title LIKE ?
  `;

  db.all(sql, [searchTerm], (err, results) => {
    if (err) return res.status(500).json({ error: "Search failed" });
    if (results.length === 0) return res.status(404).json({ message: "No books found" });
    res.json(results);
  });
});

// ✅ Admin: Add Publisher
app.post('/publisher', verifyToken, requireAdmin, (req, res) => {
  const { PName, City } = req.body;
  if (!PName || !City) return res.status(400).json({ error: "Missing required fields" });

  const sql = 'INSERT INTO Publisher (PName, City) VALUES (?, ?)';
  db.run(sql, [PName, City], function (err) {
    if (err) return res.status(500).json({ error: 'Error adding publisher' });
    res.status(201).json({ message: 'Publisher added successfully!', pubId: this.lastID });
  });
});

// ✅ Admin: Delete Publisher
app.delete('/publisher/:id', verifyToken, requireAdmin, (req, res) => {
  const pubId = req.params.id;
  db.run('DELETE FROM Publisher WHERE Id = ?', [pubId], function (err) {
    if (err) return res.status(500).json({ error: 'Error deleting publisher' });
    if (this.changes === 0) return res.status(404).json({ error: 'Publisher not found' });
    res.json({ message: 'Publisher deleted successfully!' });
  });
});

// ✅ Search Publisher
app.get('/publishers/search', (req, res) => {
  const { q } = req.query;
  if (!q || q.trim() === '') return res.status(400).json({ error: "Search query is required" });

  const searchTerm = `%${q}%`;
  db.all(`SELECT Id, PName, City FROM Publisher WHERE PName LIKE ?`, [searchTerm], (err, results) => {
    if (err) return res.status(500).json({ error: "Publisher search failed" });
    if (results.length === 0) return res.status(404).json({ message: "No publishers found" });
    res.json(results);
  });
});

// ✅ Books by Publisher
app.get('/publisher/:id/books', (req, res) => {
  const sql = `
    SELECT b.Id, b.Title, b.Type, b.Price,
           a.FName AS AuthorFirst, a.LName AS AuthorLast
    FROM Book b
    JOIN Author a ON b.AuthorId = a.Id
    WHERE b.PubId = ?
  `;
  db.all(sql, [req.params.id], (err, results) => {
    if (err) return res.status(500).json({ error: "Failed to fetch books by publisher" });
    if (results.length === 0) return res.status(404).json({ message: "This publisher has no books" });
    res.json(results);
  });
});

// ✅ Admin: Add Author
app.post('/author', verifyToken, requireAdmin, (req, res) => {
  const { FName, LName, Country, City, Address } = req.body;
  if (!FName || !LName || !Country || !City || !Address)
    return res.status(400).json({ error: "Missing required fields" });

  const sql = 'INSERT INTO Author (FName, LName, Country, City, Address) VALUES (?, ?, ?, ?, ?)';
  db.run(sql, [FName, LName, Country, City, Address], function (err) {
    if (err) return res.status(500).json({ error: 'Error adding author' });
    res.status(201).json({ message: 'Author added successfully!', authorId: this.lastID });
  });
});

// ✅ Search Authors
app.get('/authors/search', (req, res) => {
  const { q } = req.query;
  if (!q || q.trim() === '') return res.status(400).json({ error: "Search query is required" });

  const searchTerm = `%${q}%`;
  db.all(
    `SELECT Id, FName, LName, Country, City FROM Author WHERE FName LIKE ? OR LName LIKE ?`,
    [searchTerm, searchTerm],
    (err, results) => {
      if (err) return res.status(500).json({ error: "Author search failed" });
      if (results.length === 0) return res.status(404).json({ message: "No authors found" });
      res.json(results);
    }
  );
});

// ✅ Books by Author
app.get('/author/:id/books', (req, res) => {
  const sql = `
    SELECT b.Id, b.Title, b.Type, b.Price,
           p.PName AS Publisher
    FROM Book b
    JOIN Publisher p ON b.PubId = p.Id
    WHERE b.AuthorId = ?
  `;
  db.all(sql, [req.params.id], (err, results) => {
    if (err) return res.status(500).json({ error: "Failed to fetch books by author" });
    if (results.length === 0) return res.status(404).json({ message: "This author has no books" });
    res.json(results);
  });
});

// ✅ Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));