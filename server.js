require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const connection = require('./db'); // MySQL connection
const { requireAdmin } = require('./middlewares/role'); // Updated role-based middleware

const app = express();
app.use(cors());
app.use(express.json());

const SECRET_KEY = process.env.JWT_SECRET;

// 🔐 Verify JWT Middleware
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(403).json({ error: "Access Denied" });

    jwt.verify(token.split(" ")[1], SECRET_KEY, (err, decoded) => {
        if (err) return res.status(403).json({ error: "Invalid Token" });
        req.user = decoded;
        next();
    });
};

// ✅ API Health Check
app.get('/', (req, res) => {
    res.send({ message: 'E_Library API is running!' });
});

// ✅ Signup Route
app.post('/signup', async (req, res) => {
    const { username, password, fName, lName, role } = req.body;

    if (!username || !password || !fName || !lName) {
        return res.status(400).json({ error: "Missing required fields" });
    }

    const userRole = role || 'user'; // Default role: user
    const hashedPassword = await bcrypt.hash(password, 10);

    const sql = 'INSERT INTO user (Username, Password, FName, LName, Role) VALUES (?, ?, ?, ?, ?)';
    connection.query(sql, [username, hashedPassword, fName, lName, userRole], (err, result) => {
        if (err) return res.status(500).json({ error: err.sqlMessage || 'Error creating user' });
        res.status(201).json({ message: 'User created successfully!', userId: result.insertId });
    });
});

// ✅ Signin Route with Role-Based JWT
app.post('/signin', (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) return res.status(400).json({ error: "Missing username or password" });

    const sql = 'SELECT * FROM user WHERE Username = ?';
    connection.query(sql, [username], (err, results) => {
        if (err) return res.status(500).json({ error: "Internal server error" });
        if (results.length === 0) return res.status(401).json({ error: "Invalid username or password" });

        const user = results[0];

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

// ✅ Protected Dashboard Route
app.get('/dashboard', verifyToken, (req, res) => {
    res.json({ message: `Welcome ${req.user.username}, this is a protected dashboard!` });
});

// ✅ Get All Books
app.get('/books', (req, res) => {
    connection.query('SELECT * FROM Book', (err, results) => {
        if (err) return res.status(500).json({ error: 'Error fetching books' });
        res.json(results);
    });
});

// ✅Get book with publisher and author
app.get('/book/:id', (req, res) => {
  const sql = `
    SELECT b.Id, b.Title, b.Type, b.Price,
           p.PName AS Publisher, p.City AS PublisherCity,
           a.FName AS AuthorFirst, a.LName AS AuthorLast, a.Country, a.City AS AuthorCity, a.Address
    FROM Book b
    JOIN Publisher p ON b.PubId = p.Id
    JOIN Author a ON b.AuthorId = a.Id
    WHERE b.Id = ?
  `;

  connection.query(sql, [req.params.id], (err, result) => {
    if (err) {
      console.error("SQL Error:", err);
      return res.status(500).json({ error: "Error fetching book details" });
    }

    if (result.length === 0) {
      return res.status(404).json({ error: "Book not found" });
    }

    res.status(200).json(result[0]);
  });
});

// 🔐 **Admin-Only Routes** 🔐
// ✅ Only Admins Can Add a Book
app.post('/book', verifyToken, requireAdmin, (req, res) => {
    const { title, type, price, pubId, authorId } = req.body;

    if (!title || !type || !price || !pubId || !authorId) return res.status(400).json({ error: "Missing required fields" });

    const sql = 'INSERT INTO Book (Title, Type, Price, pubId, AuthorId) VALUES (?, ?, ?, ?, ?)';
    connection.query(sql, [title, type, price, pubId, authorId], (err, result) => {
        if (err) return res.status(500).json({ error: 'Error adding book' });
        res.status(201).json({ message: 'Book added successfully!', bookId: result.insertId });
    });
});

// ✅ Only Admins Can Delete a Book fragment
app.delete('/book/:id', verifyToken, requireAdmin, (req, res) => {
    const bookId = req.params.id;
    connection.query('DELETE FROM Book WHERE Id = ?', [bookId], (err, result) => {
        if (err) return res.status(500).json({ error: 'Error deleting book' });
        if (result.affectedRows === 0) return res.status(404).json({ error: 'Book not found' });
        res.json({ message: 'Book deleted successfully!' });
    });
});
// ✅Public route – search by book title 
app.get('/books/search', (req, res) => {
  const { q } = req.query;

  if (!q || q.trim() === '') {
    return res.status(400).json({ error: "Search query is required" });
  }

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

  connection.query(sql, [searchTerm], (err, results) => {
    if (err) {
      console.error("SQL Error:", err);
      return res.status(500).json({ error: "Search failed" });
    }

    if (results.length === 0) {
      return res.status(404).json({ message: "No books found" });
    }

    res.status(200).json(results);
  });
});

// ✅ Admin-Only: Add/Delete a Publisher
app.post('/publisher', verifyToken, requireAdmin, (req, res) => {
  const { PName, City } = req.body;

  if (!PName || !City) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  const sql = 'INSERT INTO Publisher (PName, City) VALUES (?, ?)';
  connection.query(sql, [PName, City], (err, result) => {
    if (err) {
      console.error("SQL Error:", err);
      return res.status(500).json({ error: 'Error adding publisher' });
    }
    res.status(201).json({ message: 'Publisher added successfully!', pubId: result.insertId });
  });
});

app.delete('/publisher/:id', verifyToken, requireAdmin, (req, res) => {
    const pubId = req.params.id;
    connection.query('DELETE FROM Publisher WHERE Id = ?', [pubId], (err, result) => {
        if (err) return res.status(500).json({ error: 'Error deleting publisher' });
        if (result.affectedRows === 0) return res.status(404).json({ error: 'Publisher not found' });
        res.json({ message: 'Publisher deleted successfully!' });
    });
});

 // ✅ Search Publisher by Partial Name 
app.get('/publishers/search', (req, res) => {
  const { q } = req.query;

  if (!q || q.trim() === '') {
    return res.status(400).json({ error: "Search query is required" });
  }

  const searchTerm = `%${q}%`;
  const sql = `
    SELECT Id, PName, City
    FROM Publisher
    WHERE PName LIKE ?
  `;

  connection.query(sql, [searchTerm], (err, results) => {
    if (err) {
      console.error("Publisher search SQL Error:", err);
      return res.status(500).json({ error: "Publisher search failed" });
    }

    if (results.length === 0) {
      return res.status(404).json({ message: "No publishers found" });
    }

    res.status(200).json(results);
  });
});
// ✅ Get Books from Selected Publisher
app.get('/publisher/:id/books', (req, res) => {
  const sql = `
    SELECT b.Id, b.Title, b.Type, b.Price,
           a.FName AS AuthorFirst, a.LName AS AuthorLast
    FROM Book b
    JOIN Author a ON b.AuthorId = a.Id
    WHERE b.PubId = ?
  `;

  connection.query(sql, [req.params.id], (err, results) => {
    if (err) {
      console.error("SQL Error:", err);
      return res.status(500).json({ error: "Failed to fetch books by publisher" });
    }

    if (results.length === 0) {
      return res.status(404).json({ message: "This publisher has no books" });
    }

    res.status(200).json(results);
  });
});

// ✅ Admin-Only: Add/Delete an Author
app.post('/author', verifyToken, requireAdmin, (req, res) => {
    const { FName, LName, Country, City, Address} = req.body;

    if (!FName || !LName || !Country || !City || !Address) return res.status(400).json({ error: "Missing required fields" });

    const sql = 'INSERT INTO Author (FName, LName, Country, City, Address) VALUES (?, ?, ?, ?, ?)';
    connection.query(sql, [FName, LName, Country, City, Address], (err, result) => {
        if (err) return res.status(500).json({ error: 'Error adding author' });
        res.status(201).json({ message: 'Author added successfully!', authorId: result.insertId });
    });
});
// ✅Public route – search by first or last Author Name fragment
app.get('/authors/search', (req, res) => {
  const { q } = req.query;

  if (!q || q.trim() === '') {
    return res.status(400).json({ error: "Search query is required" });
  }

  const searchTerm = `%${q}%`;
  const sql = `
    SELECT Id, FName, LName, Country, City
    FROM Author
    WHERE FName LIKE ? OR LName LIKE ?
  `;

  connection.query(sql, [searchTerm, searchTerm], (err, results) => {
    if (err) {
      console.error("Author search SQL Error:", err);
      return res.status(500).json({ error: "Author search failed" });
    }

    if (results.length === 0) {
      return res.status(404).json({ message: "No authors found" });
    }

    res.status(200).json(results);
  });
});

// Get All Books Written by a Selected Author
app.get('/author/:id/books', (req, res) => {
  const sql = `
    SELECT b.Id, b.Title, b.Type, b.Price,
           p.PName AS Publisher
    FROM Book b
    JOIN Publisher p ON b.PubId = p.Id
    WHERE b.AuthorId = ?
  `;

  connection.query(sql, [req.params.id], (err, results) => {
    if (err) {
      console.error("Book lookup SQL Error:", err);
      return res.status(500).json({ error: "Failed to fetch books by author" });
    }

    if (results.length === 0) {
      return res.status(404).json({ message: "This author has no books" });
    }

    res.status(200).json(results);
  });
});


// ✅ Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));