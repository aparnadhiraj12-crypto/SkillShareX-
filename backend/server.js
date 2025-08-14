// server.js
import express from 'express';
import mysql from 'mysql2/promise';
import dotenv from 'dotenv';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import bodyParser from 'body-parser';

dotenv.config();
const app = express();

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.static('public')); // For your HTML/CSS/JS files

// MySQL connection
let db;
(async () => {
  try {
    db = await mysql.createConnection({
      host: process.env.DB_HOST,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME,
      port: process.env.DB_PORT
    });
    console.log('✅ Connected to MySQL Database');
  } catch (err) {
    console.error('❌ Database connection failed:', err.message);
    process.exit(1);
  }
})();

// ---------------------- SIGNUP ----------------------
app.post('/signup', async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password)
    return res.status(400).json({ message: 'All fields are required' });

  try {
    // Check if email exists
    const [existingUser] = await db.execute(
      'SELECT id FROM users WHERE email = ?',
      [email]
    );
    if (existingUser.length > 0)
      return res.status(400).json({ message: 'Email already registered' });

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert into DB
    await db.execute(
      'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
      [username, email, hashedPassword]
    );

    res.json({ message: 'User registered successfully' });
  } catch (err) {
    res.status(500).json({ message: 'Error registering user', error: err.message });
  }
});

// ---------------------- SIGNIN ----------------------
app.post('/signin', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password)
    return res.status(400).json({ message: 'All fields are required' });

  try {
    const [rows] = await db.execute(
      'SELECT * FROM users WHERE email = ?',
      [email]
    );

    if (rows.length === 0)
      return res.status(400).json({ message: 'Invalid email or password' });

    const user = rows[0];
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid)
      return res.status(400).json({ message: 'Invalid email or password' });

    // Create token
    const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, {
      expiresIn: '1h'
    });

    res.json({ message: 'Login successful', token, username: user.username });
  } catch (err) {
    res.status(500).json({ message: 'Error logging in', error: err.message });
  }
});

// ---------------------- PROFILE ----------------------
app.get('/profile', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token provided' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const [rows] = await db.execute(
      'SELECT id, username, email FROM users WHERE id = ?',
      [decoded.id]
    );

    if (rows.length === 0)
      return res.status(404).json({ message: 'User not found' });

    res.json(rows[0]);
  } catch (err) {
    res.status(401).json({ message: 'Invalid or expired token' });
  }
});

// ---------------------- START SERVER ----------------------
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});

