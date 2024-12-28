const express = require('express');
const mysql = require('mysql2');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const requestIp = require('request-ip');
require('dotenv').config();

const app = express();
app.use(express.json());

// Initialize MySQL connection
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'jwt_auth'
});

db.connect(err => {
  if (err) throw err;
  console.log('Connected to MySQL');
  
  // Create enhanced users table
  db.query(`CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL
  )`);

  // Create enhanced tokens table with login details
  db.query(`CREATE TABLE IF NOT EXISTS tokens (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    token VARCHAR(500) NOT NULL,
    login_time DATETIME NOT NULL,
    login_ip VARCHAR(45) NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
  )`);
});

// Registration endpoint
app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Insert user
    db.query(
      'INSERT INTO users (username, password) VALUES (?, ?)',
      [username, hashedPassword],
      (err, result) => {
        if (err) {
          return res.status(400).json({ error: 'Username already exists' });
        }
        res.status(201).json({ message: 'User registered successfully' });
      }
    );
  } catch (error) {
    res.status(500).json({ error: 'Error registering user' });
  }
});

// Login endpoint
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    // Get user
    db.query(
      'SELECT * FROM users WHERE username = ?',
      [username],
      async (err, results) => {
        if (err || results.length === 0) {
          return res.status(401).json({ error: 'Invalid credentials' });
        }

        const user = results[0];
        
        // Verify password
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
          return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Get login details
        const loginTime = new Date();
        const loginIp = requestIp.getClientIp(req);

        // Create token with additional info
        const token = jwt.sign(
          { 
            userId: user.id,
            username: user.username,
            loginTime: loginTime,
            loginIp: loginIp
          },
          process.env.JWT_SECRET,
          { expiresIn: '1h' }
        );

        // Save token and login details
        db.query(
          'INSERT INTO tokens (user_id, token, login_time, login_ip) VALUES (?, ?, ?, ?)',
          [user.id, token, loginTime, loginIp],
          (err) => {
            if (err) {
              return res.status(500).json({ error: 'Error saving token' });
            }
            res.json({ token });
          }
        );
      }
    );
  } catch (error) {
    res.status(500).json({ error: 'Error logging in' });
  }
});

// Protected route
app.get('/protected', authenticateToken, (req, res) => {
  res.json({ 
    message: 'Protected data',
    user: {
      username: req.user.username,
      loginTime: req.user.loginTime,
      loginIp: req.user.loginIp
    }
  });
});

// Logout endpoint
app.post('/logout', authenticateToken, (req, res) => {
  db.query(
    'DELETE FROM tokens WHERE token = ?',
    [req.token],
    (err) => {
      if (err) {
        return res.status(500).json({ error: 'Error logging out' });
      }
      res.json({ message: 'Logged out successfully' });
    }
  );
});

// Authentication middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }

    // Verify token exists in database
    db.query(
      'SELECT * FROM tokens WHERE token = ?',
      [token],
      (err, results) => {
        if (err || results.length === 0) {
          return res.status(403).json({ error: 'Token not found' });
        }
        req.user = user;
        req.token = token;
        next();
      }
    );
  });
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});