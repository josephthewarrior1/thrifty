const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const mysql = require('mysql');
const bcrypt = require('bcrypt');
const session = require('express-session');

const app = express();

app.use(bodyParser.json());
app.use(cors());

// Session middleware setup
app.use(session({
  secret: 'your-secret-key', // Change this to a secure random string
  resave: false,
  saveUninitialized: true
}));

const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'thrifty'
});

db.connect(err => {
  if (err) {
    console.error('Error connecting to MySQL database:', err);
    return;
  }
  console.log('Connected to MySQL database');
});

// Signup endpoint
app.post('/signup', async (req, res) => {
  const { name, email, password, user_type } = req.body;
  try {
    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert the hashed password into the database
    const sql = 'INSERT INTO users (name, email, password, user_type) VALUES (?, ?, ?, ?)';
    db.query(sql, [name, email, hashedPassword, user_type], (err, result) => {
      if (err) {
        console.error('Error executing MySQL query:', err);
        res.status(500).json({ success: false, message: 'Error signing up' });
        return;
      }
      res.status(200).json({ success: true, message: 'Signed up successfully' });
    });
  } catch (error) {
    console.error('Error hashing password:', error);
    res.status(500).json({ success: false, message: 'Error signing up' });
  }
});

// Login endpoint
app.post('/login', (req, res) => {
  const { email, password } = req.body;
  const sql = 'SELECT id, email, user_type, password FROM users WHERE email = ?';
  db.query(sql, [email], async (err, results) => {
    if (err) {
      console.error('Error executing MySQL query:', err);
      res.status(500).json({ success: false, message: 'Error logging in' });
      return;
    }
    if (results.length === 1) {
      // Compare the provided password with the hashed password from the database
      const match = await bcrypt.compare(password, results[0].password); // <-- Line 70
      if (match) {
        // Store user data in session
        req.session.user = {
          id: results[0].id,
          email: results[0].email,
          userType: results[0].user_type // Send userType in the response
        };
        res.status(200).json({ success: true, message: 'Logged in successfully', userType: results[0].user_type });
      } else {
        res.status(401).json({ success: false, message: 'Invalid email or password' });
      }
    } else {
      res.status(401).json({ success: false, message: 'Invalid email or password' });
    }
  });
});



app.get('/api/data', (req, res) => {
  // Perform a database query to retrieve data from the 'users' table (replace with your table name)
  const sql = 'SELECT * FROM users'; // Modify the SQL query as needed
  db.query(sql, (err, results) => {
    if (err) {
      console.error('Error executing MySQL query:', err);
      res.status(500).json({ success: false, message: 'Error retrieving data from the database' });
      return;
    }
    // Send the retrieved data as the response
    res.json(results);
  });
});

app.get('/signup', (req, res) => {
  res.status(200).send('Sign up for an account!');
});


app.get('/login', (req, res) => {
  if (req.session.user) {
    return res.json({ valid: true, role: req.session.user.userType });
  } else {
    return res.json({ valid: false });
  }
});


const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server is running on port ${PORT}`));
