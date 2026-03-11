const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const pool = require("./db");
require("dotenv").config();

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || "focuszen-secret-key-2024";

app.use(cors());
app.use(express.json());

// Database initialization: Ensure password column exists
const initDB = async () => {
  try {
    await pool.query(`
      ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash VARCHAR(255);
    `);
    console.log("Database schema verified.");
  } catch (err) {
    console.error("Database Init Error:", err);
  }
};
initDB();

app.get("/test", async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM users");
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).send("Database error");
  }
});

// Create a new focus session
app.post("/api/focus-sessions", async (req, res) => {
  try {
    const { user_id, start_time, end_time, duration, interruptions } = req.body;
    
    if (!start_time || !end_time) {
      return res.status(400).json({ error: "Missing start_time or end_time" });
    }

    const query = `
      INSERT INTO focus_sessions (user_id, start_time, end_time, duration, interruptions)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING *;
    `;
    
    const values = [user_id, start_time, end_time, duration, interruptions || 0];
    const result = await pool.query(query, values);
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error("Error inserting focus session:", err);
    res.status(500).json({ error: "Failed to save focus session" });
  }
});

// Get all focus sessions
app.get("/api/focus-sessions", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM focus_sessions ORDER BY start_time DESC"
    );
    res.json(result.rows);
  } catch (err) {
    console.error("Error fetching focus sessions:", err);
    res.status(500).json({ error: "Failed to fetch focus sessions" });
  }
});

// Auth: Signup
app.post("/api/auth/signup", async (req, res) => {
  try {
    const { email, username, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "Email and password are required" });
    
    // Hash password
    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);
    
    const query = `
      INSERT INTO users (email, username, password_hash) 
      VALUES ($1, $2, $3) 
      RETURNING id, email, username;
    `;
    const result = await pool.query(query, [email, username, passwordHash]);
    const user = result.rows[0];
    
    // Generate JWT
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
    
    res.status(201).json({ user, token });
  } catch (err) {
    console.error("Signup error:", err);
    if (err.code === '23505') {
      return res.status(400).json({ error: "Email already exists" });
    }
    res.status(500).json({ error: "Failed to sign up" });
  }
});

// Auth: Login
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "Email and password are required" });

    const query = `SELECT * FROM users WHERE email = $1`;
    const result = await pool.query(query, [email]);
    
    if (result.rows.length === 0) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    
    const user = result.rows[0];
    
    // Verify password
    const isPasswordValid = await bcrypt.compare(password, user.password_hash || '');
    if (!isPasswordValid) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    
    // Generate JWT
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
    
    // Don't send password hash back
    delete user.password_hash;
    
    res.json({ user, token });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Failed to log in" });
  }
});

app.listen(5000, "0.0.0.0", () => {
  console.log("Server running on port 5000 (bound to 0.0.0.0)");
});