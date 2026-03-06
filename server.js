const express = require("express");
const pool = require("./db");

const app = express();

app.get("/test", async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM users");
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).send("Database error");
  }
});

app.listen(5000, () => {
  console.log("Server running on port 5000");
});