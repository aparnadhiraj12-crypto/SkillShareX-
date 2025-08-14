// server.js
const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

// Fake in-memory DB (replace with MongoDB later)
let users = [];

const app = express();
app.use(cors());
app.use(bodyParser.json());

const SECRET_KEY = "skillsharex_secret"; // Change in production

// Signup Route
app.post("/signup", async (req, res) => {
    const { name, email, password } = req.body;

    // Check if user already exists
    if (users.find(user => user.email === email)) {
        return res.status(400).json({ success: false, message: "User already exists" });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Save user
    const newUser = { name, email, password: hashedPassword };
    users.push(newUser);

    res.json({ success: true, message: "Signup successful!" });
});

// Signin Route
app.post("/signin", async (req, res) => {
    const { email, password } = req.body;
    const user = users.find(user => user.email === email);

    if (!user) {
        return res.status(400).json({ success: false, message: "Invalid email or password" });
    }

    // Compare password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
        return res.status(400).json({ success: false, message: "Invalid email or password" });
    }

    // Create JWT token
    const token = jwt.sign({ email: user.email }, SECRET_KEY, { expiresIn: "1h" });

    res.json({ success: true, message: "Login successful", token });
});

// Profile Route
app.get("/profile", (req, res) => {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) {
        return res.status(401).json({ success: false, message: "No token provided" });
    }

    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        const user = users.find(u => u.email === decoded.email);
        res.json({ success: true, user: { name: user.name, email: user.email } });
    } catch (err) {
        res.status(401).json({ success: false, message: "Invalid token" });
    }
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
