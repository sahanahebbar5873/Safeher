const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static("public"));

/* =========================
   DATABASE CONNECTION
========================= */
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB Connected"))
  .catch(err => console.log("MongoDB Error:", err));

/* =========================
   MODELS
========================= */
const UserSchema = new mongoose.Schema({
  email:     { type: String, required: true, unique: true },
  password:  { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  lastLogin: { type: Date },
  loginCount:{ type: Number, default: 0 },
  isOnline:  { type: Boolean, default: false },
});
const User = mongoose.model("User", UserSchema);

const SOSSchema = new mongoose.Schema({
  userId:    { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  email:     String,
  timestamp: { type: Date, default: Date.now },
  location:  String,
});
const SOS = mongoose.model("SOS", SOSSchema);

const LoginLogSchema = new mongoose.Schema({
  email:     String,
  timestamp: { type: Date, default: Date.now },
  action:    String, // "login" | "logout"
});
const LoginLog = mongoose.model("LoginLog", LoginLogSchema);

/* =========================
   AUTH MIDDLEWARE
========================= */
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "No token" });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ message: "Invalid token" });
  }
}

/* =========================
   HOME
========================= */
app.get("/", (req, res) => {
  res.sendFile(__dirname + "/public/index.html");
});

/* =========================
   REGISTER
========================= */
app.post("/register", async (req, res) => {
  try {
    const { email, password } = req.body;
    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ message: "User already exists" });
    const hashed = await bcrypt.hash(password, 10);
    await new User({ email, password: hashed }).save();
    res.json({ message: "User Registered Successfully" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* =========================
   LOGIN
========================= */
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "User not found" });
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: "Invalid password" });

    // Update user stats
    user.lastLogin  = new Date();
    user.loginCount = (user.loginCount || 0) + 1;
    user.isOnline   = true;
    await user.save();

    // Log it
    await new LoginLog({ email, action: "login" }).save();

    const token = jwt.sign({ id: user._id, email: user.email }, process.env.JWT_SECRET, { expiresIn: "1h" });
    res.json({ token });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* =========================
   LOGOUT
========================= */
app.post("/logout", authMiddleware, async (req, res) => {
  try {
    await User.findByIdAndUpdate(req.user.id, { isOnline: false });
    await new LoginLog({ email: req.user.email, action: "logout" }).save();
    res.json({ message: "Logged out" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* =========================
   SOS
========================= */
app.post("/sos", authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    await new SOS({
      userId:    req.user.id,
      email:     user?.email,
      location:  req.body.location || "Unknown",
      timestamp: new Date(),
    }).save();
    console.log("🚨 SOS Triggered by:", user?.email);
    res.json({ message: "SOS Alert Sent Successfully" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* =========================
   AI RISK DETECTION
========================= */
app.post("/analyze", (req, res) => {
  const message = req.body.message?.toLowerCase() || "";
  const dangerWords = ["help", "attack", "danger", "emergency", "save me", "threat", "following", "scared", "assault", "unsafe"];
  const isRisk = dangerWords.some(w => message.includes(w));
  res.json({ risk: isRisk ? "HIGH" : "LOW" });
});

/* =========================
   ADMIN — STATS
========================= */
app.get("/admin/stats", async (req, res) => {
  try {
    const totalUsers   = await User.countDocuments();
    const onlineUsers  = await User.countDocuments({ isOnline: true });
    const totalSOS     = await SOS.countDocuments();
    const recentSOS    = await SOS.find().sort({ timestamp: -1 }).limit(5);
    const recentLogins = await LoginLog.find({ action: "login" }).sort({ timestamp: -1 }).limit(10);
    const allUsers     = await User.find({}, "email createdAt lastLogin loginCount isOnline").sort({ createdAt: -1 });

    res.json({ totalUsers, onlineUsers, totalSOS, recentSOS, recentLogins, allUsers });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/* =========================
   START SERVER
========================= */
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
