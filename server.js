const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();

// Security: Set secure HTTP headers
app.use((req, res, next) => {
  // Content Security Policy
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; style-src 'self' https://fonts.googleapis.com https://cdn.jsdelivr.net 'unsafe-inline'; font-src 'self' https://fonts.gstatic.com; img-src 'self' https://ui-avatars.com data:;"
  );
  // XSS Protection
  res.setHeader('X-XSS-Protection', '1; mode=block');
  // Prevent MIME type sniffing
  res.setHeader('X-Content-Type-Options', 'nosniff');
  // Prevent clickjacking
  res.setHeader('X-Frame-Options', 'DENY');
  // Strict Transport Security
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  next();
});

// Security: Configure CORS properly
app.use(cors({
  origin: process.env.NODE_ENV === 'production' ? 
    process.env.ALLOWED_ORIGIN || 'https://yourproductiondomain.com' : 
    'http://localhost:3000',
  methods: ['GET', 'POST', 'PATCH', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

// Security: Rate limiting for login attempts
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per window per IP
  message: { error: 'Too many login attempts, please try again after 15 minutes' },
  standardHeaders: true,
  legacyHeaders: false,
});

const mongoURI = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_key';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '24h';

mongoose.connect(mongoURI).then(() => console.log('✅ MongoDB Connected'));

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', userSchema);

// Trade Schema
const tradeSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  pair: { type: String, default: 'XAUUSD' },
  entry: Number,
  slPrice: Number,
  tpPrice: Number,
  slPips: Number,
  tpPips: Number,
  reason: String,
  outcome: {
    type: String,
    enum: {
      values: ['win', 'loss', 'running'],
      message: "'{VALUE}' is not a valid outcome. Must be 'win', 'loss', or 'running'."
    }
  },
  createdAt: { type: String, default: () => new Date().toISOString().split('T')[0] }
});

// Force recompile the model to ensure enum values are updated
let Trade;
try {
  // Remove model from mongoose to ensure it's recreated with new schema
  if (mongoose.models.Trade) {
    delete mongoose.models.Trade;
  }
  
  if (mongoose.modelNames().includes('Trade')) {
    mongoose.deleteModel('Trade');
  }
} catch (error) {
  console.log('Error while resetting Trade model:', error.message);
}

// Create fresh model with updated schema
Trade = mongoose.model('Trade', tradeSchema);

console.log('Trade model initialized with outcome enum values:', 
  Trade.schema.path('outcome').enumValues);

// Auth Middleware
function authenticateToken(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// Auth Routes
app.post('/api/signup', authLimiter, async (req, res) => {
  const { username, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  try {
    const user = new User({ username, password: hashed });
    await user.save();
    res.json({ message: 'User created' });
  } catch (err) {
    res.status(400).json({ error: 'Username already exists.' });
  }
});

app.post('/api/login', authLimiter, async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(400).json({ error: 'Invalid credentials' });
  }
  
  // Security: Improved JWT token with proper expiration
  const token = jwt.sign(
    { id: user._id }, 
    JWT_SECRET, 
    { 
      expiresIn: JWT_EXPIRES_IN // Token expires after set time
    }
  );
  
  res.json({ token });
});

// Trades API
app.get('/api/trades', authenticateToken, async (req, res) => {
  const trades = await Trade.find({ userId: req.user.id }).sort({ createdAt: -1 });
  res.json(trades);
});

app.post('/api/trades', authenticateToken, async (req, res) => {
  try {
    // Extra validation for outcome
    const { outcome } = req.body;
    const validOutcomes = ['win', 'loss', 'running'];
    
    if (outcome && !validOutcomes.includes(outcome)) {
      return res.status(400).json({ 
        error: `Invalid outcome value: '${outcome}'. Must be one of: ${validOutcomes.join(', ')}`
      });
    }
    
    const trade = new Trade({ ...req.body, userId: req.user.id });
    await trade.save();
    res.status(201).json(trade);
  } catch (err) {
    console.error('Trade creation error:', err);
    res.status(400).json({ error: err.message });
  }
});

// Delete Trade
app.delete('/api/trades/:id', authenticateToken, async (req, res) => {
    await Trade.deleteOne({ _id: req.params.id, userId: req.user.id });
    res.json({ message: 'Trade deleted' });
});
  
// Edit Trade
app.patch('/api/trades/:id', authenticateToken, async (req, res) => {
  try {
    // Extra validation for outcome
    const { outcome } = req.body;
    const validOutcomes = ['win', 'loss', 'running']; 
    
    if (outcome && !validOutcomes.includes(outcome)) {
      return res.status(400).json({ 
        error: `Invalid outcome value: '${outcome}'. Must be one of: ${validOutcomes.join(', ')}`
      });
    }
    
    const updated = await Trade.findOneAndUpdate(
      { _id: req.params.id, userId: req.user.id },
      req.body,
      { new: true, runValidators: true }
    );
    
    if (!updated) {
      return res.status(404).json({ error: 'Trade not found' });
    }
    
    res.json(updated);
  } catch (err) {
    console.error('Trade update error:', err);
    res.status(400).json({ error: err.message });
  }
});

// Get current user details
app.get('/api/me', authenticateToken, async (req, res) => {
  const user = await User.findById(req.user.id).select('-password');
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json(user);
});

// Diagnostic route to check model schema
app.get('/api/system/schema-check', (req, res) => {
  const tradeModel = mongoose.model('Trade');
  const schema = tradeModel.schema;
  const outcomeEnums = schema.path('outcome').enumValues;
  
  res.json({
    outcomeEnums,
    hasRunningState: outcomeEnums.includes('running'),
    modelName: tradeModel.modelName,
    collectionName: tradeModel.collection.name
  });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running at http://localhost:${PORT}`));
