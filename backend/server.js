const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

// Create uploads directory if not exists
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir);
}

// Multer configuration for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadsDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, 'hero-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const fileFilter = (req, file, cb) => {
  const allowedTypes = /jpeg|jpg|png|webp/;
  const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
  const mimetype = allowedTypes.test(file.mimetype);
  
  if (extname && mimetype) {
    cb(null, true);
  } else {
    cb(new Error('Only image files (JPG, PNG, WEBP) are allowed!'));
  }
};

const upload = multer({ 
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  fileFilter: fileFilter
});
const sqlite3 = require('sqlite3').verbose();
const http = require('http');
const { Server } = require('socket.io');
const { OAuth2Client } = require('google-auth-library');
const { v4: uuidv4 } = require('uuid');
const nodemailer = require('nodemailer');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

const PORT = process.env.PORT || 3001;
const JWT_SECRET = 'onehive_secret_key_2026_production';

// Middleware
app.use(cors());
app.use(express.json());

// Serve uploaded files
app.use('/uploads', express.static(uploadsDir));
app.use(express.urlencoded({ extended: true }));
app.use('/uploads', express.static('uploads'));

// Google OAuth Client
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '275974330696-82d02rjco30v42a58ghan11ra98lvdf2.apps.googleusercontent.com';
const client = new OAuth2Client(GOOGLE_CLIENT_ID);

// Database Setup
const db = new sqlite3.Database('./onehive.db', (err) => {
  if (err) console.error('Database connection error:', err);
  else console.log('Connected to SQLite database');
});

// Initialize Database Tables
db.serialize(() => {
  // Users Table
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    name TEXT,
    email TEXT UNIQUE,
    password TEXT,
    phone TEXT,
    role TEXT DEFAULT 'user',
    profile_picture TEXT,
    google_id TEXT,
    address TEXT,
    latitude REAL,
    longitude REAL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Workers Table
  db.run(`CREATE TABLE IF NOT EXISTS workers (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    name TEXT,
    email TEXT,
    phone TEXT,
    service_type TEXT,
    city TEXT,
    area TEXT,
    experience INTEGER,
    hourly_rate REAL,
    rating REAL DEFAULT 0,
    total_jobs INTEGER DEFAULT 0,
    verified INTEGER DEFAULT 0,
    status TEXT DEFAULT 'pending',
    latitude REAL,
    longitude REAL,
    document_path TEXT,
    profile_picture TEXT,
    bio TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  )`);

  // Add status column to workers if it doesn't exist (migration)
  db.run(`ALTER TABLE workers ADD COLUMN status TEXT DEFAULT 'pending'`, (err) => {
    // Ignore error if column already exists
  });

  // Shops Table
  db.run(`CREATE TABLE IF NOT EXISTS shops (
    id TEXT PRIMARY KEY,
    name TEXT,
    email TEXT,
    phone TEXT,
    address TEXT,
    city TEXT,
    latitude REAL,
    longitude REAL,
    rating REAL DEFAULT 0,
    total_orders INTEGER DEFAULT 0,
    status TEXT DEFAULT 'active',
    owner_name TEXT,
    document_path TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Products Table
  db.run(`CREATE TABLE IF NOT EXISTS products (
    id TEXT PRIMARY KEY,
    shop_id TEXT,
    name TEXT,
    description TEXT,
    category TEXT,
    price REAL,
    stock INTEGER DEFAULT 0,
    image_path TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (shop_id) REFERENCES shops(id)
  )`);

  // Bookings Table
  db.run(`CREATE TABLE IF NOT EXISTS bookings (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    worker_id TEXT,
    service_type TEXT,
    description TEXT,
    address TEXT,
    latitude REAL,
    longitude REAL,
    scheduled_date TEXT,
    scheduled_time TEXT,
    status TEXT DEFAULT 'pending',
    price_estimate REAL,
    price_final REAL,
    payment_method TEXT,
    payment_status TEXT DEFAULT 'pending',
    worker_arrived_at DATETIME,
    job_started_at DATETIME,
    job_completed_at DATETIME,
    rating_user INTEGER,
    rating_worker INTEGER,
    review_user TEXT,
    review_worker TEXT,
    before_image TEXT,
    after_image TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (worker_id) REFERENCES workers(id)
  )`);

  // Messages Table
  db.run(`CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    booking_id TEXT,
    sender_id TEXT,
    sender_type TEXT,
    message TEXT,
    image_path TEXT,
    read INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (booking_id) REFERENCES bookings(id)
  )`);

  // Payments Table
  db.run(`CREATE TABLE IF NOT EXISTS payments (
    id TEXT PRIMARY KEY,
    booking_id TEXT,
    user_id TEXT,
    amount REAL,
    method TEXT,
    status TEXT DEFAULT 'pending',
    transaction_id TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (booking_id) REFERENCES bookings(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
  )`);

  // Settings Table
  db.run(`CREATE TABLE IF NOT EXISTS settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT UNIQUE,
    value TEXT,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Insert default settings
  const defaultSettings = [
    ['footer_content', '© 2026 OneHive. All rights reserved.'],
    ['contact_email', 'support@onehive.com'],
    ['contact_phone', '+91 9876543210'],
    ['commission_percent', '15'],
    ['announcement', 'Welcome to OneHive!'],
    ['support_details', '24/7 Support: support@onehive.com'],
    ['cancellation_policy', 'Free cancellation up to 2 hours before booking.'],
    ['refund_policy', 'Refunds processed within 5-7 business days.'],
    // Email settings (SMTP)
    ['email_enabled', 'true'],
    ['email_host', 'smtp.gmail.com'],
    ['email_port', '587'],
    ['email_secure', 'false'],
    ['email_user', 'onehive2026@gmail.com'],
    ['email_password', ''],
    ['email_from_name', 'OneHive']
  ];
  
  defaultSettings.forEach(([key, value]) => {
    db.run(`INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)`, [key, value]);
  });

  // Logs Tables
  db.run(`CREATE TABLE IF NOT EXISTS booking_logs (
    id TEXT PRIMARY KEY,
    booking_id TEXT,
    action TEXT,
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS user_logs (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    action TEXT,
    details TEXT,
    ip_address TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS worker_logs (
    id TEXT PRIMARY KEY,
    worker_id TEXT,
    action TEXT,
    details TEXT,
    latitude REAL,
    longitude REAL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS admin_logs (
    id TEXT PRIMARY KEY,
    admin_id TEXT,
    action TEXT,
    details TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Ratings Table
  db.run(`CREATE TABLE IF NOT EXISTS ratings (
    id TEXT PRIMARY KEY,
    booking_id TEXT,
    user_id TEXT,
    entity_id TEXT,
    entity_type TEXT,
    rating INTEGER,
    review TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (booking_id) REFERENCES bookings(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
  )`);

  // Job Locks Table (for Call Before Accept feature)
  db.run(`CREATE TABLE IF NOT EXISTS job_locks (
    id TEXT PRIMARY KEY,
    booking_id TEXT,
    worker_id TEXT,
    locked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME,
    status TEXT DEFAULT 'locked',
    FOREIGN KEY (booking_id) REFERENCES bookings(id),
    FOREIGN KEY (worker_id) REFERENCES workers(id)
  )`);

  // Password Reset OTP Table
  db.run(`CREATE TABLE IF NOT EXISTS password_reset_otps (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    otp TEXT NOT NULL,
    otp_hash TEXT NOT NULL,
    expires_at DATETIME NOT NULL,
    used INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Hero Slider Table
  db.run(`CREATE TABLE IF NOT EXISTS hero_slider (
    id TEXT PRIMARY KEY,
    image_url TEXT NOT NULL,
    title TEXT,
    subtitle TEXT,
    order_index INTEGER DEFAULT 0,
    is_enabled INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
});

// Helper function to generate UUID
function generateId() {
  return uuidv4();
}

// Helper function to generate 6-digit OTP
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// Helper function to hash OTP (simple hash for demo - use bcrypt in production)
function hashOTP(otp) {
  const crypto = require('crypto');
  return crypto.createHash('sha256').update(otp).digest('hex');
}

// Helper function to send email using nodemailer
async function sendEmail(to, subject, body) {
  // Get email settings from database
  return new Promise((resolve) => {
    db.get(`SELECT value FROM settings WHERE key = 'email_enabled'`, [], (err, row) => {
      const emailEnabled = row ? row.value === 'true' : false;
      
      if (!emailEnabled) {
        console.log(`[EMAIL DISABLED] To: ${to}, Subject: ${subject}, Body: ${body}`);
        resolve({ success: true, message: 'Email disabled (simulated)', simulated: true });
        return;
      }
      
      // Get all email settings
      db.all(`SELECT key, value FROM settings WHERE key LIKE 'email_%'`, [], (err, settings) => {
        const settingsMap = {};
        if (settings) {
          settings.forEach(s => settingsMap[s.key] = s.value);
        }
        
        const host = settingsMap.email_host || 'smtp.gmail.com';
        const port = parseInt(settingsMap.email_port) || 587;
        const secure = settingsMap.email_secure === 'true';
        const user = settingsMap.email_user || 'onehive2026@gmail.com';
        const password = settingsMap.email_password || '';
        const fromName = settingsMap.email_from_name || 'OneHive';
        
        // Log email attempt
        console.log(`[EMAIL] To: ${to}, Subject: ${subject}`);
        
        // If no password configured, simulate
        if (!password) {
          console.log(`[EMAIL - SIMULATED] Body: ${body}`);
          console.log(`[EMAIL] ⚠️ No SMTP password configured. Go to Admin Dashboard → Settings → Email Configuration to set up real email sending.`);
          resolve({ success: true, message: 'Email simulated (no SMTP password configured)', simulated: true });
          return;
        }
        
        // Create transporter
        const transporter = nodemailer.createTransport({
          host: host,
          port: port,
          secure: secure,
          auth: {
            user: user,
            pass: password
          }
        });
        
        // Send email
        transporter.sendMail({
          from: `"${fromName}" <${user}>`,
          to: to,
          subject: subject,
          html: body
        }, (err, info) => {
          if (err) {
            console.error(`[EMAIL ERROR] ${err.message}`);
            // Fallback to console
            console.log(`[EMAIL - FALLBACK] To: ${to}, Subject: ${subject}, Body: ${body}`);
            resolve({ success: false, message: err.message, fallback: true });
          } else {
            console.log(`[EMAIL SENT] Message ID: ${info.messageId}`);
            resolve({ success: true, message: 'Email sent successfully', messageId: info.messageId });
          }
        });
      });
    });
  });
}

// Helper function to log password reset attempts
function logPasswordReset(email, action, details) {
  console.log(`[PASSWORD_RESET] ${action}: ${email} - ${details}`);
}

// Helper function to log admin action
function logAdminAction(adminId, action, details) {
  db.run(`INSERT INTO admin_logs (id, admin_id, action, details) VALUES (?, ?, ?, ?)`,
    [generateId(), adminId, action, details]);
}

// Helper function to log booking action
function logBookingAction(bookingId, action, description) {
  db.run(`INSERT INTO booking_logs (id, booking_id, action, description) VALUES (?, ?, ?, ?)`,
    [generateId(), bookingId, action, description]);
}

// Middleware to verify JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
}

// Middleware to verify admin
function authenticateAdmin(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err || user.role !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }
    req.user = user;
    next();
  });
}

// Alias for adminAuth (used in hero slider routes)
const adminAuth = authenticateAdmin;

// ==================== AUTH ROUTES ====================

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, phone, role } = req.body;
    
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'Name, email and password are required' });
    }

    // Check if user exists
    db.get(`SELECT id FROM users WHERE email = ?`, [email], async (err, existingUser) => {
      if (existingUser) {
        return res.status(400).json({ error: 'Email already exists' });
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      const userId = generateId();

      db.run(`INSERT INTO users (id, name, email, password, phone, role) VALUES (?, ?, ?, ?, ?, ?)`,
        [userId, name, email, hashedPassword, phone || '', role || 'user'],
        function(err) {
          if (err) {
            console.error('Registration error:', err);
            return res.status(500).json({ error: 'Unable to register' });
          }

          // Log user registration
          db.run(`INSERT INTO user_logs (id, user_id, action, details) VALUES (?, ?, ?, ?)`,
            [generateId(), userId, 'register', `User registered: ${email}`]);

          const token = jwt.sign({ id: userId, email, role: role || 'user' }, JWT_SECRET, { expiresIn: '7d' });
          res.json({ 
            success: true, 
            token, 
            user: { id: userId, name, email, role: role || 'user' } 
          });
        });
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Server error during registration' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Check if it's admin login attempt
    if (email === 'admin2026' && password === 'admin2026') {
      console.log(`[LOGIN] Admin credentials detected via regular login - redirecting to admin`);
      const adminId = 'admin-001';
      const token = jwt.sign({ 
        id: adminId, 
        email: 'admin@onehive.com', 
        role: 'admin',
        name: 'Administrator'
      }, JWT_SECRET, { expiresIn: '7d' });
      
      logAdminAction(adminId, 'admin_login', 'Admin logged in via regular login');
      
      return res.json({ 
        success: true, 
        token, 
        user: { 
          id: adminId, 
          name: 'Administrator', 
          email: 'admin@onehive.com', 
          role: 'admin'
        } 
      });
    }

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    db.get(`SELECT * FROM users WHERE email = ?`, [email], async (err, user) => {
      if (!user) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      const validPassword = await bcrypt.compare(password, user.password);
      if (!validPassword) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      // Log user login
      db.run(`INSERT INTO user_logs (id, user_id, action, details) VALUES (?, ?, ?, ?)`,
        [generateId(), user.id, 'login', `User logged in: ${email}`]);

      const token = jwt.sign({ 
        id: user.id, 
        email: user.email, 
        role: user.role 
      }, JWT_SECRET, { expiresIn: '7d' });

      res.json({ 
        success: true, 
        token, 
        user: { 
          id: user.id, 
          name: user.name, 
          email: user.email, 
          role: user.role,
          phone: user.phone,
          profile_picture: user.profile_picture
        } 
      });
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error during login' });
  }
});

// Google Login
app.post('/api/auth/google', async (req, res) => {
  try {
    const { token: googleToken } = req.body;
    console.log('[Google Login] Request received, token present:', !!googleToken);
    
    let payload;
    let loginMethod = '';
    
    // Try to verify as ID token first
    try {
      console.log('[Google Login] Attempting ID token verification...');
      const ticket = await client.verifyIdToken({
        idToken: googleToken,
        audience: GOOGLE_CLIENT_ID
      });
      payload = ticket.getPayload();
      loginMethod = 'ID token';
      console.log('[Google Login] ID token verified, email:', payload.email);
    } catch (e) {
      console.log('[Google Login] ID token failed, trying access token:', e.message);
      // If not an ID token, try to get user info from access token
      try {
        console.log('[Google Login] Fetching userinfo with access token...');
        const response = await fetch(`https://www.googleapis.com/oauth2/v3/userinfo?alt=json`, {
          headers: {
            Authorization: `Bearer ${googleToken}`,
          },
        });
        
        if (!response.ok) {
          const errorText = await response.text();
          console.error('[Google Login] userinfo response not OK:', response.status, errorText);
          throw new Error('Failed to get user info from Google');
        }
        
        payload = await response.json();
        payload.googleId = payload.sub;
        loginMethod = 'Access token';
        console.log('[Google Login] Access token worked, email:', payload.email);
      } catch (fetchError) {
        console.error('[Google Login] Token verification completely failed:', fetchError);
        return res.status(401).json({ error: 'Invalid Google token' });
      }
    }
    
    console.log('[Google Login] Verified via', loginMethod, '- Email:', payload.email, ', Name:', payload.name);

    // Check if user exists
    db.get(`SELECT * FROM users WHERE google_id = ? OR email = ?`, [googleId, email], async (err, user) => {
      if (user) {
        // Update google_id if not set
        if (!user.google_id) {
          db.run(`UPDATE users SET google_id = ? WHERE id = ?`, [googleId, user.id]);
        }

        // Log user login
        db.run(`INSERT INTO user_logs (id, user_id, action, details) VALUES (?, ?, ?, ?)`,
          [generateId(), user.id, 'google_login', `User logged in with Google: ${email}`]);

        const token = jwt.sign({ 
          id: user.id, 
          email: user.email, 
          role: user.role 
        }, JWT_SECRET, { expiresIn: '7d' });

        return res.json({ 
          success: true, 
          token, 
          user: { 
            id: user.id, 
            name: user.name, 
            email: user.email, 
            role: user.role,
            profile_picture: user.profile_picture || picture
          } 
        });
      }

      // Create new user
      const userId = generateId();
      db.run(`INSERT INTO users (id, name, email, google_id, profile_picture, role) VALUES (?, ?, ?, ?, ?, ?)`,
        [userId, name, email, googleId, picture, 'user'],
        function(err) {
          if (err) {
            console.error('Google registration error:', err);
            return res.status(500).json({ error: 'Unable to create account' });
          }

          // Log user registration
          db.run(`INSERT INTO user_logs (id, user_id, action, details) VALUES (?, ?, ?, ?)`,
            [generateId(), userId, 'google_register', `User registered with Google: ${email}`]);

          const token = jwt.sign({ 
            id: userId, 
            email, 
            role: 'user' 
          }, JWT_SECRET, { expiresIn: '7d' });

          res.json({ 
            success: true, 
            token, 
            user: { 
              id: userId, 
              name, 
              email, 
              role: 'user',
              profile_picture: picture
            } 
          });
        });
    });
  } catch (error) {
    console.error('Google login error:', error);
    res.status(500).json({ error: 'Google authentication failed' });
  }
});

// Admin Login
app.post('/api/auth/admin/login', async (req, res) => {
  try {
    // Support both username and email fields
    const { username, password, email } = req.body;
    const loginId = username || email;
    
    console.log(`[ADMIN_LOGIN] Attempt with username: "${loginId}", password length: ${password ? password.length : 0}`);

    // Hardcoded admin credentials for simplicity
    if (loginId === 'admin2026' && password === 'admin2026') {
      console.log(`[ADMIN_LOGIN] Credentials matched for admin2026`);
      const adminId = 'admin-001';
      const token = jwt.sign({ 
        id: adminId, 
        email: 'admin@onehive.com', 
        role: 'admin',
        name: 'Administrator'
      }, JWT_SECRET, { expiresIn: '7d' });

      // Log admin login
      logAdminAction(adminId, 'admin_login', 'Admin logged in successfully');

      return res.json({ 
        success: true, 
        token, 
        user: { 
          id: adminId, 
          name: 'Administrator', 
          email: 'admin@onehive.com', 
          role: 'admin'
        } 
      });
    }

    console.log(`[ADMIN_LOGIN] Failed - username mismatch or password mismatch`);
    return res.status(401).json({ error: 'Invalid admin credentials' });
  } catch (error) {
    console.error('Admin login error:', error);
    res.status(500).json({ error: 'Server error during admin login' });
  }
});

// ==================== PASSWORD RESET ROUTES ====================

// Request password reset OTP
app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }
    
    // Check if email exists (but don't reveal this to prevent enumeration)
    db.get(`SELECT * FROM users WHERE email = ?`, [email], async (err, user) => {
      if (err) {
        logPasswordReset(email, 'ERROR', 'Database error checking email');
        return res.status(500).json({ error: 'Server error' });
      }
      
      // Generate OTP
      const otp = generateOTP();
      const otpHash = hashOTP(otp);
      const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString(); // 10 minutes
      
      // Invalidate any existing OTPs for this email
      db.run(`UPDATE password_reset_otps SET used = 1 WHERE email = ? AND used = 0`, [email]);
      
      // Store OTP
      const otpId = generateId();
      db.run(`INSERT INTO password_reset_otps (id, email, otp, otp_hash, expires_at) VALUES (?, ?, ?, ?, ?)`,
        [otpId, email, otp, otpHash, expiresAt],
        async (err) => {
          if (err) {
            logPasswordReset(email, 'ERROR', 'Failed to store OTP');
            return res.status(500).json({ error: 'Failed to generate OTP' });
          }
          
          // Send OTP via email
          await sendEmail(
            email,
            'OneHive Password Reset OTP',
            `Your OneHive password reset OTP is: ${otp}\n\nThis OTP will expire in 10 minutes.\n\nIf you didn't request this, please ignore this email.`
          );
          
          logPasswordReset(email, 'OTP_SENT', 'Password reset OTP sent successfully');
          
          res.json({ 
            success: true, 
            message: 'OTP sent to your email',
            // In production, don't include this - only for demo
            debug_otp: otp 
          });
        });
    });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Verify OTP
app.post('/api/auth/verify-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    
    if (!email || !otp) {
      return res.status(400).json({ error: 'Email and OTP are required' });
    }
    
    // Find valid OTP
    db.get(`SELECT * FROM password_reset_otps WHERE email = ? AND used = 0 AND expires_at > datetime('now') ORDER BY created_at DESC LIMIT 1`,
      [email], (err, otpRecord) => {
        if (err) {
          logPasswordReset(email, 'ERROR', 'Database error verifying OTP');
          return res.status(500).json({ error: 'Server error' });
        }
        
        if (!otpRecord) {
          logPasswordReset(email, 'OTP_FAILED', 'No valid OTP found or OTP expired');
          return res.status(400).json({ error: 'Invalid or expired OTP' });
        }
        
        // Verify OTP hash
        const otpHash = hashOTP(otp);
        if (otpRecord.otp_hash !== otpHash) {
          logPasswordReset(email, 'OTP_FAILED', 'Incorrect OTP entered');
          return res.status(400).json({ error: 'Incorrect OTP' });
        }
        
        // Mark OTP as used
        db.run(`UPDATE password_reset_otps SET used = 1 WHERE id = ?`, [otpRecord.id]);
        
        logPasswordReset(email, 'OTP_VERIFIED', 'OTP verified successfully');
        
        res.json({ 
          success: true, 
          message: 'OTP verified successfully',
          verified: true
        });
      });
  } catch (error) {
    console.error('Verify OTP error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Reset password
app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;
    
    if (!email || !otp || !newPassword) {
      return res.status(400).json({ error: 'Email, OTP, and new password are required' });
    }
    
    // Validate password strength
    if (newPassword.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    
    // Find valid OTP
    db.get(`SELECT * FROM password_reset_otps WHERE email = ? AND used = 1 AND otp = ? ORDER BY created_at DESC LIMIT 1`,
      [email, otp], (err, otpRecord) => {
        if (err) {
          logPasswordReset(email, 'ERROR', 'Database error resetting password');
          return res.status(500).json({ error: 'Server error' });
        }
        
        if (!otpRecord) {
          logPasswordReset(email, 'RESET_FAILED', 'Invalid OTP for password reset');
          return res.status(400).json({ error: 'Invalid request' });
        }
        
        // Hash new password
        const hashedPassword = bcrypt.hashSync(newPassword, 10);
        
        // Update password
        db.run(`UPDATE users SET password = ? WHERE email = ?`, [hashedPassword, email], (err) => {
          if (err) {
            logPasswordReset(email, 'ERROR', 'Failed to update password');
            return res.status(500).json({ error: 'Failed to reset password' });
          }
          
          // Invalidate all OTPs for this email
          db.run(`UPDATE password_reset_otps SET used = 1 WHERE email = ?`, [email]);
          
          logPasswordReset(email, 'PASSWORD_RESET_SUCCESS', 'Password reset successfully');
          
          res.json({ 
            success: true, 
            message: 'Password reset successfully'
          });
        });
      });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// ==================== USER ROUTES ====================

// Get user profile
app.get('/api/user/profile', authenticateToken, (req, res) => {
  db.get(`SELECT id, name, email, phone, role, profile_picture, address, latitude, longitude, created_at 
          FROM users WHERE id = ?`, [req.user.id], (err, user) => {
    if (err || !user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(user);
  });
});

// Update user profile
app.put('/api/user/profile', authenticateToken, (req, res) => {
  const { name, phone, address, latitude, longitude } = req.body;
  
  db.run(`UPDATE users SET name = ?, phone = ?, address = ?, latitude = ?, longitude = ?, updated_at = CURRENT_TIMESTAMP 
          WHERE id = ?`, [name, phone, address, latitude, longitude, req.user.id],
    function(err) {
      if (err) {
        return res.status(500).json({ error: 'Failed to update profile' });
      }
      res.json({ success: true, message: 'Profile updated successfully' });
    });
});

// Update user location
app.put('/api/user/location', authenticateToken, (req, res) => {
  const { latitude, longitude, address } = req.body;
  
  db.run(`UPDATE users SET latitude = ?, longitude = ?, address = ?, updated_at = CURRENT_TIMESTAMP 
          WHERE id = ?`, [latitude, longitude, address, req.user.id],
    function(err) {
      if (err) {
        return res.status(500).json({ error: 'Failed to update location' });
      }
      res.json({ success: true, message: 'Location updated successfully' });
    });
});

// ==================== WORKER ROUTES ====================

// Worker registration
app.post('/api/worker/register', authenticateToken, async (req, res) => {
  try {
    const { name, email, phone, service_type, city, area, experience, hourly_rate, bio } = req.body;
    
    const workerId = generateId();
    
    db.run(`INSERT INTO workers (id, user_id, name, email, phone, service_type, city, area, experience, hourly_rate, bio) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [workerId, req.user.id, name, email, phone, service_type, city, area, experience, hourly_rate, bio],
      function(err) {
        if (err) {
          console.error('Worker registration error:', err);
          return res.status(500).json({ error: 'Failed to register as worker' });
        }
        res.json({ success: true, worker_id: workerId, message: 'Worker registration successful' });
      });
  } catch (error) {
    console.error('Worker registration error:', error);
    res.status(500).json({ error: 'Server error during worker registration' });
  }
});

// Get worker profile
app.get('/api/worker/profile', authenticateToken, (req, res) => {
  db.get(`SELECT * FROM workers WHERE user_id = ?`, [req.user.id], (err, worker) => {
    if (err || !worker) {
      return res.status(404).json({ error: 'Worker profile not found' });
    }
    res.json(worker);
  });
});

// Update worker location
app.put('/api/worker/location', authenticateToken, (req, res) => {
  const { latitude, longitude } = req.body;
  
  db.get(`SELECT id FROM workers WHERE user_id = ?`, [req.user.id], (err, worker) => {
    if (err || !worker) {
      return res.status(404).json({ error: 'Worker not found' });
    }
    
    db.run(`UPDATE workers SET latitude = ?, longitude = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
      [latitude, longitude, worker.id],
      function(err) {
        if (err) {
          return res.status(500).json({ error: 'Failed to update location' });
        }
        
        // Log worker location update
        db.run(`INSERT INTO worker_logs (id, worker_id, action, details, latitude, longitude) VALUES (?, ?, ?, ?, ?, ?)`,
          [generateId(), worker.id, 'location_update', 'Worker updated location', latitude, longitude]);
        
        res.json({ success: true, message: 'Location updated successfully' });
      });
  });
});

// Get available workers
app.get('/api/workers', (req, res) => {
  const { service_type, city, latitude, longitude } = req.query;
  
  let query = `SELECT * FROM workers WHERE status = 'available' AND verified = 1`;
  const params = [];
  
  if (service_type) {
    query += ` AND service_type = ?`;
    params.push(service_type);
  }
  
  if (city) {
    query += ` AND city = ?`;
    params.push(city);
  }
  
  query += ` ORDER BY rating DESC, total_jobs DESC`;
  
  db.all(query, params, (err, workers) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to fetch workers' });
    }
    res.json(workers);
  });
});

// Update worker status
app.put('/api/worker/status', authenticateToken, (req, res) => {
  const { status } = req.body;
  
  db.get(`SELECT id FROM workers WHERE user_id = ?`, [req.user.id], (err, worker) => {
    if (err || !worker) {
      return res.status(404).json({ error: 'Worker not found' });
    }
    
    db.run(`UPDATE workers SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
      [status, worker.id],
      function(err) {
        if (err) {
          return res.status(500).json({ error: 'Failed to update status' });
        }
        
        // Log worker status change
        db.run(`INSERT INTO worker_logs (id, worker_id, action, details) VALUES (?, ?, ?, ?)`,
          [generateId(), worker.id, 'status_change', `Worker changed status to ${status}`]);
        
        res.json({ success: true, message: 'Status updated successfully' });
      });
  });
});

// ==================== SHOP ROUTES ====================

// Shop registration
app.post('/api/shop/register', authenticateToken, (req, res) => {
  const { name, email, phone, address, city, owner_name } = req.body;
  
  const shopId = generateId();
  
  db.run(`INSERT INTO shops (id, name, email, phone, address, city, owner_name) VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [shopId, name, email, phone, address, city, owner_name],
    function(err) {
      if (err) {
        console.error('Shop registration error:', err);
        return res.status(500).json({ error: 'Failed to register shop' });
      }
      res.json({ success: true, shop_id: shopId, message: 'Shop registration successful' });
    });
});

// Get shop profile
app.get('/api/shop/profile', authenticateToken, (req, res) => {
  db.get(`SELECT * FROM shops WHERE id = ?`, [req.user.id], (err, shop) => {
    if (err || !shop) {
      return res.status(404).json({ error: 'Shop not found' });
    }
    res.json(shop);
  });
});

// Add product
app.post('/api/shop/product', authenticateToken, (req, res) => {
  const { name, description, category, price, stock } = req.body;
  
  db.get(`SELECT id FROM shops WHERE owner_name = ?`, [req.user.name], (err, shop) => {
    if (err || !shop) {
      return res.status(404).json({ error: 'Shop not found' });
    }
    
    const productId = generateId();
    
    db.run(`INSERT INTO products (id, shop_id, name, description, category, price, stock) VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [productId, shop.id, name, description, category, price, stock],
      function(err) {
        if (err) {
          return res.status(500).json({ error: 'Failed to add product' });
        }
        res.json({ success: true, product_id: productId, message: 'Product added successfully' });
      });
  });
});

// Get shop products
app.get('/api/shop/products', authenticateToken, (req, res) => {
  db.get(`SELECT id FROM shops WHERE owner_name = ?`, [req.user.name], (err, shop) => {
    if (err || !shop) {
      return res.status(404).json({ error: 'Shop not found' });
    }
    
    db.all(`SELECT * FROM products WHERE shop_id = ?`, [shop.id], (err, products) => {
      if (err) {
        return res.status(500).json({ error: 'Failed to fetch products' });
      }
      res.json(products);
    });
  });
});

// Get shops by city
app.get('/api/shops', (req, res) => {
  const { city, latitude, longitude } = req.query;
  
  let query = `SELECT * FROM shops WHERE status = 'active'`;
  const params = [];
  
  if (city) {
    query += ` AND city = ?`;
    params.push(city);
  }
  
  query += ` ORDER BY rating DESC`;
  
  db.all(query, params, (err, shops) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to fetch shops' });
    }
    res.json(shops);
  });
});

// ==================== BOOKING ROUTES ====================

// Create booking
app.post('/api/booking/create', authenticateToken, (req, res) => {
  const { service_type, description, address, latitude, longitude, scheduled_date, scheduled_time, price_estimate } = req.body;
  
  // Validate required fields
  if (!latitude || !longitude) {
    return res.status(400).json({ error: 'Location is required. Please select location on map.' });
  }
  
  const bookingId = generateId();
  
  db.run(`INSERT INTO bookings (id, user_id, service_type, description, address, latitude, longitude, scheduled_date, scheduled_time, price_estimate, status) 
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')`,
    [bookingId, req.user.id, service_type, description, address, latitude, longitude, scheduled_date, scheduled_time, price_estimate],
    function(err) {
      if (err) {
        console.error('Booking creation error:', err);
        return res.status(500).json({ error: 'Failed to create booking' });
      }
      
      // Log booking creation
      logBookingAction(bookingId, 'created', `Booking created for ${service_type}`);
      
      // Broadcast job to all matching workers
      db.all(`SELECT * FROM workers WHERE service_type = ? AND city = (SELECT city FROM users WHERE id = ?) AND verified = 1 AND status = 'available'`,
        [service_type, req.user.id],
        (err, workers) => {
          if (!err && workers && workers.length > 0) {
            // Broadcast to all matching workers
            workers.forEach(worker => {
              io.to(`worker_${worker.id}`).emit('job_broadcast', {
                booking_id: bookingId,
                service_type,
                description,
                address,
                latitude,
                longitude,
                scheduled_date,
                scheduled_time,
                price_estimate,
                user_name: req.user.name,
                user_phone: 'XXX-XXX-XXXX' // Masked for privacy
              });
            });
          }
        });
      
      res.json({ success: true, booking_id: bookingId, message: 'Booking created successfully' });
    });
});

// Get user bookings
app.get('/api/bookings/user', authenticateToken, (req, res) => {
  db.all(`SELECT b.*, w.name as worker_name, w.phone as worker_phone, w.profile_picture as worker_picture, w.rating as worker_rating
          FROM bookings b 
          LEFT JOIN workers w ON b.worker_id = w.id 
          WHERE b.user_id = ? 
          ORDER BY b.created_at DESC`, [req.user.id], (err, bookings) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to fetch bookings' });
    }
    res.json(bookings);
  });
});

// Get worker bookings
app.get('/api/bookings/worker', authenticateToken, (req, res) => {
  db.get(`SELECT id FROM workers WHERE user_id = ?`, [req.user.id], (err, worker) => {
    if (err || !worker) {
      return res.status(404).json({ error: 'Worker not found' });
    }
    
    db.all(`SELECT b.*, u.name as user_name, u.phone as user_phone, u.profile_picture as user_picture
            FROM bookings b 
            LEFT JOIN users u ON b.user_id = u.id 
            WHERE b.worker_id = ? 
            ORDER BY b.created_at DESC`, [worker.id], (err, bookings) => {
      if (err) {
        return res.status(500).json({ error: 'Failed to fetch bookings' });
      }
      res.json(bookings);
    });
  });
});

// Accept booking (worker)
app.put('/api/booking/accept', authenticateToken, (req, res) => {
  const { booking_id } = req.body;
  
  db.get(`SELECT id FROM workers WHERE user_id = ?`, [req.user.id], (err, worker) => {
    if (err || !worker) {
      return res.status(404).json({ error: 'Worker not found' });
    }
    
    db.run(`UPDATE bookings SET worker_id = ?, status = 'accepted', updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
      [worker.id, booking_id],
      function(err) {
        if (err) {
          return res.status(500).json({ error: 'Failed to accept booking' });
        }
        
        // Log booking acceptance
        logBookingAction(booking_id, 'accepted', `Booking accepted by worker ${worker.id}`);
        
        // Notify user via socket
        io.to(`booking_${booking_id}`).emit('booking_updated', { booking_id, status: 'accepted' });
        
        res.json({ success: true, message: 'Booking accepted successfully' });
      });
  });
});

// Reject booking (worker)
app.put('/api/booking/reject', authenticateToken, (req, res) => {
  const { booking_id } = req.body;
  
  db.get(`SELECT id FROM workers WHERE user_id = ?`, [req.user.id], (err, worker) => {
    if (err || !worker) {
      return res.status(404).json({ error: 'Worker not found' });
    }
    
    db.run(`UPDATE bookings SET status = 'rejected', updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
      [booking_id],
      function(err) {
        if (err) {
          return res.status(500).json({ error: 'Failed to reject booking' });
        }
        
        logBookingAction(booking_id, 'rejected', `Booking rejected by worker ${worker.id}`);
        io.to(`booking_${booking_id}`).emit('booking_updated', { booking_id, status: 'rejected' });
        
        res.json({ success: true, message: 'Booking rejected' });
      });
  });
});

// Worker arrived
app.put('/api/booking/arrived', authenticateToken, (req, res) => {
  const { booking_id } = req.body;
  
  db.run(`UPDATE bookings SET worker_arrived_at = CURRENT_TIMESTAMP, status = 'arrived', updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
    [booking_id],
    function(err) {
      if (err) {
        return res.status(500).json({ error: 'Failed to update status' });
      }
      
      logBookingAction(booking_id, 'worker_arrived', 'Worker arrived at location');
      io.to(`booking_${booking_id}`).emit('booking_updated', { booking_id, status: 'arrived' });
      
      res.json({ success: true, message: 'Status updated to arrived' });
    });
});

// Start job
app.put('/api/booking/start', authenticateToken, (req, res) => {
  const { booking_id } = req.body;
  
  db.run(`UPDATE bookings SET job_started_at = CURRENT_TIMESTAMP, status = 'in_progress', updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
    [booking_id],
    function(err) {
      if (err) {
        return res.status(500).json({ error: 'Failed to start job' });
      }
      
      logBookingAction(booking_id, 'job_started', 'Job started');
      io.to(`booking_${booking_id}`).emit('booking_updated', { booking_id, status: 'in_progress' });
      
      res.json({ success: true, message: 'Job started successfully' });
    });
});

// Complete job
app.put('/api/booking/complete', authenticateToken, (req, res) => {
  const { booking_id, price_final, after_image } = req.body;
  
  db.run(`UPDATE bookings SET job_completed_at = CURRENT_TIMESTAMP, status = 'completed', price_final = ?, after_image = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
    [price_final, after_image, booking_id],
    function(err) {
      if (err) {
        return res.status(500).json({ error: 'Failed to complete job' });
      }
      
      logBookingAction(booking_id, 'job_completed', `Job completed with final price ${price_final}`);
      io.to(`booking_${booking_id}`).emit('booking_updated', { booking_id, status: 'completed', price_final });
      
      res.json({ success: true, message: 'Job completed successfully' });
    });
});

// Confirm completion (user)
app.put('/api/booking/confirm', authenticateToken, (req, res) => {
  const { booking_id, rating, review } = req.body;
  
  db.run(`UPDATE bookings SET rating_user = ?, review_user = ?, status = 'confirmed', updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
    [rating, review, booking_id],
    function(err) {
      if (err) {
        return res.status(500).json({ error: 'Failed to confirm completion' });
      }
      
      logBookingAction(booking_id, 'confirmed', 'User confirmed job completion');
      io.to(`booking_${booking_id}`).emit('booking_updated', { booking_id, status: 'confirmed' });
      
      res.json({ success: true, message: 'Job confirmed successfully' });
    });
});

// Cancel booking
app.put('/api/booking/cancel', authenticateToken, (req, res) => {
  const { booking_id, reason } = req.body;
  
  db.run(`UPDATE bookings SET status = 'cancelled', updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
    [booking_id],
    function(err) {
      if (err) {
        return res.status(500).json({ error: 'Failed to cancel booking' });
      }
      
      logBookingAction(booking_id, 'cancelled', `Booking cancelled: ${reason || 'No reason provided'}`);
      io.to(`booking_${booking_id}`).emit('booking_updated', { booking_id, status: 'cancelled' });
      
      res.json({ success: true, message: 'Booking cancelled successfully' });
    });
});

// Get booking details
app.get('/api/booking/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  
  db.get(`SELECT b.*, w.name as worker_name, w.phone as worker_phone, w.profile_picture as worker_picture, w.rating as worker_rating,
                 u.name as user_name, u.phone as user_phone, u.profile_picture as user_picture
          FROM bookings b 
          LEFT JOIN workers w ON b.worker_id = w.id 
          LEFT JOIN users u ON b.user_id = u.id 
          WHERE b.id = ?`, [id], (err, booking) => {
    if (err || !booking) {
      return res.status(404).json({ error: 'Booking not found' });
    }
    res.json(booking);
  });
});

// ==================== CHAT ROUTES ====================

// Send message
app.post('/api/message/send', authenticateToken, (req, res) => {
  const { booking_id, message, image_path } = req.body;
  
  const messageId = generateId();
  const senderType = req.user.role === 'worker' ? 'worker' : 'user';
  
  db.run(`INSERT INTO messages (id, booking_id, sender_id, sender_type, message, image_path) VALUES (?, ?, ?, ?, ?, ?)`,
    [messageId, booking_id, req.user.id, senderType, message, image_path],
    function(err) {
      if (err) {
        return res.status(500).json({ error: 'Failed to send message' });
      }
      
      // Emit to socket
      io.to(`booking_${booking_id}`).emit('new_message', {
        id: messageId,
        booking_id,
        sender_id: req.user.id,
        sender_type: senderType,
        message,
        image_path,
        created_at: new Date()
      });
      
      res.json({ success: true, message_id: messageId });
    });
});

// Get booking messages
app.get('/api/messages/:booking_id', authenticateToken, (req, res) => {
  const { booking_id } = req.params;
  
  db.all(`SELECT * FROM messages WHERE booking_id = ? ORDER BY created_at ASC`, [booking_id], (err, messages) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to fetch messages' });
    }
    res.json(messages);
  });
});

// ==================== RATING ROUTES ====================

// Submit rating
app.post('/api/rating/submit', authenticateToken, (req, res) => {
  const { booking_id, entity_id, entity_type, rating, review } = req.body;
  
  // Check if booking is completed
  db.get(`SELECT status FROM bookings WHERE id = ?`, [booking_id], (err, booking) => {
    if (err || !booking) {
      return res.status(404).json({ error: 'Booking not found' });
    }
    
    if (booking.status !== 'completed') {
      return res.status(400).json({ error: 'Can only rate completed bookings' });
    }
    
    // Check if already rated
    db.get(`SELECT id FROM ratings WHERE booking_id = ? AND entity_id = ?`, [booking_id, entity_id], (err, existing) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      
      if (existing) {
        return res.status(400).json({ error: 'Already rated this entity for this booking' });
      }
      
      const ratingId = generateId();
      
      db.run(`INSERT INTO ratings (id, booking_id, user_id, entity_id, entity_type, rating, review) VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [ratingId, booking_id, req.user.id, entity_id, entity_type, rating, review || ''],
        function(err) {
          if (err) {
            return res.status(500).json({ error: 'Failed to submit rating' });
          }
          
          // Update entity rating
          if (entity_type === 'worker') {
            db.get(`SELECT AVG(rating) as avg_rating, COUNT(*) as count FROM ratings WHERE entity_id = ? AND entity_type = 'worker'`, [entity_id], (err, result) => {
              if (!err && result) {
                db.run(`UPDATE workers SET rating = ?, total_jobs = total_jobs + 1 WHERE id = ?`, [result.avg_rating || rating, entity_id]);
              }
            });
          } else if (entity_type === 'shop') {
            db.get(`SELECT AVG(rating) as avg_rating, COUNT(*) as count FROM ratings WHERE entity_id = ? AND entity_type = 'shop'`, [entity_id], (err, result) => {
              if (!err && result) {
                db.run(`UPDATE shops SET rating = ? WHERE id = ?`, [result.avg_rating || rating, entity_id]);
              }
            });
          }
          
          res.json({ success: true, message: 'Rating submitted successfully' });
        });
    });
  });
});

// Get ratings for an entity
app.get('/api/ratings/:entity_type/:entity_id', (req, res) => {
  const { entity_type, entity_id } = req.params;
  
  db.all(`SELECT r.*, u.name as user_name FROM ratings r LEFT JOIN users u ON r.user_id = u.id WHERE r.entity_id = ? AND r.entity_type = ? ORDER BY r.created_at DESC`, 
    [entity_id, entity_type], (err, ratings) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to fetch ratings' });
    }
    res.json(ratings);
  });
});

// Check if user has rated a booking
app.get('/api/rating/check/:booking_id', authenticateToken, (req, res) => {
  const { booking_id } = req.params;
  
  db.all(`SELECT * FROM ratings WHERE booking_id = ? AND user_id = ?`, [booking_id, req.user.id], (err, ratings) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to check ratings' });
    }
    res.json(ratings);
  });
});

// ==================== JOB LOCK ROUTES (Call Before Accept) ====================

// Lock job for call before accept
app.post('/api/job/lock', authenticateToken, (req, res) => {
  const { booking_id } = req.body;
  const LOCK_DURATION = 120; // 120 seconds
  
  // Get worker ID from user
  db.get(`SELECT id FROM workers WHERE user_id = ?`, [req.user.id], (err, worker) => {
    if (err || !worker) {
      return res.status(404).json({ error: 'Worker not found' });
    }
    
    // Check if job is already locked by another worker
    db.get(`SELECT * FROM job_locks WHERE booking_id = ? AND status = 'locked' AND expires_at > datetime('now')`, 
      [booking_id], (err, existingLock) => {
        if (err) {
          return res.status(500).json({ error: 'Database error' });
        }
        
        if (existingLock) {
          if (existingLock.worker_id === worker.id) {
            // Already locked by this worker, return success with phone
            return res.json({ 
              success: true, 
              already_locked: true,
              expires_at: existingLock.expires_at
            });
          }
          return res.status(400).json({ error: 'Another worker is currently reviewing this job' });
        }
        
        // Create new lock
        const lockId = generateId();
        const expiresAt = new Date(Date.now() + LOCK_DURATION * 1000).toISOString();
        
        db.run(`INSERT INTO job_locks (id, booking_id, worker_id, expires_at) VALUES (?, ?, ?, ?)`,
          [lockId, booking_id, worker.id, expiresAt],
          function(err) {
            if (err) {
              return res.status(500).json({ error: 'Failed to lock job' });
            }
            
            // Get user phone for the worker
            db.get(`SELECT u.phone, u.name FROM bookings b JOIN users u ON b.user_id = u.id WHERE b.id = ?`, 
              [booking_id], (err, booking) => {
                // Notify other workers that job is being reviewed
                io.to(`booking_${booking_id}`).emit('job_locked', {
                  booking_id,
                  locked_by: worker.id,
                  worker_name: worker.name
                });
                
                res.json({ 
                  success: true, 
                  lock_id: lockId,
                  expires_at: expiresAt,
                  user_phone: booking ? booking.phone : null,
                  user_name: booking ? booking.name : null
                });
              });
          });
      });
  });
});

// Release job lock
app.post('/api/job/release', authenticateToken, (req, res) => {
  const { booking_id } = req.body;
  
  db.get(`SELECT id FROM workers WHERE user_id = ?`, [req.user.id], (err, worker) => {
    if (err || !worker) {
      return res.status(404).json({ error: 'Worker not found' });
    }
    
    db.run(`UPDATE job_locks SET status = 'released' WHERE booking_id = ? AND worker_id = ? AND status = 'locked'`,
      [booking_id, worker.id],
      function(err) {
        if (err) {
          return res.status(500).json({ error: 'Failed to release lock' });
        }
        
        // Notify other workers
        io.to(`booking_${booking_id}`).emit('job_released', {
          booking_id,
          worker_id: worker.id
        });
        
        res.json({ success: true, message: 'Job lock released' });
      });
  });
});

// Check job lock status
app.get('/api/job/lock/:booking_id', authenticateToken, (req, res) => {
  const { booking_id } = req.params;
  
  db.get(`SELECT jl.*, w.name as worker_name FROM job_locks jl 
          LEFT JOIN workers w ON jl.worker_id = w.id 
          WHERE jl.booking_id = ? AND jl.status = 'locked' AND jl.expires_at > datetime('now')`, 
    [booking_id], (err, lock) => {
      if (err) {
        return res.status(500).json({ error: 'Failed to check lock' });
      }
      res.json(lock || null);
    });
});

// ==================== PAYMENT ROUTES ====================

// Create payment
app.post('/api/payment/create', authenticateToken, (req, res) => {
  const { booking_id, amount, method } = req.body;
  
  const paymentId = generateId();
  const transactionId = 'TXN-' + Date.now();
  
  db.run(`INSERT INTO payments (id, booking_id, user_id, amount, method, transaction_id) VALUES (?, ?, ?, ?, ?, ?)`,
    [paymentId, booking_id, req.user.id, amount, method, transactionId],
    function(err) {
      if (err) {
        return res.status(500).json({ error: 'Failed to create payment' });
      }
      
      db.run(`UPDATE bookings SET payment_method = ?, payment_status = 'processing' WHERE id = ?`,
        [method, booking_id]);
      
      res.json({ success: true, payment_id: paymentId, transaction_id: transactionId });
    });
});

// Update payment status
app.put('/api/payment/status', authenticateToken, (req, res) => {
  const { payment_id, status } = req.body;
  
  db.run(`UPDATE payments SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
    [status, payment_id],
    function(err) {
      if (err) {
        return res.status(500).json({ error: 'Failed to update payment status' });
      }
      
      // Get booking_id and update booking payment status
      db.get(`SELECT booking_id FROM payments WHERE id = ?`, [payment_id], (err, payment) => {
        if (payment) {
          const bookingStatus = status === 'completed' ? 'paid' : 'payment_failed';
          db.run(`UPDATE bookings SET payment_status = ? WHERE id = ?`, [bookingStatus, payment.booking_id]);
        }
      });
      
      res.json({ success: true, message: 'Payment status updated' });
    });
});

// ==================== ADMIN ROUTES ====================

// Get all users
app.get('/api/admin/users', authenticateAdmin, (req, res) => {
  db.all(`SELECT id, name, email, phone, role, created_at FROM users ORDER BY created_at DESC`, (err, users) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to fetch users' });
    }
    res.json(users);
  });
});

// Get all workers
app.get('/api/admin/workers', authenticateAdmin, (req, res) => {
  db.all(`SELECT * FROM workers ORDER BY created_at DESC`, (err, workers) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to fetch workers' });
    }
    res.json(workers);
  });
});

// Verify worker
app.put('/api/admin/worker/verify', authenticateAdmin, (req, res) => {
  const { worker_id, verified } = req.body;
  
  // If rejecting, set status to 'rejected'. If verifying, set status to 'available' and verified to 1
  const status = verified ? 'available' : 'rejected';
  
  db.run(`UPDATE workers SET verified = ?, status = ? WHERE id = ?`, [verified ? 1 : 0, status, worker_id],
    function(err) {
      if (err) {
        return res.status(500).json({ error: 'Failed to update worker verification' });
      }
      
      logAdminAction(req.user.id, 'worker_verify', `Worker ${worker_id} verification status: ${verified ? 'verified' : 'rejected'}`);
      
      res.json({ success: true, message: verified ? 'Worker verified successfully' : 'Worker rejected' });
    });
});

// Get all shops
app.get('/api/admin/shops', authenticateAdmin, (req, res) => {
  db.all(`SELECT * FROM shops ORDER BY created_at DESC`, (err, shops) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to fetch shops' });
    }
    res.json(shops);
  });
});

// Get all bookings (admin)
app.get('/api/admin/bookings', authenticateAdmin, (req, res) => {
  const { status, date_from, date_to } = req.query;
  
  let query = `SELECT b.*, u.name as user_name, w.name as worker_name 
               FROM bookings b 
               LEFT JOIN users u ON b.user_id = u.id 
               LEFT JOIN workers w ON b.worker_id = w.id 
               WHERE 1=1`;
  const params = [];
  
  if (status) {
    query += ` AND b.status = ?`;
    params.push(status);
  }
  
  if (date_from) {
    query += ` AND b.created_at >= ?`;
    params.push(date_from);
  }
  
  if (date_to) {
    query += ` AND b.created_at <= ?`;
    params.push(date_to);
  }
  
  query += ` ORDER BY b.created_at DESC`;
  
  db.all(query, params, (err, bookings) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to fetch bookings' });
    }
    res.json(bookings);
  });
});

// Get settings
app.get('/api/admin/settings', authenticateAdmin, (req, res) => {
  db.all(`SELECT * FROM settings`, (err, settings) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to fetch settings' });
    }
    
    const settingsObj = {};
    settings.forEach(s => {
      settingsObj[s.key] = s.value;
    });
    
    res.json(settingsObj);
  });
});

// Update settings
app.put('/api/admin/settings', authenticateAdmin, (req, res) => {
  const settings = req.body;
  
  const keys = Object.keys(settings);
  const values = Object.values(settings);
  
  keys.forEach((key, index) => {
    db.run(`INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)`,
      [key, values[index]]);
  });
  
  logAdminAction(req.user.id, 'settings_update', `Updated settings: ${keys.join(', ')}`);
  
  res.json({ success: true, message: 'Settings updated successfully' });
});

// Test email configuration
app.post('/api/admin/test-email', authenticateAdmin, async (req, res) => {
  const { testEmail } = req.body;
  
  if (!testEmail) {
    return res.status(400).json({ error: 'Test email address required' });
  }
  
  try {
    const result = await sendEmail(
      testEmail,
      'OneHive Email Test',
      `<div style="font-family: Arial, sans-serif; padding: 20px; max-width: 600px;">
        <h2 style="color: #F59E0B;"><i className="fas fa-cube"></i> OneHive Email Test</h2>
        <p>Hello,</p>
        <p>This is a test email from OneHive to verify your email configuration.</p>
        <p>If you received this email, your SMTP settings are working correctly!</p>
        <p><strong>Timestamp:</strong> ${new Date().toISOString()}</p>
        <hr style="border: 1px solid #E5E7EB; margin: 20px 0;">
        <p style="color: #6B7280; font-size: 12px;">This is an automated message from OneHive Platform</p>
      </div>`
    );
    
    logAdminAction(req.user.id, 'test_email', `Sent test email to ${testEmail}`);
    
    if (result.success) {
      res.json({ success: true, message: result.simulated ? 'Test email simulated (no password configured)' : 'Test email sent successfully!' });
    } else {
      res.status(500).json({ error: result.message });
    }
  } catch (err) {
    console.error('[TEST EMAIL ERROR]', err);
    res.status(500).json({ error: err.message });
  }
});

// Get admin logs
app.get('/api/admin/logs', authenticateAdmin, (req, res) => {
  const { type, limit = 100 } = req.query;
  
  let table = 'admin_logs';
  if (type === 'booking') table = 'booking_logs';
  else if (type === 'user') table = 'user_logs';
  else if (type === 'worker') table = 'worker_logs';
  
  db.all(`SELECT * FROM ${table} ORDER BY created_at DESC LIMIT ?`, [limit], (err, logs) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to fetch logs' });
    }
    res.json(logs);
  });
});

// Delete user
app.delete('/api/admin/user/:email', authenticateAdmin, (req, res) => {
  const { email } = req.params;
  
  db.run(`DELETE FROM users WHERE email = ?`, [email], function(err) {
    if (err) {
      return res.status(500).json({ error: 'Failed to delete user' });
    }
    
    logAdminAction(req.user.id, 'user_delete', `Deleted user: ${email}`);
    res.json({ success: true, message: 'User deleted successfully' });
  });
});

// Get analytics
app.get('/api/admin/analytics', authenticateAdmin, (req, res) => {
  const analytics = {};
  
  db.get(`SELECT COUNT(*) as total FROM users`, (err, result) => {
    analytics.totalUsers = result.total;
    
    db.get(`SELECT COUNT(*) as total FROM workers`, (err, result) => {
      analytics.totalWorkers = result.total;
      
      db.get(`SELECT COUNT(*) as total FROM shops`, (err, result) => {
        analytics.totalShops = result.total;
        
        db.get(`SELECT COUNT(*) as total FROM bookings`, (err, result) => {
          analytics.totalBookings = result.total;
          
          db.get(`SELECT SUM(price_final) as total FROM bookings WHERE status IN ('completed', 'confirmed')`, (err, result) => {
            analytics.totalRevenue = result.total || 0;
            
            db.get(`SELECT COUNT(*) as total FROM bookings WHERE status = 'pending'`, (err, result) => {
              analytics.pendingBookings = result.total;
              
              res.json(analytics);
            });
          });
        });
      });
    });
  });
});

// ==================== SERVICES ROUTES ====================

// Get service types
app.get('/api/services', (req, res) => {
  const services = [
    { id: 'plumbing', name: 'Plumbing', icon: 'fa-solid fa-faucet-drip', description: 'Water pipe repairs, leak fixes, installation' },
    { id: 'electrical', name: 'Electrical', icon: 'fa-solid fa-bolt', description: 'Wiring, switchboard, fan repair' },
    { id: 'cleaning', name: 'Home Cleaning', icon: 'fa-solid fa-broom', description: 'Deep cleaning, regular cleaning, sanitization' },
    { id: 'painting', name: 'Painting', icon: 'fa-solid fa-paint-roller', description: 'Interior, exterior, texture painting' },
    { id: 'carpentry', name: 'Carpentry', icon: 'fa-solid fa-hammer', description: 'Furniture repair, installation, custom work' },
    { id: 'ac_repair', name: 'AC Repair', icon: 'fa-solid fa-snowflake', description: 'AC servicing, gas refill, repair' },
    { id: 'appliance', name: 'Appliance Repair', icon: 'fa-solid fa-plug', description: 'Refrigerator, washing machine, microwave' },
    { id: 'pest_control', name: 'Pest Control', icon: 'fa-solid fa-bug', description: 'Cockroaches, termites, bed bugs' },
    { id: 'gardening', name: 'Gardening', icon: 'fa-solid fa-leaf', description: 'Lawn care, plant maintenance' },
    { id: 'moving', name: 'Moving & Shifting', icon: 'fa-solid fa-boxes-packing', description: 'Home shifting, packing, loading' }
  ];
  res.json(services);
});

// Get cities
app.get('/api/cities', (req, res) => {
  const cities = [
    { id: 'mumbai', name: 'Mumbai', state: 'Maharashtra' },
    { id: 'delhi', name: 'Delhi', state: 'Delhi' },
    { id: 'bangalore', name: 'Bangalore', state: 'Karnataka' },
    { id: 'chennai', name: 'Chennai', state: 'Tamil Nadu' },
    { id: 'hyderabad', name: 'Hyderabad', state: 'Telangana' },
    { id: 'kolkata', name: 'Kolkata', state: 'West Bengal' },
    { id: 'pune', name: 'Pune', state: 'Maharashtra' },
    { id: 'ahmedabad', name: 'Ahmedabad', state: 'Gujarat' }
  ];
  res.json(cities);
});

// ==================== FILE UPLOAD ====================

app.post('/api/upload', upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }
  res.json({ 
    success: true, 
    file_path: `/uploads/${req.file.filename}`,
    file_name: req.file.filename
  });
});

// ==================== SOCKET.IO ====================

io.on('connection', (socket) => {
  console.log('User connected:', socket.id);

  // Join booking room
  socket.on('join_booking', (booking_id) => {
    socket.join(`booking_${booking_id}`);
    console.log(`Socket ${socket.id} joined booking_${booking_id}`);
  });

  // Leave booking room
  socket.on('leave_booking', (booking_id) => {
    socket.leave(`booking_${booking_id}`);
  });

  // Worker location update
  socket.on('worker_location', (data) => {
    const { booking_id, latitude, longitude } = data;
    io.to(`booking_${booking_id}`).emit('worker_location_update', { latitude, longitude });
    
    // Log worker location
    db.get(`SELECT worker_id FROM bookings WHERE id = ?`, [booking_id], (err, booking) => {
      if (booking && booking.worker_id) {
        db.run(`INSERT INTO worker_logs (id, worker_id, action, details, latitude, longitude) VALUES (?, ?, ?, ?, ?, ?)`,
          [generateId(), booking.worker_id, 'location_tracking', 'Live location update', latitude, longitude]);
      }
    });
  });

  socket.on('disconnect', () => {
    console.log('User disconnected:', socket.id);
  });
});

// ==================== AI ASSISTANT ====================

app.post('/api/ai/chat', authenticateToken, (req, res) => {
  const { message, context } = req.body;
  
  // Simple AI response logic
  let response = '';
  const lowerMessage = message.toLowerCase();
  
  if (lowerMessage.includes('leak') || lowerMessage.includes('water')) {
    response = 'It sounds like you have a plumbing issue. Our plumbers can help fix leaks, pipe bursts, and water pressure problems. Would you like to book a plumber?';
  } else if (lowerMessage.includes('electrical') || lowerMessage.includes('power') || lowerMessage.includes('wire')) {
    response = 'I understand you have an electrical issue. Our certified electricians can handle wiring, switchboard, and electrical repairs safely. Should I help you book an electrician?';
  } else if (lowerMessage.includes('clean')) {
    response = 'We offer home cleaning services including deep cleaning, regular cleaning, and sanitization. How often would you like the cleaning service?';
  } else if (lowerMessage.includes('ac') || lowerMessage.includes('air condition')) {
    response = 'Our AC technicians provide servicing, gas refill, and repair for all AC brands. What is the issue with your AC?';
  } else if (lowerMessage.includes('painting') || lowerMessage.includes('paint')) {
    response = 'We offer interior and exterior painting services with professional finish. Would you like to schedule a painting consultation?';
  } else if (lowerMessage.includes('book') || lowerMessage.includes('service')) {
    response = 'I can help you book a service. Please tell me what type of service you need and your location.';
  } else if (lowerMessage.includes('price') || lowerMessage.includes('cost') || lowerMessage.includes('charge')) {
    response = 'Pricing depends on the type of service, complexity, and materials needed. Once you describe your problem, I can provide an estimated cost range.';
  } else {
    response = 'I\'m here to help you with home services. Could you describe the problem you\'re facing in more detail?';
  }
  
  res.json({ 
    success: true, 
    response,
    suggestions: ['Book a service', 'Get a quote', 'Talk to support']
  });
});

// ==================== PRICE ESTIMATION ====================

app.post('/api/price/estimate', (req, res) => {
  const { service_type, description, city } = req.body;
  
  // Base prices
  const basePrices = {
    plumbing: { min: 300, max: 800 },
    electrical: { min: 350, max: 900 },
    cleaning: { min: 500, max: 2000 },
    painting: { min: 2000, max: 10000 },
    carpentry: { min: 400, max: 1500 },
    ac_repair: { min: 500, max: 2000 },
    appliance: { min: 300, max: 1500 },
    pest_control: { min: 800, max: 3000 },
    gardening: { min: 400, max: 1500 },
    moving: { min: 3000, max: 15000 }
  };
  
  const price = basePrices[service_type] || { min: 300, max: 1000 };
  
  res.json({
    success: true,
    estimate: {
      min: price.min,
      max: price.max,
      currency: 'INR'
    },
    breakdown: {
      labor: Math.round((price.min + price.max) / 4),
      materials: Math.round((price.min + price.max) / 4),
      convenience: Math.round((price.min + price.max) / 4),
      tax: Math.round((price.min + price.max) / 8)
    }
  });
});

// ==================== WORKER MATCHING ====================

app.post('/api/workers/match', (req, res) => {
  const { service_type, city, latitude, longitude } = req.body;
  
  let query = `SELECT * FROM workers WHERE service_type = ? AND city = ? AND verified = 1 AND status = 'available'`;
  const params = [service_type, city];
  
  db.all(query, params, (err, workers) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to match workers' });
    }
    
    // Calculate distance and sort by rating
    workers = workers.map(w => {
      let distance = 0;
      if (latitude && longitude && w.latitude && w.longitude) {
        distance = Math.sqrt(
          Math.pow(latitude - w.latitude, 2) + 
          Math.pow(longitude - w.longitude, 2)
        );
      }
      return { ...w, distance, score: (w.rating * 10) - distance };
    });
    
    workers.sort((a, b) => b.score - a.score);
    
    res.json({ success: true, workers: workers.slice(0, 5) });
  });
});

// ==================== HERO SLIDER API ====================

// Get all hero slider images (public)
app.get('/api/hero-slider', (req, res) => {
  db.all(`SELECT * FROM hero_slider WHERE is_enabled = 1 ORDER BY order_index ASC`, [], (err, slides) => {
    if (err) {
      console.error('[Hero Slider] Error fetching slides:', err);
      return res.status(500).json({ error: 'Failed to fetch slider images' });
    }
    res.json({ success: true, slides: slides || [] });
  });
});

// Get all hero slider images (admin)
app.get('/api/admin/hero-slider', adminAuth, (req, res) => {
  db.all(`SELECT * FROM hero_slider ORDER BY order_index ASC`, [], (err, slides) => {
    if (err) {
      console.error('[Hero Slider] Error fetching slides:', err);
      return res.status(500).json({ error: 'Failed to fetch slider images' });
    }
    res.json({ success: true, slides: slides || [] });
  });
});

// Add hero slider image (admin) - with file upload
app.post('/api/admin/hero-slider', adminAuth, upload.single('image'), (req, res) => {
  console.log('[Hero Slider] Upload request:', req.file, req.body);
  
  const { title, subtitle, order_index } = req.body;
  let imageUrl = req.body.image_url; // Fallback to URL if no file
  
  // If file was uploaded, use the file path
  if (req.file) {
    imageUrl = `/uploads/${req.file.filename}`;
    console.log('[Hero Slider] File uploaded:', imageUrl);
  }
  
  if (!imageUrl) {
    return res.status(400).json({ error: 'Image file or URL is required' });
  }
  
  // Get max order
  db.get(`SELECT MAX(order_index) as max_order FROM hero_slider`, [], (err, row) => {
    const maxOrder = row?.max_order || 0;
    const id = generateId();
    
    db.run(
      `INSERT INTO hero_slider (id, image_url, title, subtitle, order_index, is_enabled) VALUES (?, ?, ?, ?, ?, 1)`,
      [id, image_url, title || '', subtitle || '', order_index || maxOrder + 1],
      function(err) {
        if (err) {
          console.error('[Hero Slider] Error adding slide:', err);
          return res.status(500).json({ error: 'Failed to add slider image' });
        }
        
        // Log admin action
        db.run(`INSERT INTO admin_logs (id, admin_id, action, details) VALUES (?, ?, ?, ?)`,
          [generateId(), req.adminId, 'hero_slider_add', `Added hero slider image: ${image_url}`]);
        
        res.json({ success: true, id, message: 'Slider image added successfully' });
      }
    );
  });
});

// Update hero slider image (admin)
app.put('/api/admin/hero-slider/:id', adminAuth, (req, res) => {
  const { id } = req.params;
  const { image_url, title, subtitle, order_index, is_enabled } = req.body;
  
  const updates = [];
  const values = [];
  
  if (image_url) {
    updates.push('image_url = ?');
    values.push(image_url);
  }
  if (title !== undefined) {
    updates.push('title = ?');
    values.push(title);
  }
  if (subtitle !== undefined) {
    updates.push('subtitle = ?');
    values.push(subtitle);
  }
  if (order_index !== undefined) {
    updates.push('order_index = ?');
    values.push(order_index);
  }
  if (is_enabled !== undefined) {
    updates.push('is_enabled = ?');
    values.push(is_enabled ? 1 : 0);
  }
  
  if (updates.length === 0) {
    return res.status(400).json({ error: 'No fields to update' });
  }
  
  values.push(id);
  
  db.run(
    `UPDATE hero_slider SET ${updates.join(', ')} WHERE id = ?`,
    values,
    function(err) {
      if (err) {
        console.error('[Hero Slider] Error updating slide:', err);
        return res.status(500).json({ error: 'Failed to update slider image' });
      }
      
      // Log admin action
      db.run(`INSERT INTO admin_logs (id, admin_id, action, details) VALUES (?, ?, ?, ?)`,
        [generateId(), req.adminId, 'hero_slider_update', `Updated hero slider image: ${id}`]);
      
      res.json({ success: true, message: 'Slider image updated successfully' });
    }
  );
});

// Delete hero slider image (admin)
app.delete('/api/admin/hero-slider/:id', adminAuth, (req, res) => {
  const { id } = req.params;
  
  db.run(`DELETE FROM hero_slider WHERE id = ?`, [id], function(err) {
    if (err) {
      console.error('[Hero Slider] Error deleting slide:', err);
      return res.status(500).json({ error: 'Failed to delete slider image' });
    }
    
    // Log admin action
    db.run(`INSERT INTO admin_logs (id, admin_id, action, details) VALUES (?, ?, ?, ?)`,
      [generateId(), req.adminId, 'hero_slider_delete', `Deleted hero slider image: ${id}`]);
    
    res.json({ success: true, message: 'Slider image deleted successfully' });
  });
});

// Reorder hero slider images (admin)
app.post('/api/admin/hero-slider/reorder', adminAuth, (req, res) => {
  const { ordered_ids } = req.body;
  
  if (!ordered_ids || !Array.isArray(ordered_ids)) {
    return res.status(400).json({ error: 'Ordered IDs array is required' });
  }
  
  ordered_ids.forEach((id, index) => {
    db.run(`UPDATE hero_slider SET order_index = ? WHERE id = ?`, [index, id]);
  });
  
  // Log admin action
  db.run(`INSERT INTO admin_logs (id, admin_id, action, details) VALUES (?, ?, ?, ?)`,
    [generateId(), req.adminId, 'hero_slider_reorder', `Reordered hero slider images`]);
  
  res.json({ success: true, message: 'Slider images reordered successfully' });
});

// Start server
server.listen(PORT, () => {
  console.log(`OneHive server running on port ${PORT}`);
});
