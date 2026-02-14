import React, { useState, useEffect, createContext, useContext } from 'react';
import { BrowserRouter as Router, Routes, Route, Link, useNavigate, useLocation, Navigate, useParams } from 'react-router-dom';
import axios from 'axios';
import ShopAuthPage from './ShopAuth';
import OneHiveLogo from './components/Logo';
import LocationMap, { reverseGeocode } from './components/LocationMap';
import HeroSlider from './components/HeroSlider';

// API Base URL - Use environment variable or fallback to localhost
// For GitHub Pages deployment, set REACT_APP_API_URL in build process
const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:3001/api';
const UPLOADS_URL = process.env.REACT_APP_UPLOADS_URL || 'http://localhost:3001/uploads';

// Auth Context
const AuthContext = createContext(null);

// Axios setup
axios.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// API Functions
const api = {
  // Auth
  register: (data) => axios.post(`${API_URL}/auth/register`, data),
  login: (data) => axios.post(`${API_URL}/auth/login`, data),
  googleLogin: (token) => axios.post(`${API_URL}/auth/google`, { token }),
  adminLogin: (data) => axios.post(`${API_URL}/auth/admin/login`, data),
  forgotPassword: (email) => axios.post(`${API_URL}/auth/forgot-password`, { email }),
  verifyOTP: (email, otp) => axios.post(`${API_URL}/auth/verify-otp`, { email, otp }),
  resetPassword: (email, otp, newPassword) => axios.post(`${API_URL}/auth/reset-password`, { email, otp, newPassword }),
  
  // User
  getProfile: () => axios.get(`${API_URL}/user/profile`),
  updateProfile: (data) => axios.put(`${API_URL}/user/profile`, data),
  updateLocation: (data) => axios.put(`${API_URL}/user/location`, data),
  
  // Services
  getServices: () => axios.get(`${API_URL}/services`),
  getCities: () => axios.get(`${API_URL}/cities`),
  
  // Workers
  getWorkers: (params) => axios.get(`${API_URL}/workers`, { params }),
  getWorkerProfile: () => axios.get(`${API_URL}/worker/profile`),
  registerWorker: (data) => axios.post(`${API_URL}/worker/register`, data),
  updateWorkerLocation: (data) => axios.put(`${API_URL}/worker/location`, data),
  updateWorkerStatus: (status) => axios.put(`${API_URL}/worker/status`, { status }),
  matchWorkers: (data) => axios.post(`${API_URL}/workers/match`, data),
  
  // Shops
  getShops: (params) => axios.get(`${API_URL}/shops`, { params }),
  registerShop: (data) => axios.post(`${API_URL}/shop/register`, data),
  getShopProducts: () => axios.get(`${API_URL}/shop/products`),
  addProduct: (data) => axios.post(`${API_URL}/shop/product`, data),
  
  // Bookings
  createBooking: (data) => axios.post(`${API_URL}/booking/create`, data),
  getUserBookings: () => axios.get(`${API_URL}/bookings/user`),
  getWorkerBookings: () => axios.get(`${API_URL}/bookings/worker`),
  getBooking: (id) => axios.get(`${API_URL}/booking/${id}`),
  acceptBooking: (id) => axios.put(`${API_URL}/booking/accept`, { booking_id: id }),
  rejectBooking: (id) => axios.put(`${API_URL}/booking/reject`, { booking_id: id }),
  arrivedBooking: (id) => axios.put(`${API_URL}/booking/arrived`, { booking_id: id }),
  startBooking: (id) => axios.put(`${API_URL}/booking/start`, { booking_id: id }),
  completeBooking: (id, data) => axios.put(`${API_URL}/booking/complete`, { booking_id: id, ...data }),
  confirmBooking: (id, data) => axios.put(`${API_URL}/booking/confirm`, { booking_id: id, ...data }),
  cancelBooking: (id) => axios.put(`${API_URL}/booking/cancel`, { booking_id: id }),
  
  // Messages
  sendMessage: (data) => axios.post(`${API_URL}/message/send`, data),
  getMessages: (bookingId) => axios.get(`${API_URL}/messages/${bookingId}`),
  
  // Payment
  createPayment: (data) => axios.post(`${API_URL}/payment/create`, data),
  
  // Ratings
  submitRating: (data) => axios.post(`${API_URL}/rating/submit`, data),
  getRatings: (entityType, entityId) => axios.get(`${API_URL}/ratings/${entityType}/${entityId}`),
  checkRating: (bookingId) => axios.get(`${API_URL}/rating/check/${bookingId}`),
  
  // Job Lock (Call Before Accept)
  lockJob: (bookingId) => axios.post(`${API_URL}/job/lock`, { booking_id: bookingId }),
  releaseJob: (bookingId) => axios.post(`${API_URL}/job/release`, { booking_id: bookingId }),
  checkJobLock: (bookingId) => axios.get(`${API_URL}/job/lock/${bookingId}`),
  
  // Price
  estimatePrice: (data) => axios.post(`${API_URL}/price/estimate`, data),
  
  // AI
  aiChat: (data) => axios.post(`${API_URL}/ai/chat`, data),
  
  // Admin
  getUsers: () => axios.get(`${API_URL}/admin/users`),
  getAdminWorkers: () => axios.get(`${API_URL}/admin/workers`),
  verifyWorker: (id, verified) => axios.put(`${API_URL}/admin/worker/verify`, { worker_id: id, verified }),
  getAdminShops: () => axios.get(`${API_URL}/admin/shops`),
  getAdminBookings: (params) => axios.get(`${API_URL}/admin/bookings`, { params }),
  getSettings: () => axios.get(`${API_URL}/admin/settings`),
  updateSettings: (data) => axios.put(`${API_URL}/admin/settings`, data),
  
  // Hero Slider
  getHeroSlider: () => axios.get(`${API_URL}/hero-slider`),
  getAdminHeroSlider: () => axios.get(`${API_URL}/admin/hero-slider`),
  addHeroSlider: (data) => axios.post(`${API_URL}/admin/hero-slider`, data),
  updateHeroSlider: (id, data) => axios.put(`${API_URL}/admin/hero-slider/${id}`, data),
  deleteHeroSlider: (id) => axios.delete(`${API_URL}/admin/hero-slider/${id}`),
  reorderHeroSlider: (ordered_ids) => axios.post(`${API_URL}/admin/hero-slider/reorder`, { ordered_ids }),
  testEmail: (testEmail) => axios.post(`${API_URL}/admin/test-email`, { testEmail }),
  getAdminLogs: (type) => axios.get(`${API_URL}/admin/logs`, { params: { type } }),
  getAnalytics: () => axios.get(`${API_URL}/admin/analytics`),
  
  // Upload
  upload: (file) => {
    const formData = new FormData();
    formData.append('file', file);
    return axios.post(`${API_URL}/upload`, formData, { headers: { 'Content-Type': 'multipart/form-data' } });
  }
};

// Loading Spinner
const LoadingSpinner = () => (
  <div className="loading-container">
    <div className="spinner"></div>
  </div>
);

// Alert Component
const Alert = ({ type, message }) => (
  <div className={`alert alert-${type}`}>
    <i className={`fas fa-${type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-circle' : type === 'warning' ? 'exclamation-triangle' : 'info-circle'}`}></i>
    {message}
  </div>
);

// Auth Provider
const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = localStorage.getItem('token');
    const savedUser = localStorage.getItem('user');
    if (token && savedUser) {
      setUser(JSON.parse(savedUser));
    }
    setLoading(false);
  }, []);

  const login = (token, userData) => {
    localStorage.setItem('token', token);
    localStorage.setItem('user', JSON.stringify(userData));
    setUser(userData);
  };

  const logout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    setUser(null);
  };

  const updateUser = (userData) => {
    setUser(userData);
    localStorage.setItem('user', JSON.stringify(userData));
  };

  return (
    <AuthContext.Provider value={{ user, login, logout, updateUser, loading }}>
      {children}
    </AuthContext.Provider>
  );
};

const useAuth = () => useContext(AuthContext);

// ==================== LANDING PAGE ====================
const LandingPage = () => {
  const [services, setServices] = useState([]);
  const navigate = useNavigate();

  useEffect(() => {
    api.getServices().then(res => setServices(res.data)).catch(err => console.error(err));
  }, []);

  return (
    <div>
      {/* Navigation Bar */}
      <nav className="navbar" style={{ position: 'relative', background: 'white', boxShadow: '0 2px 10px rgba(0,0,0,0.1)' }}>
        <div className="navbar-container" style={{ maxWidth: '1200px', margin: '0 auto', padding: '0 20px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', cursor: 'pointer' }} onClick={() => navigate('/')}>
            <OneHiveLogo size="medium" />
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '30px' }}>
            <a href="#services" style={{ color: '#2D3436', fontWeight: '500', textDecoration: 'none' }}>Services</a>
            <a href="#about" style={{ color: '#2D3436', fontWeight: '500', textDecoration: 'none' }}>About</a>
            <a href="#contact" style={{ color: '#2D3436', fontWeight: '500', textDecoration: 'none' }}>Contact</a>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <button className="btn btn-outline" onClick={() => navigate('/auth')}>Login</button>
            <button className="btn btn-primary" onClick={() => navigate('/auth')}>Get Started</button>
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <section className="hero">
        <div className="hero-container">
          <div className="hero-content">
            <h1>Home Services at <span>Your Doorstep</span></h1>
            <p>Professional workers, shops, and services all in one place. Like a beehive, we bring everything together for you.</p>
            <div className="hero-buttons">
              <button className="btn btn-primary btn-lg" onClick={() => navigate('/auth')}>
                Get Started <i className="fas fa-arrow-right"></i>
              </button>
              <button className="btn btn-secondary btn-lg" onClick={() => navigate('/worker/auth')}>
                Become a Worker
              </button>
            </div>
          </div>
          <div className="hero-image">
            <HeroSlider />
          </div>
        </div>
      </section>

      {/* Services Section */}
      <section className="services-section">
        <div className="container">
          <div className="section-title">
            <h2>Our Services</h2>
            <p>Choose from a wide range of professional services</p>
          </div>
          <div className="services-grid">
            {services.map(service => (
              <div key={service.id} className="service-card" onClick={() => navigate('/auth')}>
                <div className="service-icon"><i className={service.icon}></i></div>
                <h3 className="service-name">{service.name}</h3>
                <p className="service-description">{service.description}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section style={{ padding: '48px 0', background: 'white' }}>
        <div className="container">
          <div className="section-title">
            <h2>Why Choose OneHive?</h2>
          </div>
          <div className="stats-grid" style={{ marginTop: '32px' }}>
            <div className="stat-card">
              <div className="stat-card-icon"><i className="fas fa-users"></i></div>
              <div className="stat-card-value">10K+</div>
              <div className="stat-card-label">Verified Workers</div>
            </div>
            <div className="stat-card">
              <div className="stat-card-icon"><i className="fas fa-store"></i></div>
              <div className="stat-card-value">500+</div>
              <div className="stat-card-label">Partner Shops</div>
            </div>
            <div className="stat-card">
              <div className="stat-card-icon"><i className="fas fa-star"></i></div>
              <div className="stat-card-value">4.8</div>
              <div className="stat-card-label">Average Rating</div>
            </div>
            <div className="stat-card">
              <div className="stat-card-icon"><i className="fas fa-calendar-check"></i></div>
              <div className="stat-card-value">50K+</div>
              <div className="stat-card-label">Jobs Completed</div>
            </div>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="footer">
        <div className="footer-container">
          <div className="footer-grid">
            <div>
              <h4 className="footer-title">OneHive</h4>
              <p style={{ color: '#aaa' }}>Your trusted hyperlocal service marketplace. Professional workers and shops all in one place.</p>
            </div>
            <div>
              <h4 className="footer-title">Quick Links</h4>
              <ul className="footer-links">
                <li><Link to="/auth">Login</Link></li>
                <li><Link to="/auth">Register</Link></li>
                <li><Link to="/worker/auth">Become a Worker</Link></li>
                <li><Link to="/shop/auth">Register Shop</Link></li>
              </ul>
            </div>
            <div>
              <h4 className="footer-title">Services</h4>
              <ul className="footer-links">
                <li><a href="#">Plumbing</a></li>
                <li><a href="#">Electrical</a></li>
                <li><a href="#">Cleaning</a></li>
                <li><a href="#">More...</a></li>
              </ul>
            </div>
            <div>
              <h4 className="footer-title">Contact</h4>
              <ul className="footer-links">
                <li><i className="fas fa-phone"></i> +91 9876543210</li>
                <li><i className="fas fa-envelope"></i> support@onehive.com</li>
                <li><i className="fas fa-map-marker"></i> Mumbai, India</li>
              </ul>
            </div>
          </div>
          <div className="footer-bottom">
            <p>© 2026 OneHive. All rights reserved.</p>
          </div>
        </div>
      </footer>
    </div>
  );
};

// ==================== AUTH PAGE ====================
const AuthPage = () => {
  const [isLogin, setIsLogin] = useState(true);
  const [userType, setUserType] = useState('user'); // user, worker, shop
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [formData, setFormData] = useState({
    name: '', email: '', password: '', phone: '', service_type: '', city: '', experience: '', hourly_rate: '', shop_name: '', owner_name: '', address: ''
  });
  const { login } = useAuth();
  const navigate = useNavigate();

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      if (isLogin) {
        const res = await api.login({ email: formData.email, password: formData.password });
        login(res.data.token, res.data.user);
        // Redirect based on role
        if (res.data.user.role === 'worker') {
          navigate('/worker/dashboard');
        } else if (res.data.user.role === 'shop') {
          navigate('/shop/dashboard');
        } else {
          navigate('/dashboard');
        }
      } else {
        const res = await api.register({ ...formData, role: userType });
        
        // If worker or shop, also create their profile
        if (userType === 'worker') {
          await api.registerWorker({ name: formData.name, email: formData.email, phone: formData.phone, service_type: formData.service_type, city: formData.city, experience: formData.experience, hourly_rate: formData.hourly_rate });
        } else if (userType === 'shop') {
          await api.registerShop({ name: formData.shop_name, email: formData.email, phone: formData.phone, address: formData.address, city: formData.city, owner_name: formData.owner_name });
        }
        
        login(res.data.token, res.data.user);
        if (userType === 'worker') navigate('/worker/dashboard');
        else if (userType === 'shop') navigate('/shop/dashboard');
        else navigate('/dashboard');
      }
    } catch (err) {
      setError(err.response?.data?.error || 'An error occurred');
    } finally {
      setLoading(false);
    }
  };

  const handleGoogleLogin = () => {
    const clientId = process.env.REACT_APP_GOOGLE_CLIENT_ID || '275974330696-82d02rjco30v42a58ghan11ra98lvdf2.apps.googleusercontent.com';
    
    console.log('[Google Login] Starting Google login flow...');
    
    // Check if Google OAuth2 is loaded
    if (!window.google?.accounts?.oauth2) {
      console.error('[Google Login] Google OAuth2 not loaded');
      setError('Google Login is not available. Please refresh the page and try again.');
      return;
    }
    
    // Use OAuth2 popup directly - more reliable than One Tap
    try {
      const client = window.google.accounts.oauth2.initTokenClient({
        client_id: clientId,
        scope: 'email profile openid',
        ux_mode: 'popup',
        callback: (response) => {
          console.log('[Google Login] OAuth2 callback triggered:', response);
          
          if (response.access_token) {
            console.log('[Google Login] Access token received, calling backend...');
            api.googleLogin(response.access_token)
              .then((res) => {
                console.log('[Google Login] Backend success:', res.data);
                if (res.data.success) {
                  login(res.data.token, res.data.user);
                  navigate('/');
                } else {
                  setError(res.data.error || 'Google login failed');
                }
              })
              .catch((err) => {
                console.error('[Google Login] Backend error:', err);
                setError(err.response?.data?.error || 'Failed to connect to server');
              });
          } else if (response.error) {
            console.log('[Google Login] OAuth Error:', response.error);
            if (response.error !== 'access_denied') {
              setError('Google login was cancelled or failed');
            }
          } else {
            console.log('[Google Login] No access token in response');
            setError('No access token received from Google');
          }
        },
      });
      
      console.log('[Google Login] Requesting access token...');
      client.requestAccessToken();
    } catch (err) {
      console.error('[Google Login] Init error:', err);
      setError('Google Login is not available. Please try again or use email login.');
    }
  };

  return (
    <div className="auth-page">
      <div className="auth-container">
        <div className="auth-header">
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: '20px' }}>
            <OneHiveLogo size="large" />
          </div>
          <h1>{isLogin ? 'Welcome Back' : 'Join OneHive'}</h1>
          <p>{isLogin ? 'Sign in to continue' : 'Create your account'}</p>
        </div>

        {error && <Alert type="error" message={error} />}

        {/* User Type Selector */}
        {!isLogin && (
          <div className="form-group">
            <label className="form-label">I want to join as:</label>
            <div style={{ display: 'flex', gap: '8px' }}>
              <button type="button" className={`btn ${userType === 'user' ? 'btn-primary' : 'btn-outline'}`} style={{ flex: 1 }} onClick={() => setUserType('user')}>
                <i className="fas fa-user"></i> Customer
              </button>
              <button type="button" className={`btn ${userType === 'worker' ? 'btn-primary' : 'btn-outline'}`} style={{ flex: 1 }} onClick={() => setUserType('worker')}>
                <i className="fas fa-tools"></i> Worker
              </button>
              <button type="button" className={`btn ${userType === 'shop' ? 'btn-primary' : 'btn-outline'}`} style={{ flex: 1 }} onClick={() => setUserType('shop')}>
                <i className="fas fa-store"></i> Shop
              </button>
            </div>
          </div>
        )}

        <div className="auth-tabs">
          <button className={`auth-tab ${isLogin ? 'active' : ''}`} onClick={() => setIsLogin(true)}>Login</button>
          <button className={`auth-tab ${!isLogin ? 'active' : ''}`} onClick={() => setIsLogin(false)}>Register</button>
        </div>

        <form onSubmit={handleSubmit}>
          {!isLogin && (
            <>
              <div className="form-group">
                <label className="form-label">Full Name</label>
                <input type="text" name="name" className="form-input" placeholder="Enter your name" value={formData.name} onChange={handleChange} />
              </div>
              
              {userType === 'shop' && (
                <div className="form-group">
                  <label className="form-label">Shop Name</label>
                  <input type="text" name="shop_name" className="form-input" placeholder="Enter shop name" value={formData.shop_name} onChange={handleChange} />
                </div>
              )}
              
              {userType === 'worker' && (
                <>
                  <div className="form-group">
                    <label className="form-label">Service Type</label>
                    <select name="service_type" className="form-select" value={formData.service_type} onChange={handleChange}>
                      <option value="">Select service</option>
                      <option value="plumbing">Plumbing</option>
                      <option value="electrical">Electrical</option>
                      <option value="cleaning">Home Cleaning</option>
                      <option value="painting">Painting</option>
                      <option value="carpentry">Carpentry</option>
                      <option value="ac_repair">AC Repair</option>
                      <option value="appliance">Appliance Repair</option>
                    </select>
                  </div>
                  <div className="form-group">
                    <label className="form-label">City</label>
                    <select name="city" className="form-select" value={formData.city} onChange={handleChange}>
                      <option value="">Select city</option>
                      <option value="mumbai">Mumbai</option>
                      <option value="delhi">Delhi</option>
                      <option value="bangalore">Bangalore</option>
                      <option value="chennai">Chennai</option>
                      <option value="pune">Pune</option>
                    </select>
                  </div>
                  <div className="form-group">
                    <label className="form-label">Experience (years)</label>
                    <input type="number" name="experience" className="form-input" placeholder="Years of experience" value={formData.experience} onChange={handleChange} />
                  </div>
                  <div className="form-group">
                    <label className="form-label">Hourly Rate (₹)</label>
                    <input type="number" name="hourly_rate" className="form-input" placeholder="Your hourly rate" value={formData.hourly_rate} onChange={handleChange} />
                  </div>
                </>
              )}
              
              {userType === 'shop' && (
                <>
                  <div className="form-group">
                    <label className="form-label">Owner Name</label>
                    <input type="text" name="owner_name" className="form-input" placeholder="Enter owner name" value={formData.owner_name} onChange={handleChange} />
                  </div>
                  <div className="form-group">
                    <label className="form-label">City</label>
                    <select name="city" className="form-select" value={formData.city} onChange={handleChange}>
                      <option value="">Select city</option>
                      <option value="mumbai">Mumbai</option>
                      <option value="delhi">Delhi</option>
                      <option value="bangalore">Bangalore</option>
                      <option value="chennai">Chennai</option>
                      <option value="pune">Pune</option>
                    </select>
                  </div>
                  <div className="form-group">
                    <label className="form-label">Address</label>
                    <textarea name="address" className="form-textarea" placeholder="Enter shop address" value={formData.address} onChange={handleChange}></textarea>
                  </div>
                </>
              )}
              
              {!isLogin && (
                <div className="form-group">
                  <label className="form-label">Phone Number</label>
                  <input type="tel" name="phone" className="form-input" placeholder="Enter your phone number" value={formData.phone} onChange={handleChange} />
                </div>
              )}
            </>
          )}
          <div className="form-group">
            <label className="form-label">Email Address</label>
            <input type="email" name="email" className="form-input" placeholder="Enter your email" value={formData.email} onChange={handleChange} required />
          </div>
          <div className="form-group">
            <label className="form-label">Password</label>
            <input type="password" name="password" className="form-input" placeholder="Enter your password" value={formData.password} onChange={handleChange} required />
          </div>
          <button type="submit" className="btn btn-primary" style={{ width: '100%' }} disabled={loading}>
            {loading ? <LoadingSpinner /> : (isLogin ? 'Sign In' : 'Create Account')}
          </button>
        </form>

        <div className="auth-divider">
          <span>OR</span>
        </div>

        <button className="google-btn" onClick={handleGoogleLogin}>
          <i className="fab fa-google"></i>
          Continue with Google
        </button>

        <p style={{ textAlign: 'center', marginTop: '24px', color: '#636E72' }}>
          {isLogin ? "Don't have an account? " : "Already have an account? "}
          <Link to={isLogin ? "/auth" : "/auth"} style={{ color: '#D4A574', fontWeight: '500' }} onClick={(e) => { e.preventDefault(); setIsLogin(!isLogin); }}>
            {isLogin ? 'Register' : 'Login'}
          </Link>
        </p>

        {isLogin && (
          <p style={{ textAlign: 'center', marginTop: '12px' }}>
            <Link to="/forgot-password" style={{ color: '#D4A574', fontSize: '0.9rem' }}>
              <i className="fas fa-lock"></i> Forgot Password?
            </Link>
          </p>
        )}

        <p style={{ textAlign: 'center', marginTop: '16px' }}>
          <Link to="/admin/auth" style={{ color: '#636E72', fontSize: '0.85rem' }}>
            <i className="fas fa-shield-alt"></i> Admin Login
          </Link>
        </p>
      </div>
    </div>
  );
};


// ==================== FORGOT PASSWORD ====================
const ForgotPasswordPage = () => {
  const [step, setStep] = useState(1); // 1: email, 2: OTP, 3: new password
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [email, setEmail] = useState('');
  const [otp, setOtp] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [resendTimer, setResendTimer] = useState(0);
  const navigate = useNavigate();

  useEffect(() => {
    if (resendTimer > 0) {
      const timer = setTimeout(() => setResendTimer(resendTimer - 1), 1000);
      return () => clearTimeout(timer);
    }
  }, [resendTimer]);

  const handleSendOTP = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const res = await api.forgotPassword(email);
      setSuccess('OTP sent to your email!');
      setStep(2);
      setResendTimer(60);
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to send OTP');
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyOTP = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      await api.verifyOTP(email, otp);
      setSuccess('OTP verified!');
      setStep(3);
    } catch (err) {
      setError(err.response?.data?.error || 'Invalid OTP');
    } finally {
      setLoading(false);
    }
  };

  const handleResetPassword = async (e) => {
    e.preventDefault();
    setError('');

    if (newPassword !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    if (newPassword.length < 6) {
      setError('Password must be at least 6 characters');
      return;
    }

    setLoading(true);

    try {
      await api.resetPassword(email, otp, newPassword);
      setSuccess('Password reset successfully!');
      setTimeout(() => navigate('/auth'), 2000);
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to reset password');
    } finally {
      setLoading(false);
    }
  };

  const resendOTP = async () => {
    if (resendTimer > 0) return;
    setError('');
    setLoading(true);
    try {
      await api.forgotPassword(email);
      setSuccess('OTP resent!');
      setResendTimer(60);
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to resend OTP');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-page">
      <div className="auth-container">
        <div className="auth-header">
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: '20px' }}>
            <OneHiveLogo size="large" />
          </div>
          <h1>
            {step === 1 && 'Reset Password'}
            {step === 2 && 'Verify OTP'}
            {step === 3 && 'New Password'}
          </h1>
          <p>
            {step === 1 && 'Enter your email to receive OTP'}
            {step === 2 && 'Enter the OTP sent to your email'}
            {step === 3 && 'Enter your new password'}
          </p>
        </div>

        {error && <div className="alert alert-error" style={{ marginBottom: '16px', padding: '12px', background: '#fee', color: '#c00', borderRadius: '8px' }}>{error}</div>}
        {success && <div className="alert alert-success" style={{ marginBottom: '16px', padding: '12px', background: '#efe', color: '#060', borderRadius: '8px' }}>{success}</div>}

        {step === 1 && (
          <form onSubmit={handleSendOTP}>
            <div className="form-group">
              <label className="form-label">Email Address</label>
              <input type="email" className="form-input" placeholder="Enter your email" value={email} onChange={(e) => setEmail(e.target.value)} required />
            </div>
            <button type="submit" className="btn btn-primary" style={{ width: '100%' }} disabled={loading}>
              {loading ? <LoadingSpinner /> : 'Send OTP'}
            </button>
          </form>
        )}

        {step === 2 && (
          <form onSubmit={handleVerifyOTP}>
            <div className="form-group">
              <label className="form-label">Enter OTP</label>
              <input type="text" className="form-input" placeholder="6-digit OTP" value={otp} onChange={(e) => setOtp(e.target.value)} maxLength={6} required />
            </div>
            <button type="submit" className="btn btn-primary" style={{ width: '100%' }} disabled={loading}>
              {loading ? <LoadingSpinner /> : 'Verify OTP'}
            </button>
            <div style={{ marginTop: '16px', textAlign: 'center' }}>
              <button type="button" className="btn btn-link" onClick={resendOTP} disabled={resendTimer > 0} style={{ background: 'none', border: 'none', color: resendTimer > 0 ? '#999' : '#D4A574', cursor: resendTimer > 0 ? 'not-allowed' : 'pointer' }}>
                {resendTimer > 0 ? `Resend OTP in ${resendTimer}s` : 'Resend OTP'}
              </button>
            </div>
          </form>
        )}

        {step === 3 && (
          <form onSubmit={handleResetPassword}>
            <div className="form-group">
              <label className="form-label">New Password</label>
              <input type="password" className="form-input" placeholder="Enter new password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} required />
            </div>
            <div className="form-group">
              <label className="form-label">Confirm Password</label>
              <input type="password" className="form-input" placeholder="Confirm new password" value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} required />
            </div>
            <button type="submit" className="btn btn-primary" style={{ width: '100%' }} disabled={loading}>
              {loading ? <LoadingSpinner /> : 'Reset Password'}
            </button>
          </form>
        )}

        <p style={{ textAlign: 'center', marginTop: '24px' }}>
          <Link to="/auth" style={{ color: '#D4A574' }}>← Back to Login</Link>
        </p>
      </div>
    </div>
  );
};

// ==================== ADMIN AUTH ====================
const AdminAuthPage = () => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [formData, setFormData] = useState({ username: '', password: '' });
  const { login } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const res = await api.adminLogin(formData);
      login(res.data.token, res.data.user);
      navigate('/admin');
    } catch (err) {
      setError(err.response?.data?.error || 'Invalid credentials');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-page">
      <div className="auth-container">
        <div className="auth-header">
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: '20px' }}>
            <OneHiveLogo size="large" />
          </div>
          <h1>Admin Login</h1>
          <p>Access the admin dashboard</p>
        </div>

        {error && <Alert type="error" message={error} />}

        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label className="form-label">Username</label>
            <input type="text" name="username" className="form-input" placeholder="Enter username" value={formData.username} onChange={(e) => setFormData({ ...formData, username: e.target.value })} required />
          </div>
          <div className="form-group">
            <label className="form-label">Password</label>
            <input type="password" name="password" className="form-input" placeholder="Enter password" value={formData.password} onChange={(e) => setFormData({ ...formData, password: e.target.value })} required />
          </div>
          <button type="submit" className="btn btn-primary" style={{ width: '100%' }} disabled={loading}>
            {loading ? <LoadingSpinner /> : 'Login as Admin'}
          </button>
        </form>

        <p style={{ textAlign: 'center', marginTop: '24px' }}>
          <Link to="/" style={{ color: '#D4A574' }}>← Back to Home</Link>
        </p>
      </div>
    </div>
  );
};

// ==================== USER DASHBOARD ====================
const UserDashboard = () => {
  const [bookings, setBookings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [selectedService, setSelectedService] = useState(null);
  const [services, setServices] = useState([]);
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      const [bookingsRes, servicesRes] = await Promise.all([
        api.getUserBookings(),
        api.getServices()
      ]);
      setBookings(bookingsRes.data);
      setServices(servicesRes.data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const getStatusClass = (status) => {
    const statusMap = {
      'pending': 'pending',
      'accepted': 'accepted',
      'arrived': 'accepted',
      'in_progress': 'accepted',
      'completed': 'completed',
      'confirmed': 'completed',
      'cancelled': 'cancelled'
    };
    return statusMap[status] || 'pending';
  };

  return (
    <div className="dashboard">
      <aside className="dashboard-sidebar">
        <div className="dashboard-logo">
          <i className="fas fa-bee"></i> OneHive
        </div>
        <ul className="dashboard-menu">
          <li className="dashboard-menu-item">
            <a className="dashboard-menu-link active"><i className="fas fa-home"></i> Dashboard</a>
          </li>
          <li className="dashboard-menu-item">
            <a className="dashboard-menu-link" onClick={() => setShowModal(true)}><i className="fas fa-plus-circle"></i> New Booking</a>
          </li>
          <li className="dashboard-menu-item">
            <a className="dashboard-menu-link" onClick={() => navigate('/user/bookings')}><i className="fas fa-calendar"></i> My Bookings</a>
          </li>
          <li className="dashboard-menu-item">
            <a className="dashboard-menu-link"><i className="fas fa-user"></i> Profile</a>
          </li>
          <li className="dashboard-menu-item">
            <a className="dashboard-menu-link" onClick={logout}><i className="fas fa-sign-out-alt"></i> Logout</a>
          </li>
        </ul>
      </aside>

      <main className="dashboard-main">
        <div className="dashboard-header">
          <h2>Welcome, {user?.name}</h2>
          <button className="btn btn-primary" onClick={() => setShowModal(true)}>
            <i className="fas fa-plus"></i> New Booking
          </button>
        </div>

        <div className="dashboard-content">
          {/* Stats */}
          <div className="stats-grid">
            <div className="stat-card">
              <div className="stat-card-icon"><i className="fas fa-calendar-check"></i></div>
              <div className="stat-card-value">{bookings.filter(b => b.status === 'completed' || b.status === 'confirmed').length}</div>
              <div className="stat-card-label">Completed Jobs</div>
            </div>
            <div className="stat-card">
              <div className="stat-card-icon"><i className="fas fa-clock"></i></div>
              <div className="stat-card-value">{bookings.filter(b => b.status === 'pending' || b.status === 'accepted').length}</div>
              <div className="stat-card-label">Active Bookings</div>
            </div>
            <div className="stat-card">
              <div className="stat-card-icon"><i className="fas fa-star"></i></div>
              <div className="stat-card-value">4.8</div>
              <div className="stat-card-label">Your Rating</div>
            </div>
          </div>

          {/* Recent Bookings */}
          <h3 style={{ marginBottom: '16px' }}>Recent Bookings</h3>
          {loading ? <LoadingSpinner /> : bookings.length === 0 ? (
            <div className="empty-state">
              <i className="fas fa-calendar-plus"></i>
              <h3>No bookings yet</h3>
              <p>Create your first booking to get started</p>
              <button className="btn btn-primary" onClick={() => setShowModal(true)}>Create Booking</button>
            </div>
          ) : (
            <div className="bookings-grid">
              {bookings.slice(0, 6).map(booking => (
                <div key={booking.id} className="booking-card">
                  <div className="booking-header">
                    <span className="booking-service">{booking.service_type}</span>
                    <span className={`booking-status ${getStatusClass(booking.status)}`}>{booking.status}</span>
                  </div>
                  <div className="booking-body">
                    <div className="booking-info">
                      <p><i className="fas fa-map-marker-alt"></i> {booking.address || 'No address'}</p>
                      <p><i className="fas fa-calendar"></i> {booking.scheduled_date} at {booking.scheduled_time}</p>
                      <p><i className="fas fa-rupee-sign"></i> ₹{booking.price_estimate || 'Pending'}</p>
                    </div>
                  </div>
                  <div className="booking-footer">
                    <button className="btn btn-sm btn-secondary" onClick={() => navigate(`/booking/${booking.id}`)}>View Details</button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </main>

      {/* Service Selection Modal */}
      {showModal && (
        <div className="modal-overlay" onClick={() => setShowModal(false)}>
          <div className="modal" onClick={e => e.stopPropagation()} style={{ maxWidth: '800px' }}>
            <div className="modal-header">
              <h3 className="modal-title">Select a Service</h3>
              <button className="modal-close" onClick={() => setShowModal(false)}>×</button>
            </div>
            <div className="modal-body">
              <div className="services-grid">
                {services.map(service => (
                  <div key={service.id} className="service-card" onClick={() => { setSelectedService(service); setShowModal(false); navigate('/booking/create', { state: { service } }); }}>
                    <div className="service-icon"><i className={service.icon}></i></div>
                    <h3 className="service-name">{service.name}</h3>
                    <p className="service-description">{service.description}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

// ==================== CREATE BOOKING ====================
const CreateBooking = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const { user } = useAuth();
  
  const [step, setStep] = useState(1);
  const [loading, setLoading] = useState(false);
  const [services, setServices] = useState([]);
  const [cities, setCities] = useState([]);
  const [workers, setWorkers] = useState([]);
  const [priceEstimate, setPriceEstimate] = useState(null);
  const [showMapModal, setShowMapModal] = useState(false);
  const [mapCenter, setMapCenter] = useState({ lat: 19.0760, lng: 72.8777 }); // Default Mumbai
  
  const [formData, setFormData] = useState({
    service_type: location.state?.service?.id || '',
    description: '',
    address: '',
    city: '',
    latitude: '',
    longitude: '',
    scheduled_date: '',
    scheduled_time: ''
  });

  useEffect(() => {
    const loadData = async () => {
      try {
        const [servicesRes, citiesRes] = await Promise.all([
          api.getServices(),
          api.getCities()
        ]);
        setServices(servicesRes.data);
        setCities(citiesRes.data);
      } catch (err) {
        console.error(err);
      }
    };
    loadData();
  }, []);

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const getPriceEstimate = async () => {
    if (!formData.service_type) return;
    try {
      const res = await api.estimatePrice({ service_type: formData.service_type, city: formData.city });
      setPriceEstimate(res.data);
    } catch (err) {
      console.error(err);
    }
  };

  const findWorkers = async () => {
    if (!formData.service_type || !formData.city) return;
    try {
      const res = await api.matchWorkers({
        service_type: formData.service_type,
        city: formData.city,
        latitude: formData.latitude,
        longitude: formData.longitude
      });
      setWorkers(res.data.workers);
    } catch (err) {
      console.error(err);
    }
  };

  const handleSubmit = async () => {
    setLoading(true);
    try {
      const res = await api.createBooking(formData);
      navigate(`/booking/${res.data.booking_id}`);
    } catch (err) {
      console.error(err);
      alert('Failed to create booking');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="dashboard">
      <aside className="dashboard-sidebar">
        <div className="dashboard-logo">
          <i className="fas fa-bee"></i> OneHive
        </div>
        <ul className="dashboard-menu">
          <li className="dashboard-menu-item">
            <a className="dashboard-menu-link" onClick={() => navigate('/dashboard')}><i className="fas fa-home"></i> Dashboard</a>
          </li>
          <li className="dashboard-menu-item">
            <a className="dashboard-menu-link" onClick={() => navigate('/user/bookings')}><i className="fas fa-calendar"></i> My Bookings</a>
          </li>
          <li className="dashboard-menu-item">
            <a className="dashboard-menu-link" onClick={() => navigate('/')}><i className="fas fa-sign-out-alt"></i> Logout</a>
          </li>
        </ul>
      </aside>

      <main className="dashboard-main">
        <div className="dashboard-header">
          <h2>Create New Booking</h2>
        </div>

        <div className="dashboard-content">
          {/* Steps */}
          <div className="tabs">
            <button className={`tab ${step >= 1 ? 'active' : ''}`}>1. Service</button>
            <button className={`tab ${step >= 2 ? 'active' : ''}`}>2. Location</button>
            <button className={`tab ${step >= 3 ? 'active' : ''}`}>3. Schedule</button>
            <button className={`tab ${step >= 4 ? 'active' : ''}`}>4. Confirm</button>
          </div>

          {/* Step 1: Service */}
          {step === 1 && (
            <div className="card">
              <h3 className="card-title">Select Service</h3>
              <div className="form-group">
                <label className="form-label">Service Type</label>
                <select name="service_type" className="form-select" value={formData.service_type} onChange={handleChange}>
                  <option value="">Select a service</option>
                  {services.map(s => <option key={s.id} value={s.id}>{s.icon} {s.name}</option>)}
                </select>
              </div>
              <div className="form-group">
                <label className="form-label">Describe Your Problem</label>
                <textarea name="description" className="form-textarea" placeholder="Describe what you need help with..." value={formData.description} onChange={handleChange}></textarea>
              </div>
              <button className="btn btn-primary" onClick={() => { getPriceEstimate(); setStep(2); }} disabled={!formData.service_type}>
                Next <i className="fas fa-arrow-right"></i>
              </button>
            </div>
          )}

          {/* Step 2: Location */}
          {step === 2 && (
            <div className="card">
              <h3 className="card-title">Location Details</h3>
              <div className="form-group">
                <label className="form-label">City</label>
                <select name="city" className="form-select" value={formData.city} onChange={handleChange}>
                  <option value="">Select city</option>
                  {cities.map(c => <option key={c.id} value={c.id}>{c.name}</option>)}
                </select>
              </div>
              <div className="form-group">
                <label className="form-label">Address</label>
                <textarea name="address" className="form-textarea" placeholder="Enter your full address..." value={formData.address} onChange={handleChange}></textarea>
              </div>
              <div className="form-group">
                <label className="form-label">Pin Location on Map <span style={{ color: 'red' }}>*</span></label>
                <div style={{ height: '200px', background: '#E8E6E3', borderRadius: '10px', display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: '12px' }}>
                  {formData.latitude && formData.longitude ? (
                    <>
                      <p style={{ color: 'var(--success)' }}><i className="fas fa-check-circle"></i> Location pinned</p>
                      <p style={{ fontSize: '12px', color: '#666' }}>Lat: {formData.latitude}, Lng: {formData.longitude}</p>
                    </>
                  ) : (
                    <p style={{ color: '#636E72' }}>Please pin your location</p>
                  )}
                  <button type="button" className="btn btn-primary" onClick={() => setShowMapModal(true)}>
                    <i className="fas fa-map-marker-alt"></i> {formData.latitude ? 'Change Location' : 'Select Location on Map'}
                  </button>
                </div>
                {!formData.latitude && <p style={{ color: 'red', fontSize: '12px', marginTop: '8px' }}>Location is required. Please select your location on the map.</p>}
              </div>
              <button className="btn btn-primary" onClick={() => { findWorkers(); setStep(3); }} disabled={!formData.city || !formData.address || !formData.latitude}>
                Next <i className="fas fa-arrow-right"></i>
              </button>
            </div>
          )}

          {/* Step 3: Schedule */}
          {step === 3 && (
            <div className="card">
              <h3 className="card-title">Schedule</h3>
              <div className="form-group">
                <label className="form-label">Date</label>
                <input type="date" name="scheduled_date" className="form-input" value={formData.scheduled_date} onChange={handleChange} min={new Date().toISOString().split('T')[0]} />
              </div>
              <div className="form-group">
                <label className="form-label">Time</label>
                <select name="scheduled_time" className="form-select" value={formData.scheduled_time} onChange={handleChange}>
                  <option value="">Select time</option>
                  <option value="09:00">09:00 AM</option>
                  <option value="10:00">10:00 AM</option>
                  <option value="11:00">11:00 AM</option>
                  <option value="12:00">12:00 PM</option>
                  <option value="14:00">02:00 PM</option>
                  <option value="15:00">03:00 PM</option>
                  <option value="16:00">04:00 PM</option>
                  <option value="17:00">05:00 PM</option>
                </select>
              </div>

              {priceEstimate && (
                <div className="price-estimate">
                  <h4>Price Estimate</h4>
                  <div className="price-range">₹{priceEstimate.estimate.min} - ₹{priceEstimate.estimate.max}</div>
                  <div className="price-breakdown">
                    <div className="price-item"><span>Labor</span><span>₹{priceEstimate.breakdown.labor}</span></div>
                    <div className="price-item"><span>Materials</span><span>₹{priceEstimate.breakdown.materials}</span></div>
                    <div className="price-item"><span>Convenience Fee</span><span>₹{priceEstimate.breakdown.convenience}</span></div>
                    <div className="price-item total"><span>Total (approx)</span><span>₹{priceEstimate.estimate.min + priceEstimate.breakdown.tax} - ₹{priceEstimate.estimate.max + priceEstimate.breakdown.tax}</span></div>
                  </div>
                </div>
              )}

              <button className="btn btn-primary" onClick={() => setStep(4)} disabled={!formData.scheduled_date || !formData.scheduled_time}>
                Next <i className="fas fa-arrow-right"></i>
              </button>
            </div>
          )}

          {/* Step 4: Confirm */}
          {step === 4 && (
            <div className="card">
              <h3 className="card-title">Confirm Booking</h3>
              
              <div style={{ marginBottom: '24px' }}>
                <p><strong>Service:</strong> {services.find(s => s.id === formData.service_type)?.name}</p>
                <p><strong>Description:</strong> {formData.description}</p>
                <p><strong>Address:</strong> {formData.address}</p>
                <p><strong>Date:</strong> {formData.scheduled_date} at {formData.scheduled_time}</p>
                <p><strong>Estimated Price:</strong> ₹{priceEstimate?.estimate.min} - ₹{priceEstimate?.estimate.max}</p>
              </div>

              <button className="btn btn-primary" onClick={handleSubmit} disabled={loading}>
                {loading ? <LoadingSpinner /> : 'Confirm Booking'}
              </button>
            </div>
          )}
        </div>

        {/* Map Selection Modal */}
        {showMapModal && (
          <div className="modal-overlay" style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, background: 'rgba(0,0,0,0.7)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }}>
            <div className="modal" style={{ background: 'white', padding: '20px', borderRadius: '12px', width: '95%', maxWidth: '600px', maxHeight: '90vh', overflow: 'auto' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                <h3>Select Location on Map</h3>
                <button onClick={() => setShowMapModal(false)} style={{ background: 'none', border: 'none', fontSize: '24px', cursor: 'pointer' }}>×</button>
              </div>
              
              <p style={{ marginBottom: '12px', color: '#666' }}>Click on the map to set your location, or use your current location:</p>
              
              <button 
                className="btn btn-primary" 
                style={{ marginBottom: '16px', width: '100%' }}
                onClick={() => {
                  if (navigator.geolocation) {
                    navigator.geolocation.getCurrentPosition(
                      (position) => {
                        setMapCenter({
                          lat: position.coords.latitude,
                          lng: position.coords.longitude
                        });
                      },
                      (err) => alert('Could not get location. Please select manually.')
                    );
                  }
                }}
              >
                <i className="fas fa-crosshairs"></i> Use My Current Location
              </button>
              
              <LocationMap 
                center={mapCenter}
                markerPosition={formData.latitude && formData.longitude ? { lat: parseFloat(formData.latitude), lng: parseFloat(formData.longitude) } : null}
                onLocationSelect={async (location) => {
                  setFormData({ 
                    ...formData, 
                    latitude: location.lat.toFixed(6), 
                    longitude: location.lng.toFixed(6) 
                  });
                  
                  // Reverse geocode to get address
                  const address = await reverseGeocode(location.lat, location.lng);
                  if (address) {
                    setFormData(prev => ({ ...prev, address }));
                  }
                  
                  setShowMapModal(false);
                }}
                height="350px"
              />
              
              <div style={{ marginTop: '16px', display: 'flex', gap: '12px', justifyContent: 'flex-end' }}>
                <button className="btn" onClick={() => setShowMapModal(false)} style={{ background: '#E0E0E0' }}>Cancel</button>
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
};

// ==================== BOOKING DETAILS ====================
const BookingDetails = () => {
  const [booking, setBooking] = useState(null);
  const [loading, setLoading] = useState(true);
  const [messages, setMessages] = useState([]);
  const [newMessage, setNewMessage] = useState('');
  const [showRatingModal, setShowRatingModal] = useState(false);
  const [rating, setRating] = useState(0);
  const [review, setReview] = useState('');
  const [existingRatings, setExistingRatings] = useState([]);
  const { id } = useParams();
  const { user } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    loadBooking();
  }, [id]);

  const loadBooking = async () => {
    try {
      const res = await api.getBooking(id);
      setBooking(res.data);
      const msgsRes = await api.getMessages(id);
      setMessages(msgsRes.data);
      
      // Check if user has already rated
      if (res.data.status === 'completed' || res.data.status === 'confirmed') {
        const ratingsRes = await api.checkRating(id);
        setExistingRatings(ratingsRes.data);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleSendMessage = async () => {
    if (!newMessage.trim()) return;
    try {
      await api.sendMessage({ booking_id: id, message: newMessage });
      setNewMessage('');
      loadBooking();
    } catch (err) {
      console.error(err);
    }
  };

  const handleConfirm = async () => {
    setShowRatingModal(true);
  };
  
  const submitRating = async () => {
    if (rating === 0) {
      alert('Please select a rating');
      return;
    }
    try {
      // Submit rating for worker
      await api.submitRating({
        booking_id: id,
        entity_id: booking.worker_id,
        entity_type: 'worker',
        rating: rating,
        review: review
      });
      
      // Also confirm the booking
      await api.confirmBooking(id, { rating, review });
      
      setShowRatingModal(false);
      loadBooking();
    } catch (err) {
      console.error(err);
      alert(err.response?.data?.error || 'Failed to submit rating');
    }
  };

  const getStatusClass = (status) => {
    const statusMap = {
      'pending': 'pending', 'accepted': 'accepted', 'arrived': 'accepted',
      'in_progress': 'accepted', 'completed': 'completed', 'confirmed': 'completed', 'cancelled': 'cancelled'
    };
    return statusMap[status] || 'pending';
  };

  if (loading) return <LoadingSpinner />;
  if (!booking) return <div>Booking not found</div>;

  return (
    <div className="dashboard">
      <aside className="dashboard-sidebar">
        <div className="dashboard-logo"><i className="fas fa-bee"></i> OneHive</div>
        <ul className="dashboard-menu">
          <li className="dashboard-menu-item"><a className="dashboard-menu-link" onClick={() => navigate('/dashboard')}><i className="fas fa-home"></i> Dashboard</a></li>
          <li className="dashboard-menu-item"><a className="dashboard-menu-link" onClick={() => navigate('/user/bookings')}><i className="fas fa-calendar"></i> My Bookings</a></li>
        </ul>
      </aside>

      <main className="dashboard-main">
        <div className="dashboard-header">
          <h2>Booking Details</h2>
          <span className={`booking-status ${getStatusClass(booking.status)}`}>{booking.status}</span>
        </div>

        <div className="dashboard-content">
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px' }}>
            {/* Booking Info */}
            <div className="card">
              <h3 className="card-title">{booking.service_type}</h3>
              <p><strong>Description:</strong> {booking.description}</p>
              <p><strong>Address:</strong> {booking.address}</p>
              <p><strong>Scheduled:</strong> {booking.scheduled_date} at {booking.scheduled_time}</p>
              <p><strong>Estimated Price:</strong> ₹{booking.price_estimate}</p>
              {booking.price_final && <p><strong>Final Price:</strong> ₹{booking.price_final}</p>}
              
              {booking.worker_name && (
                <div style={{ marginTop: '16px', padding: '16px', background: '#F5F4F2', borderRadius: '10px' }}>
                  <h4>Assigned Worker</h4>
                  <p><strong>Name:</strong> {booking.worker_name}</p>
                  <p><strong>Phone:</strong> {booking.worker_phone}</p>
                  <p><strong>Rating:</strong> <i className="fas fa-star" style={{ color: '#F59E0B' }}></i> {booking.worker_rating}</p>
                </div>
              )}

              {booking.status === 'completed' && existingRatings.length === 0 && (
                <button className="btn btn-primary" style={{ marginTop: '16px' }} onClick={handleConfirm}>
                  Rate Service
                </button>
              )}
              
              {existingRatings.length > 0 && (
                <div style={{ marginTop: '16px', padding: '12px', background: 'rgba(39, 174, 96, 0.1)', borderRadius: '8px' }}>
                  <p style={{ color: 'var(--success)', margin: 0 }}><i className="fas fa-check-circle"></i> You have already rated this service</p>
                </div>
              )}
            </div>

            {/* Chat */}
            <div className="card">
              <h3 className="card-title">Chat</h3>
              <div className="chat-container" style={{ height: '300px' }}>
                <div className="chat-messages">
                  {messages.length === 0 ? (
                    <p style={{ textAlign: 'center', color: '#636E72' }}>No messages yet</p>
                  ) : (
                    messages.map(msg => (
                      <div key={msg.id} className={`chat-message ${msg.sender_type === 'user' ? 'sent' : 'received'}`}>
                        {msg.message}
                      </div>
                    ))
                  )}
                </div>
                <div className="chat-input">
                  <input type="text" className="form-input" placeholder="Type a message..." value={newMessage} onChange={(e) => setNewMessage(e.target.value)} onKeyPress={(e) => e.key === 'Enter' && handleSendMessage()} />
                  <button className="btn btn-primary" onClick={handleSendMessage}><i className="fas fa-paper-plane"></i></button>
                </div>
              </div>
            </div>
          </div>

          {/* Live Tracking */}
          {(booking.status === 'accepted' || booking.status === 'arrived' || booking.status === 'in_progress') && (
            <div className="card" style={{ marginTop: '24px' }}>
              <h3 className="card-title">Live Tracking</h3>
              <div className="live-tracking">
                <div className="tracking-map" style={{ height: '300px', background: '#E8E6E3', borderRadius: '10px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                  <p>Live map would appear here</p>
                </div>
                <div className="tracking-info">
                  <div className="tracking-status">
                    <span className="tracking-dot"></span>
                    <span>Worker is on the way</span>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </main>
    </div>
  );
  
  // Rating Modal
  if (showRatingModal) {
    return (
      <div className="modal-overlay" style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, background: 'rgba(0,0,0,0.5)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }}>
        <div className="modal" style={{ background: 'white', padding: '24px', borderRadius: '12px', width: '90%', maxWidth: '400px' }}>
          <h3 style={{ marginBottom: '16px' }}>Rate Your Experience</h3>
          
          <div style={{ display: 'flex', justifyContent: 'center', gap: '8px', marginBottom: '16px' }}>
            {[1, 2, 3, 4, 5].map((star) => (
              <span
                key={star}
                onClick={() => setRating(star)}
                style={{ cursor: 'pointer', fontSize: '32px', color: star <= rating ? '#F39C12' : '#DDD' }}
              >
                <i className="fas fa-star"></i>
              </span>
            ))}
          </div>
          
          <textarea
            className="form-input"
            placeholder="Write a review (optional)..."
            value={review}
            onChange={(e) => setReview(e.target.value)}
            rows={3}
            style={{ marginBottom: '16px', width: '100%', resize: 'vertical' }}
          />
          
          <div style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end' }}>
            <button className="btn" onClick={() => setShowRatingModal(false)} style={{ background: '#E0E0E0' }}>Cancel</button>
            <button className="btn btn-primary" onClick={submitRating}>Submit Rating</button>
          </div>
        </div>
      </div>
    );
  }
};

// ==================== WORKER DASHBOARD ====================
const WorkerDashboard = () => {
  const [bookings, setBookings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [status, setStatus] = useState('available');
  const [broadcastJobs, setBroadcastJobs] = useState([]);
  const [activeLock, setActiveLock] = useState(null);
  const [showJobModal, setShowJobModal] = useState(null);
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    loadBookings();
    setupSocketListeners();
  }, []);

  const loadBookings = async () => {
    try {
      const res = await api.getWorkerBookings();
      setBookings(res.data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleAccept = async (id) => {
    try {
      await api.acceptBooking(id);
      loadBookings();
    } catch (err) {
      console.error(err);
    }
  };

  const handleReject = async (id) => {
    try {
      await api.rejectBooking(id);
      loadBookings();
    } catch (err) {
      console.error(err);
    }
  };

  const handleArrived = async (id) => {
    try {
      await api.arrivedBooking(id);
      loadBookings();
    } catch (err) {
      console.error(err);
    }
  };

  const handleStart = async (id) => {
    try {
      await api.startBooking(id);
      loadBookings();
    } catch (err) {
      console.error(err);
    }
  };

  const handleComplete = async (id) => {
    const price = window.prompt('Enter final price:');
    if (!price) return;
    try {
      await api.completeBooking(id, { price_final: parseInt(price) });
      loadBookings();
    } catch (err) {
      console.error(err);
    }
  };

  const handleStatusChange = async (newStatus) => {
    try {
      await api.updateWorkerStatus(newStatus);
      setStatus(newStatus);
    } catch (err) {
      console.error(err);
    }
  };
  
  // Socket listeners for job broadcasts
  const setupSocketListeners = () => {
    if (window.socket) {
      window.socket.on('job_broadcast', (job) => {
        // Add to broadcast jobs if not already present
        setBroadcastJobs(prev => {
          if (prev.find(j => j.booking_id === job.booking_id)) return prev;
          return [...prev, job];
        });
      });
      
      window.socket.on('job_locked', (data) => {
        // Update broadcast jobs to show lock status
        setBroadcastJobs(prev => prev.map(j => 
          j.booking_id === data.booking_id 
            ? { ...j, locked: true, locked_by: data.worker_name } 
            : j
        ));
      });
      
      window.socket.on('job_released', (data) => {
        setBroadcastJobs(prev => prev.map(j => 
          j.booking_id === data.booking_id 
            ? { ...j, locked: false, locked_by: null } 
            : j
        ));
      });
      
      window.socket.on('job_accepted', (data) => {
        // Remove from broadcast jobs
        setBroadcastJobs(prev => prev.filter(j => j.booking_id !== data.booking_id));
      });
    }
  };
  
  // Handle Call Before Accept
  const handleCallBeforeAccept = async (job) => {
    try {
      const res = await api.lockJob(job.booking_id);
      if (res.data.success) {
        setActiveLock({
          ...job,
          lock_id: res.data.lock_id,
          user_phone: res.data.user_phone,
          user_name: res.data.user_name,
          expires_at: res.data.expires_at
        });
        setShowJobModal(job);
      }
    } catch (err) {
      alert(err.response?.data?.error || 'Failed to lock job');
    }
  };
  
  // Handle Release Job
  const handleReleaseJob = async (job) => {
    try {
      await api.releaseJob(job.booking_id);
      setActiveLock(null);
      setShowJobModal(null);
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div className="dashboard">
      <aside className="dashboard-sidebar">
        <div className="dashboard-logo"><i className="fas fa-bee"></i> OneHive</div>
        <ul className="dashboard-menu">
          <li className="dashboard-menu-item"><a className="dashboard-menu-link active"><i className="fas fa-home"></i> Dashboard</a></li>
          <li className="dashboard-menu-item"><a className="dashboard-menu-link"><i className="fas fa-user"></i> Profile</a></li>
          <li className="dashboard-menu-item"><a className="dashboard-menu-link" onClick={logout}><i className="fas fa-sign-out-alt"></i> Logout</a></li>
        </ul>
      </aside>

      <main className="dashboard-main">
        <div className="dashboard-header">
          <h2>Worker Dashboard</h2>
          <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
            <span>Status:</span>
            <select className="form-select" style={{ width: 'auto' }} value={status} onChange={(e) => handleStatusChange(e.target.value)}>
              <option value="available">Available</option>
              <option value="busy">Busy</option>
              <option value="offline">Offline</option>
            </select>
          </div>
        </div>

        <div className="dashboard-content">
          <div className="stats-grid">
            <div className="stat-card">
              <div className="stat-card-icon"><i className="fas fa-briefcase"></i></div>
              <div className="stat-card-value">{bookings.filter(b => b.status === 'accepted' || b.status === 'in_progress').length}</div>
              <div className="stat-card-label">Active Jobs</div>
            </div>
            <div className="stat-card">
              <div className="stat-card-icon"><i className="fas fa-check-circle"></i></div>
              <div className="stat-card-value">{bookings.filter(b => b.status === 'completed' || b.status === 'confirmed').length}</div>
              <div className="stat-card-label">Completed Jobs</div>
            </div>
            <div className="stat-card">
              <div className="stat-card-icon"><i className="fas fa-rupee-sign"></i></div>
              <div className="stat-card-value">₹{bookings.filter(b => b.status === 'completed' || b.status === 'confirmed').reduce((sum, b) => sum + (b.price_final || 0), 0)}</div>
              <div className="stat-card-label">Total Earnings</div>
            </div>
          </div>

          {/* Job Broadcast Section */}
          {broadcastJobs.length > 0 && (
            <div style={{ marginBottom: '24px' }}>
              <h3 style={{ marginBottom: '16px', color: 'var(--primary)' }}>
                <i className="fas fa-bell"></i> New Job Requests ({broadcastJobs.length})
              </h3>
              <div className="bookings-grid">
                {broadcastJobs.map(job => (
                  <div key={job.booking_id} className="booking-card" style={{ borderLeft: '4px solid var(--primary)' }}>
                    <div className="booking-header">
                      <span className="booking-service">{job.service_type}</span>
                      {job.locked && <span className="booking-status pending">Being Reviewed</span>}
                    </div>
                    <div className="booking-body">
                      <div className="booking-info">
                        <p><i className="fas fa-user"></i> {job.user_name}</p>
                        <p><i className="fas fa-map-marker-alt"></i> {job.address}</p>
                        <p><i className="fas fa-calendar"></i> {job.scheduled_date} at {job.scheduled_time}</p>
                        <p><i className="fas fa-rupee-sign"></i> ₹{job.price_estimate}</p>
                        {job.locked && <p style={{ color: 'var(--warning)' }}><i className="fas fa-lock"></i> {job.locked_by} is reviewing</p>}
                      </div>
                    </div>
                    <div className="booking-footer">
                      {!job.locked && (
                        <>
                          <button className="btn btn-sm btn-primary" onClick={() => handleCallBeforeAccept(job)}>
                            <i className="fas fa-phone"></i> Call Before Accept
                          </button>
                          <button className="btn btn-sm btn-success" onClick={() => handleAccept(job.booking_id)}>Accept</button>
                          <button className="btn btn-sm btn-danger" onClick={() => handleReject(job.booking_id)}>Reject</button>
                        </>
                      )}
                      {job.locked && <span style={{ color: 'var(--grey-600)' }}>Please wait or check other jobs</span>}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          <h3 style={{ marginBottom: '16px' }}>Job Requests</h3>
          {loading ? <LoadingSpinner /> : bookings.length === 0 ? (
            <div className="empty-state">
              <i className="fas fa-briefcase"></i>
              <h3>No jobs yet</h3>
              <p>Waiting for new booking requests</p>
            </div>
          ) : (
            <div className="bookings-grid">
              {bookings.map(booking => (
                <div key={booking.id} className="booking-card">
                  <div className="booking-header">
                    <span className="booking-service">{booking.service_type}</span>
                    <span className={`booking-status ${booking.status}`}>{booking.status}</span>
                  </div>
                  <div className="booking-body">
                    <div className="booking-info">
                      <p><i className="fas fa-user"></i> {booking.user_name}</p>
                      <p><i className="fas fa-map-marker-alt"></i> {booking.address}</p>
                      <p><i className="fas fa-calendar"></i> {booking.scheduled_date} at {booking.scheduled_time}</p>
                    </div>
                  </div>
                  <div className="booking-footer">
                    {booking.status === 'pending' && (
                      <>
                        <button className="btn btn-sm btn-success" onClick={() => handleAccept(booking.id)}>Accept</button>
                        <button className="btn btn-sm btn-danger" onClick={() => handleReject(booking.id)}>Reject</button>
                      </>
                    )}
                    {booking.status === 'accepted' && (
                      <button className="btn btn-sm btn-primary" onClick={() => handleArrived(booking.id)}>Mark Arrived</button>
                    )}
                    {booking.status === 'arrived' && (
                      <button className="btn btn-sm btn-primary" onClick={() => handleStart(booking.id)}>Start Job</button>
                    )}
                    {booking.status === 'in_progress' && (
                      <button className="btn btn-sm btn-success" onClick={() => handleComplete(booking.id)}>Complete Job</button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </main>
    </div>
  );
  
  // Call Before Accept Modal
  if (showJobModal && activeLock) {
    return (
      <div className="modal-overlay" style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, background: 'rgba(0,0,0,0.5)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }}>
        <div className="modal" style={{ background: 'white', padding: '24px', borderRadius: '12px', width: '90%', maxWidth: '450px' }}>
          <h3 style={{ marginBottom: '16px' }}><i className="fas fa-phone"></i> Call Before Accept</h3>
          
          <div style={{ marginBottom: '16px', padding: '16px', background: '#F5F4F2', borderRadius: '8px' }}>
            <p><strong>Customer:</strong> {activeLock.user_name}</p>
            <p><strong>Service:</strong> {activeLock.service_type}</p>
            <p><strong>Address:</strong> {activeLock.address}</p>
          </div>
          
          <div style={{ marginBottom: '16px', padding: '16px', background: 'rgba(39, 174, 96, 0.1)', borderRadius: '8px', textAlign: 'center' }}>
            <p style={{ margin: 0, fontSize: '18px' }}><i className="fas fa-phone"></i></p>
            <p style={{ margin: '8px 0 0', fontSize: '24px', fontWeight: 'bold' }}>{activeLock.user_phone}</p>
            <p style={{ margin: '4px 0 0', fontSize: '12px', color: '#666' }}>Phone number revealed for call</p>
          </div>
          
          <div style={{ marginBottom: '16px' }}>
            <p style={{ fontSize: '14px', color: '#666' }}>
              <i className="fas fa-clock"></i> Lock expires in {Math.max(0, Math.floor((new Date(activeLock.expires_at) - new Date()) / 1000))} seconds
            </p>
          </div>
          
          {/* Navigation Section */}
          <div style={{ marginBottom: '16px' }}>
            <h4 style={{ marginBottom: '8px' }}>Navigate to Customer</h4>
            <a 
              href={`https://www.google.com/maps/dir/?api=1&destination=${activeLock.latitude},${activeLock.longitude}`}
              target="_blank"
              rel="noopener noreferrer"
              className="btn btn-primary"
              style={{ display: 'block', textAlign: 'center', textDecoration: 'none' }}
            >
              <i className="fas fa-navigation"></i> Open Navigation
            </a>
          </div>
          
          <div style={{ display: 'flex', gap: '12px', justifyContent: 'flex-end' }}>
            <button className="btn" onClick={() => handleReleaseJob(activeLock)} style={{ background: '#E0E0E0' }}>Release Job</button>
            <button className="btn btn-success" onClick={() => {
              handleAccept(activeLock.booking_id);
              setActiveLock(null);
              setShowJobModal(null);
            }}>Confirm & Accept</button>
          </div>
        </div>
      </div>
    );
  }
};

// ==================== WORKER AUTH ====================
const WorkerAuthPage = () => {
  const [isLogin, setIsLogin] = useState(true);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [formData, setFormData] = useState({
    name: '', email: '', password: '', phone: '', service_type: '', city: '', experience: '', hourly_rate: ''
  });
  const { login } = useAuth();
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      if (isLogin) {
        const res = await api.login({ email: formData.email, password: formData.password });
        login(res.data.token, res.data.user);
      } else {
        const res = await api.register({ ...formData, role: 'worker' });
        await api.registerWorker({ name: formData.name, email: formData.email, phone: formData.phone, service_type: formData.service_type, city: formData.city, experience: formData.experience, hourly_rate: formData.hourly_rate });
        login(res.data.token, res.data.user);
      }
      navigate('/worker/dashboard');
    } catch (err) {
      setError(err.response?.data?.error || 'An error occurred');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-page">
      <div className="auth-container">
        <div className="auth-header">
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px', marginBottom: '16px' }}>
            <div style={{ width: '40px', height: '40px', background: 'linear-gradient(135deg, #D4A574, #E5A84B)', borderRadius: '10px', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'white', fontSize: '1.2rem' }}><i className="fas fa-bee"></i></div>
            <span style={{ fontSize: '1.5rem', fontWeight: '700', color: '#B8956A' }}>OneHive</span>
          </div>
          <h1>{isLogin ? 'Worker Login' : 'Worker Registration'}</h1>
          <p>{isLogin ? 'Sign in to access your worker dashboard' : 'Join our network of professional workers'}</p>
        </div>

        {error && <Alert type="error" message={error} />}

        <div className="auth-tabs">
          <button className={`auth-tab ${isLogin ? 'active' : ''}`} onClick={() => setIsLogin(true)}>Login</button>
          <button className={`auth-tab ${!isLogin ? 'active' : ''}`} onClick={() => setIsLogin(false)}>Register</button>
        </div>

        <form onSubmit={handleSubmit}>
          {!isLogin && (
            <>
              <div className="form-group">
                <label className="form-label">Full Name</label>
                <input type="text" className="form-input" placeholder="Enter your name" value={formData.name} onChange={(e) => setFormData({ ...formData, name: e.target.value })} />
              </div>
              <div className="form-group">
                <label className="form-label">Service Type</label>
                <select className="form-select" value={formData.service_type} onChange={(e) => setFormData({ ...formData, service_type: e.target.value })}>
                  <option value="">Select service</option>
                  <option value="plumbing">Plumbing</option>
                  <option value="electrical">Electrical</option>
                  <option value="cleaning">Home Cleaning</option>
                  <option value="painting">Painting</option>
                  <option value="carpentry">Carpentry</option>
                  <option value="ac_repair">AC Repair</option>
                  <option value="appliance">Appliance Repair</option>
                </select>
              </div>
              <div className="form-group">
                <label className="form-label">City</label>
                <select className="form-select" value={formData.city} onChange={(e) => setFormData({ ...formData, city: e.target.value })}>
                  <option value="">Select city</option>
                  <option value="mumbai">Mumbai</option>
                  <option value="delhi">Delhi</option>
                  <option value="bangalore">Bangalore</option>
                  <option value="chennai">Chennai</option>
                  <option value="pune">Pune</option>
                </select>
              </div>
              <div className="form-group">
                <label className="form-label">Experience (years)</label>
                <input type="number" className="form-input" placeholder="Years of experience" value={formData.experience} onChange={(e) => setFormData({ ...formData, experience: e.target.value })} />
              </div>
              <div className="form-group">
                <label className="form-label">Hourly Rate (₹)</label>
                <input type="number" className="form-input" placeholder="Your hourly rate" value={formData.hourly_rate} onChange={(e) => setFormData({ ...formData, hourly_rate: e.target.value })} />
              </div>
            </>
          )}
          <div className="form-group">
            <label className="form-label">Email Address</label>
            <input type="email" className="form-input" placeholder="Enter your email" value={formData.email} onChange={(e) => setFormData({ ...formData, email: e.target.value })} required />
          </div>
          <div className="form-group">
            <label className="form-label">Password</label>
            <input type="password" className="form-input" placeholder="Enter your password" value={formData.password} onChange={(e) => setFormData({ ...formData, password: e.target.value })} required />
          </div>
          <button type="submit" className="btn btn-primary" style={{ width: '100%' }} disabled={loading}>
            {loading ? <LoadingSpinner /> : (isLogin ? 'Sign In' : 'Register')}
          </button>
        </form>

        <p style={{ textAlign: 'center', marginTop: '24px' }}><Link to="/" style={{ color: '#D4A574' }}>← Back to Home</Link></p>
      </div>
    </div>
  );
};

// ==================== ADMIN DASHBOARD ====================
const AdminDashboard = () => {
  const [analytics, setAnalytics] = useState({});
  const [activeTab, setActiveTab] = useState('overview');
  const [users, setUsers] = useState([]);
  const [workers, setWorkers] = useState([]);
  const [bookings, setBookings] = useState([]);
  const [settings, setSettings] = useState({});
  const [heroSlider, setHeroSlider] = useState([]);
  const [loading, setLoading] = useState(true);
  const { logout } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    loadData();
  }, [activeTab]);

  const loadData = async () => {
    setLoading(true);
    try {
      const analyticsRes = await api.getAnalytics();
      setAnalytics(analyticsRes.data);

      if (activeTab === 'users') {
        const res = await api.getUsers();
        setUsers(res.data);
      } else if (activeTab === 'workers') {
        const res = await api.getAdminWorkers();
        setWorkers(res.data);
      } else if (activeTab === 'bookings') {
        const res = await api.getAdminBookings({});
        setBookings(res.data);
      } else if (activeTab === 'settings') {
        const res = await api.getSettings();
        setSettings(res.data);
      } else if (activeTab === 'hero-slider') {
        const res = await api.getAdminHeroSlider();
        setHeroSlider(res.data.slides || []);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyWorker = async (id, verified) => {
    try {
      await api.verifyWorker(id, verified);
      loadData();
    } catch (err) {
      console.error(err);
    }
  };

  const handleSaveSettings = async () => {
    try {
      await api.updateSettings(settings);
      alert('Settings saved successfully');
    } catch (err) {
      console.error(err);
    }
  };

  return (
    <div className="dashboard">
      <aside className="dashboard-sidebar">
        <div className="dashboard-logo"><i className="fas fa-bee"></i> OneHive Admin</div>
        <ul className="dashboard-menu">
          <li className="dashboard-menu-item"><a className={`dashboard-menu-link ${activeTab === 'overview' ? 'active' : ''}`} onClick={() => setActiveTab('overview')}><i className="fas fa-chart-line"></i> Overview</a></li>
          <li className="dashboard-menu-item"><a className={`dashboard-menu-link ${activeTab === 'users' ? 'active' : ''}`} onClick={() => setActiveTab('users')}><i className="fas fa-users"></i> Users</a></li>
          <li className="dashboard-menu-item"><a className={`dashboard-menu-link ${activeTab === 'workers' ? 'active' : ''}`} onClick={() => setActiveTab('workers')}><i className="fas fa-tools"></i> Workers</a></li>
          <li className="dashboard-menu-item"><a className={`dashboard-menu-link ${activeTab === 'bookings' ? 'active' : ''}`} onClick={() => setActiveTab('bookings')}><i className="fas fa-calendar"></i> Bookings</a></li>
          <li className="dashboard-menu-item"><a className={`dashboard-menu-link ${activeTab === 'shops' ? 'active' : ''}`} onClick={() => setActiveTab('shops')}><i className="fas fa-store"></i> Shops</a></li>
          <li className="dashboard-menu-item"><a className={`dashboard-menu-link ${activeTab === 'hero-slider' ? 'active' : ''}`} onClick={() => setActiveTab('hero-slider')}><i className="fas fa-images"></i> Hero Slider</a></li>
          <li className="dashboard-menu-item"><a className={`dashboard-menu-link ${activeTab === 'settings' ? 'active' : ''}`} onClick={() => setActiveTab('settings')}><i className="fas fa-cog"></i> Settings</a></li>
          <li className="dashboard-menu-item"><a className="dashboard-menu-link" onClick={logout}><i className="fas fa-sign-out-alt"></i> Logout</a></li>
        </ul>
      </aside>

      <main className="dashboard-main">
        <div className="dashboard-header">
          <h2>Admin Dashboard</h2>
        </div>

        <div className="dashboard-content">
          {activeTab === 'overview' && (
            <>
              <div className="stats-grid">
                <div className="stat-card">
                  <div className="stat-card-icon"><i className="fas fa-users"></i></div>
                  <div className="stat-card-value">{analytics.totalUsers || 0}</div>
                  <div className="stat-card-label">Total Users</div>
                </div>
                <div className="stat-card">
                  <div className="stat-card-icon"><i className="fas fa-tools"></i></div>
                  <div className="stat-card-value">{analytics.totalWorkers || 0}</div>
                  <div className="stat-card-label">Total Workers</div>
                </div>
                <div className="stat-card">
                  <div className="stat-card-icon"><i className="fas fa-store"></i></div>
                  <div className="stat-card-value">{analytics.totalShops || 0}</div>
                  <div className="stat-card-label">Total Shops</div>
                </div>
                <div className="stat-card">
                  <div className="stat-card-icon"><i className="fas fa-calendar-check"></i></div>
                  <div className="stat-card-value">{analytics.totalBookings || 0}</div>
                  <div className="stat-card-label">Total Bookings</div>
                </div>
                <div className="stat-card">
                  <div className="stat-card-icon"><i className="fas fa-rupee-sign"></i></div>
                  <div className="stat-card-value">₹{analytics.totalRevenue || 0}</div>
                  <div className="stat-card-label">Total Revenue</div>
                </div>
                <div className="stat-card">
                  <div className="stat-card-icon"><i className="fas fa-clock"></i></div>
                  <div className="stat-card-value">{analytics.pendingBookings || 0}</div>
                  <div className="stat-card-label">Pending Bookings</div>
                </div>
              </div>
            </>
          )}

          {activeTab === 'users' && (
            <>
              <h3 style={{ marginBottom: '16px' }}>All Users</h3>
              {loading ? <LoadingSpinner /> : (
                <div className="card">
                  <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                    <thead>
                      <tr style={{ borderBottom: '2px solid #E5E3E0' }}>
                        <th style={{ textAlign: 'left', padding: '12px' }}>Name</th>
                        <th style={{ textAlign: 'left', padding: '12px' }}>Email</th>
                        <th style={{ textAlign: 'left', padding: '12px' }}>Phone</th>
                        <th style={{ textAlign: 'left', padding: '12px' }}>Role</th>
                        <th style={{ textAlign: 'left', padding: '12px' }}>Joined</th>
                      </tr>
                    </thead>
                    <tbody>
                      {users.map(user => (
                        <tr key={user.id} style={{ borderBottom: '1px solid #E5E3E0' }}>
                          <td style={{ padding: '12px' }}>{user.name}</td>
                          <td style={{ padding: '12px' }}>{user.email}</td>
                          <td style={{ padding: '12px' }}>{user.phone || '-'}</td>
                          <td style={{ padding: '12px' }}><span className="badge badge-pending">{user.role}</span></td>
                          <td style={{ padding: '12px' }}>{new Date(user.created_at).toLocaleDateString()}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </>
          )}

          {activeTab === 'workers' && (
            <>
              <h3 style={{ marginBottom: '16px' }}>Worker Verification</h3>
              {loading ? <LoadingSpinner /> : (
                <div className="workers-grid">
                  {workers.map(worker => (
                    <div key={worker.id} className="worker-card">
                      <div className="worker-header">
                        <div className="worker-avatar"><i className="fas fa-user"></i></div>
                        <div className="worker-name">{worker.name}</div>
                        <div className="worker-rating"><i className="fas fa-star" style={{ color: '#F59E0B', marginRight: '4px' }}></i> {worker.rating || 0} ({worker.total_jobs || 0} jobs)</div>
                      </div>
                      <div className="worker-body">
                        <div className="worker-info">
                          <p><i className="fas fa-wrench"></i> {worker.service_type}</p>
                          <p><i className="fas fa-map-marker-alt"></i> {worker.city}</p>
                          <p><i className="fas fa-rupee-sign"></i> ₹{worker.hourly_rate}/hr</p>
                        </div>
                      </div>
                      <div className="worker-footer">
                        {worker.status === 'rejected' ? (
                          <span className="badge badge-rejected"><i className="fas fa-times-circle"></i> Rejected</span>
                        ) : worker.verified ? (
                          <span className="badge badge-verified"><i className="fas fa-check-circle"></i> Verified</span>
                        ) : (
                          <>
                            <button className="btn btn-sm btn-success" onClick={() => handleVerifyWorker(worker.id, true)}>Verify</button>
                            <button className="btn btn-sm btn-danger" onClick={() => handleVerifyWorker(worker.id, false)}>Reject</button>
                          </>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </>
          )}

          {activeTab === 'bookings' && (
            <>
              <h3 style={{ marginBottom: '16px' }}>All Bookings</h3>
              {loading ? <LoadingSpinner /> : (
                <div className="bookings-grid">
                  {bookings.map(booking => (
                    <div key={booking.id} className="booking-card">
                      <div className="booking-header">
                        <span className="booking-service">{booking.service_type}</span>
                        <span className={`booking-status ${booking.status}`}>{booking.status}</span>
                      </div>
                      <div className="booking-body">
                        <div className="booking-info">
                          <p><i className="fas fa-user"></i> {booking.user_name}</p>
                          <p><i className="fas fa-tools"></i> {booking.worker_name || 'Unassigned'}</p>
                          <p><i className="fas fa-calendar"></i> {booking.scheduled_date}</p>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </>
          )}

          {activeTab === 'settings' && (
            <>
              <h3 style={{ marginBottom: '16px' }}>Dynamic Settings</h3>
              <div className="settings-section">
                <h4 className="settings-title">General Settings</h4>
                <div className="form-group">
                  <label className="form-label">Footer Content</label>
                  <input type="text" className="form-input" value={settings.footer_content || ''} onChange={(e) => setSettings({ ...settings, footer_content: e.target.value })} />
                </div>
                <div className="form-group">
                  <label className="form-label">Contact Email</label>
                  <input type="email" className="form-input" value={settings.contact_email || ''} onChange={(e) => setSettings({ ...settings, contact_email: e.target.value })} />
                </div>
                <div className="form-group">
                  <label className="form-label">Contact Phone</label>
                  <input type="tel" className="form-input" value={settings.contact_phone || ''} onChange={(e) => setSettings({ ...settings, contact_phone: e.target.value })} />
                </div>
                <div className="form-group">
                  <label className="form-label">Commission Percentage</label>
                  <input type="number" className="form-input" value={settings.commission_percent || ''} onChange={(e) => setSettings({ ...settings, commission_percent: e.target.value })} />
                </div>
                <div className="form-group">
                  <label className="form-label">Announcement</label>
                  <textarea className="form-textarea" value={settings.announcement || ''} onChange={(e) => setSettings({ ...settings, announcement: e.target.value })}></textarea>
                </div>
                <div className="form-group">
                  <label className="form-label">Support Details</label>
                  <textarea className="form-textarea" value={settings.support_details || ''} onChange={(e) => setSettings({ ...settings, support_details: e.target.value })}></textarea>
                </div>
              </div>

              {/* Email Configuration Section */}
              <div className="settings-section" style={{ marginTop: '24px' }}>
                <h4 className="settings-title">📧 Email Configuration (SMTP)</h4>
                <p style={{ fontSize: '12px', color: '#6B7280', marginBottom: '12px' }}>
                  Configure SMTP settings to enable real email sending. Without password, emails will be simulated.
                </p>
                <div className="form-group">
                  <label className="form-label">Enable Email</label>
                  <select className="form-input" value={settings.email_enabled || 'true'} onChange={(e) => setSettings({ ...settings, email_enabled: e.target.value })}>
                    <option value="true">Enabled</option>
                    <option value="false">Disabled (Simulated)</option>
                  </select>
                </div>
                <div className="form-group">
                  <label className="form-label">SMTP Host</label>
                  <input type="text" className="form-input" value={settings.email_host || 'smtp.gmail.com'} onChange={(e) => setSettings({ ...settings, email_host: e.target.value })} placeholder="smtp.gmail.com" />
                </div>
                <div className="form-group">
                  <label className="form-label">SMTP Port</label>
                  <input type="number" className="form-input" value={settings.email_port || '587'} onChange={(e) => setSettings({ ...settings, email_port: e.target.value })} placeholder="587" />
                </div>
                <div className="form-group">
                  <label className="form-label">Secure (TLS)</label>
                  <select className="form-input" value={settings.email_secure || 'false'} onChange={(e) => setSettings({ ...settings, email_secure: e.target.value })}>
                    <option value="false">No (Port 587)</option>
                    <option value="true">Yes (Port 465)</option>
                  </select>
                </div>
                <div className="form-group">
                  <label className="form-label">SMTP Username / Email</label>
                  <input type="text" className="form-input" value={settings.email_user || ''} onChange={(e) => setSettings({ ...settings, email_user: e.target.value })} placeholder="your-email@gmail.com" />
                </div>
                <div className="form-group">
                  <label className="form-label">SMTP App Password</label>
                  <input type="password" className="form-input" value={settings.email_password || ''} onChange={(e) => setSettings({ ...settings, email_password: e.target.value })} placeholder="16-character app password" />
                  <small style={{ fontSize: '11px', color: '#6B7280' }}>For Gmail: Enable 2-Step Verification → Create App Password</small>
                </div>
                <div className="form-group">
                  <label className="form-label">From Name</label>
                  <input type="text" className="form-input" value={settings.email_from_name || 'OneHive'} onChange={(e) => setSettings({ ...settings, email_from_name: e.target.value })} placeholder="OneHive" />
                </div>
                <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
                  <button className="btn btn-primary" onClick={handleSaveSettings}>Save Settings</button>
                  <button className="btn btn-secondary" onClick={async () => {
                    const testEmail = prompt('Enter test email address:');
                    if (testEmail) {
                      try {
                        const res = await api.testEmail(testEmail);
                        alert(res.data.message);
                      } catch (err) {
                        alert('Failed to send test email: ' + (err.response?.data?.error || err.message));
                      }
                    }
                  }}><i className="fas fa-flask"></i> Send Test Email</button>
                </div>
                {!settings.email_password && (
                  <div style={{ marginTop: '12px', padding: '12px', backgroundColor: '#FEF3C7', borderRadius: '6px', fontSize: '12px', color: '#92400E' }}>
                    <i className="fas fa-exclamation-triangle" style={{ marginRight: '8px' }}></i><strong>Email is in simulation mode.</strong> Add SMTP password above to enable real email sending.
                  </div>
                )}
              </div>
            </>
          )}

          {activeTab === 'hero-slider' && (
            <>
              <h3 style={{ marginBottom: '16px' }}>Hero Slider Management</h3>
              <p style={{ marginBottom: '16px', color: '#6B7280' }}>Manage images displayed in the hero section of the homepage.</p>
              
              {/* Add New Slide Form */}
              <div className="settings-section" style={{ marginBottom: '24px' }}>
                <h4 className="settings-title">Add New Slide</h4>
                <div className="form-group">
                  <label className="form-label">Upload Image</label>
                  <input 
                    type="file" 
                    className="form-input" 
                    id="new-slide-file" 
                    accept="image/jpeg,image/jpg,image/png,image/webp"
                  />
                  <small style={{ fontSize: '11px', color: '#6B7280' }}>Accepted: JPG, PNG, WEBP (Max 5MB)</small>
                </div>
                <div className="form-group">
                  <label className="form-label">Title (optional)</label>
                  <input type="text" className="form-input" id="new-slide-title" placeholder="Slide title" />
                </div>
                <div className="form-group">
                  <label className="form-label">Subtitle (optional)</label>
                  <input type="text" className="form-input" id="new-slide-subtitle" placeholder="Slide subtitle" />
                </div>
                <button className="btn btn-primary" onClick={async () => {
                  const fileInput = document.getElementById('new-slide-file');
                  const title = document.getElementById('new-slide-title').value;
                  const subtitle = document.getElementById('new-slide-subtitle').value;
                  const file = fileInput.files[0];
                  
                  if (!file) {
                    alert('Please select an image file');
                    return;
                  }
                  
                  // Validate file type
                  const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/webp'];
                  if (!allowedTypes.includes(file.type)) {
                    alert('Invalid file type. Please select JPG, PNG, or WEBP');
                    return;
                  }
                  
                  // Validate file size (5MB)
                  if (file.size > 5 * 1024 * 1024) {
                    alert('File too large. Maximum size is 5MB');
                    return;
                  }
                  
                  const formData = new FormData();
                  formData.append('image', file);
                  formData.append('title', title);
                  formData.append('subtitle', subtitle);
                  
                  try {
                    const token = localStorage.getItem('token');
                    const res = await fetch(`${API_URL}/admin/hero-slider`, {
                      method: 'POST',
                      headers: {
                        'Authorization': `Bearer ${token}`
                      },
                      body: formData
                    });
                    const data = await res.json();
                    
                    if (data.success) {
                      fileInput.value = '';
                      document.getElementById('new-slide-title').value = '';
                      document.getElementById('new-slide-subtitle').value = '';
                      loadData();
                      alert('Slide added successfully');
                    } else {
                      alert('Failed to add slide: ' + (data.error || 'Unknown error'));
                    }
                  } catch (err) {
                    alert('Failed to add slide: ' + err.message);
                  }
                }}><i className="fas fa-plus"></i> Upload Slide</button>
              </div>
              
              {/* Existing Slides */}
              <div className="settings-section">
                <h4 className="settings-title">Current Slides ({heroSlider.length})</h4>
                {heroSlider.length === 0 ? (
                  <p style={{ color: '#6B7280', textAlign: 'center', padding: '20px' }}>No slides added yet. Upload your first slide above.</p>
                ) : (
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(250px, 1fr))', gap: '16px' }}>
                    {heroSlider.map((slide) => (
                      <div key={slide.id} style={{ border: '1px solid #E5E7EB', borderRadius: '12px', overflow: 'hidden', background: 'white' }}>
                        <div style={{ height: '150px', backgroundImage: `url(${UPLOADS_URL}${slide.image_url?.replace('/uploads', '')})`, backgroundSize: 'cover', backgroundPosition: 'center', position: 'relative' }}>
                          <div style={{ position: 'absolute', top: '8px', right: '8px', display: 'flex', gap: '4px' }}>
                            <button 
                              onClick={async () => {
                                const newEnabled = slide.is_enabled ? 0 : 1;
                                await api.updateHeroSlider(slide.id, { is_enabled: newEnabled });
                                loadData();
                              }}
                              style={{ padding: '6px 10px', borderRadius: '6px', border: 'none', cursor: 'pointer', background: slide.is_enabled ? '#10B981' : '#EF4444', color: 'white', fontSize: '12px' }}
                            >
                              {slide.is_enabled ? 'Enabled' : 'Disabled'}
                            </button>
                          </div>
                        </div>
                        <div style={{ padding: '12px' }}>
                          {slide.title && <h5 style={{ margin: '0 0 4px 0', fontSize: '14px' }}>{slide.title}</h5>}
                          {slide.subtitle && <p style={{ margin: 0, fontSize: '12px', color: '#6B7280' }}>{slide.subtitle}</p>}
                          <div style={{ marginTop: '12px', display: 'flex', gap: '8px' }}>
                            <button 
                              onClick={async () => {
                                const newTitle = prompt('Enter new title:', slide.title || '');
                                if (newTitle !== null) {
                                  await api.updateHeroSlider(slide.id, { title: newTitle });
                                  loadData();
                                }
                              }}
                              style={{ flex: 1, padding: '6px', borderRadius: '6px', border: '1px solid #E5E7EB', background: 'white', cursor: 'pointer' }}
                            >
                              <i className="fas fa-edit"></i>
                            </button>
                            <button 
                              onClick={async () => {
                                if (confirm('Are you sure you want to delete this slide?')) {
                                  await api.deleteHeroSlider(slide.id);
                                  loadData();
                                }
                              }}
                              style={{ flex: 1, padding: '6px', borderRadius: '6px', border: '1px solid #EF4444', background: '#FEF2F2', color: '#EF4444', cursor: 'pointer' }}
                            >
                              <i className="fas fa-trash"></i>
                            </button>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </>
          )}

          {activeTab === 'shops' && (
            <div className="empty-state">
              <i className="fas fa-store"></i>
              <h3>Shop Management</h3>
              <p>Shop management features coming soon</p>
            </div>
          )}
        </div>
      </main>
    </div>
  );
};

// ==================== PROTECTED ROUTE ====================
const ProtectedRoute = ({ children, role }) => {
  const { user, loading } = useAuth();
  const location = useLocation();

  if (loading) return <LoadingSpinner />;
  
  if (!user) {
    return <Navigate to="/auth" state={{ from: location }} replace />;
  }

  if (role && user.role !== role) {
    return <Navigate to="/" replace />;
  }

  return children;
};

// ==================== APP ====================
function App() {
  return (
    <AuthProvider>
      <Router>
        <Routes>
          <Route path="/" element={<LandingPage />} />
          <Route path="/auth" element={<AuthPage />} />
          <Route path="/forgot-password" element={<ForgotPasswordPage />} />
          <Route path="/admin/auth" element={<AdminAuthPage />} />
          <Route path="/worker/auth" element={<WorkerAuthPage />} />
          <Route path="/shop/auth" element={<ShopAuthPage />} />
          <Route path="/dashboard" element={<ProtectedRoute><UserDashboard /></ProtectedRoute>} />
          <Route path="/booking/create" element={<ProtectedRoute><CreateBooking /></ProtectedRoute>} />
          <Route path="/booking/:id" element={<ProtectedRoute><BookingDetails /></ProtectedRoute>} />
          <Route path="/worker/dashboard" element={<ProtectedRoute role="worker"><WorkerDashboard /></ProtectedRoute>} />
          <Route path="/admin" element={<ProtectedRoute role="admin"><AdminDashboard /></ProtectedRoute>} />
          <Route path="/user/bookings" element={<ProtectedRoute><UserDashboard /></ProtectedRoute>} />
        </Routes>
      </Router>
    </AuthProvider>
  );
}

export default App;
