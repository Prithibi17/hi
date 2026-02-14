import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import axios from 'axios';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:3001/api';

// Simple inline logo component
const OneHiveLogo = ({ size = 'medium' }) => {
  const sizes = {
    small: 28,
    medium: 36,
    large: 48
  };
  const iconSize = sizes[size] || sizes.medium;
  
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
      <svg 
        width={iconSize} 
        height={iconSize} 
        viewBox="0 0 64 64" 
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
      >
        <path d="M32 4L44 14V30L32 40L20 30V14L32 4Z" fill="#E5A84B"/>
        <path d="M32 16L38 22V30L32 36L26 30V22L32 16Z" fill="#D4A574"/>
        <ellipse cx="32" cy="28" rx="4" ry="8" fill="#2D3436"/>
        <circle cx="29" cy="26" r="1.5" fill="#2D3436"/>
        <circle cx="35" cy="26" r="1.5" fill="#2D3436"/>
      </svg>
      <span style={{ 
        fontSize: size === 'large' ? '1.8rem' : '1.4rem', 
        fontWeight: '700', 
        color: '#B8956A',
        letterSpacing: '-0.5px'
      }}>
        OneHive
      </span>
    </div>
  );
};

const api = {
  register: (data) => axios.post(`${API_URL}/auth/register`, data),
  login: (data) => axios.post(`${API_URL}/auth/login`, data),
  registerShop: (data) => axios.post(`${API_URL}/shop/register`, data),
};

const ShopAuthPage = () => {
  const [isLogin, setIsLogin] = useState(true);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [formData, setFormData] = useState({
    name: '', email: '', password: '', phone: '', address: '', city: '', owner_name: ''
  });
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      if (isLogin) {
        const res = await api.login({ email: formData.email, password: formData.password });
        localStorage.setItem('token', res.data.token);
        localStorage.setItem('user', JSON.stringify(res.data.user));
      } else {
        const res = await api.register({ ...formData, role: 'shop' });
        await api.registerShop({ name: formData.name, email: formData.email, phone: formData.phone, address: formData.address, city: formData.city, owner_name: formData.owner_name });
        localStorage.setItem('token', res.data.token);
        localStorage.setItem('user', JSON.stringify(res.data.user));
      }
      navigate('/dashboard');
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
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: '20px' }}>
            <OneHiveLogo size="large" />
          </div>
          <h1>{isLogin ? 'Shop Login' : 'Register Your Shop'}</h1>
          <p>{isLogin ? 'Sign in to manage your shop' : 'Join our network of partner shops'}</p>
        </div>

        {error && <div className="alert alert-error">{error}</div>}

        <div className="auth-tabs">
          <button className={`auth-tab ${isLogin ? 'active' : ''}`} onClick={() => setIsLogin(true)}>Login</button>
          <button className={`auth-tab ${!isLogin ? 'active' : ''}`} onClick={() => setIsLogin(false)}>Register</button>
        </div>

        <form onSubmit={handleSubmit}>
          {!isLogin && (
            <>
              <div className="form-group">
                <label className="form-label">Shop Name</label>
                <input type="text" className="form-input" placeholder="Enter shop name" value={formData.name} onChange={(e) => setFormData({ ...formData, name: e.target.value })} />
              </div>
              <div className="form-group">
                <label className="form-label">Owner Name</label>
                <input type="text" className="form-input" placeholder="Enter owner name" value={formData.owner_name} onChange={(e) => setFormData({ ...formData, owner_name: e.target.value })} />
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
                <label className="form-label">Address</label>
                <textarea className="form-textarea" placeholder="Enter shop address" value={formData.address} onChange={(e) => setFormData({ ...formData, address: e.target.value })}></textarea>
              </div>
              <div className="form-group">
                <label className="form-label">Phone Number</label>
                <input type="tel" className="form-input" placeholder="Enter phone number" value={formData.phone} onChange={(e) => setFormData({ ...formData, phone: e.target.value })} />
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
            {loading ? 'Please wait...' : (isLogin ? 'Sign In' : 'Register Shop')}
          </button>
        </form>

        <p style={{ textAlign: 'center', marginTop: '24px' }}><Link to="/" style={{ color: '#D4A574' }}>← Back to Home</Link></p>
      </div>
    </div>
  );
};

export default ShopAuthPage;
