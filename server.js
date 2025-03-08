// Step 1: Import necessary modules
const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const cookieParser = require('cookie-parser');
const { createClient } = require('@supabase/supabase-js');

// Step 2: Initialize the Express application
const app = express();

// Step 3: Configure dotenv to load .env file
dotenv.config();

// Step 4: Initialize Supabase client
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_ANON_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

// Step 5: Define essential middlewares
app.use(express.json()); // Parses incoming JSON requests
app.use(cors({
  origin: true, // Allows all origins
  credentials: true, // Allows sending of cookies
}));
app.use(cookieParser()); // Parses cookies

// Step 6: Define authentication routes
// Login endpoint
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }
    
    // Authenticate with Supabase
    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password
    });
    
    if (error) {
      return res.status(401).json({ error: error.message });
    }
    
    // Set secure cookie with session token
    res.cookie('auth_token', data.session.access_token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 60 * 60 * 24 * 7 * 1000 // 1 week
    });
    
    return res.status(200).json({ 
      user: {
        id: data.user.id,
        email: data.user.email
      },
      message: 'Login successful'
    });
  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Get current user endpoint
app.get('/api/auth/user', async (req, res) => {
  try {
    const token = req.cookies.auth_token;
    
    if (!token) {
      return res.status(401).json({ error: 'Not authenticated' });
    }
    
    // Verify the token with Supabase
    const { data: { user }, error } = await supabase.auth.getUser(token);
    
    if (error || !user) {
      // Clear invalid cookie
      res.clearCookie('auth_token');
      return res.status(401).json({ error: 'Invalid or expired session' });
    }
    
    return res.status(200).json({ 
      user: {
        id: user.id,
        email: user.email
      }
    });
  } catch (error) {
    console.error('Get user error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Logout endpoint
app.post('/api/auth/logout', (req, res) => {
  try {
    // Clear the auth cookie
    res.clearCookie('auth_token');
    return res.status(200).json({ message: 'Logout successful' });
  } catch (error) {
    console.error('Logout error:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Step 7: Define a simple route (optional)
app.get('/', (req, res) => {
  res.send('Express server is running!');
});

// Step 8: Start the server
const port = process.env.PORT || 5000;
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});