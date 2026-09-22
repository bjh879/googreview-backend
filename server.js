// ReviewVault Backend Server
// npm install express cors dotenv pg stripe jsonwebtoken bcryptjs qrcode
// Run: node server.js

const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const { Pool } = require('pg');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const jwt = require('jsonwebtoken');
const bcryptjs = require('bcryptjs');

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// ============ AUTHENTICATION ============

const generateToken = (userId) => {
  return jwt.sign({ userId }, process.env.JWT_SECRET, { expiresIn: '30d' });
};

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Access token required' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

// ============ OWNER ROUTES ============

// Owner signup
app.post('/api/owners/signup', async (req, res) => {
  try {
    const { email, password, businessName } = req.body;

    // Check if owner exists
    const existing = await pool.query('SELECT id FROM owners WHERE email = $1', [email]);
    if (existing.rows.length > 0) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    // Hash password
    const hashedPassword = await bcryptjs.hash(password, 10);
    const businessId = Math.random().toString(36).substr(2, 9);

    // Create owner
    const ownerResult = await pool.query(
      'INSERT INTO owners (email, password_hash, business_name, business_id) VALUES ($1, $2, $3, $4) RETURNING id, email, business_id',
      [email, hashedPassword, businessName, businessId]
    );

    const owner = ownerResult.rows[0];
    const token = generateToken(owner.id);

    // Create Stripe customer
    const customer = await stripe.customers.create({
      email: email,
      metadata: { businessId: owner.id }
    });

    // Update owner with Stripe customer ID
    await pool.query('UPDATE owners SET stripe_customer_id = $1 WHERE id = $2', 
      [customer.id, owner.id]);

    res.json({
      message: 'Account created',
      token,
      owner: {
        id: owner.id,
        email: owner.email,
        businessId: owner.business_id,
        businessName: businessName
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Signup failed' });
  }
});

// Owner login
app.post('/api/owners/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const result = await pool.query('SELECT id, email, business_id, business_name, password_hash FROM owners WHERE email = $1', [email]);
    
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const owner = result.rows[0];
    const validPassword = await bcryptjs.compare(password, owner.password_hash);

    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = generateToken(owner.id);

    res.json({
      token,
      owner: {
        id: owner.id,
        email: owner.email,
        businessId: owner.business_id,
        businessName: owner.business_name
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Get owner dashboard
app.get('/api/owners/dashboard', authenticateToken, async (req, res) => {
  try {
    const owner = await pool.query('SELECT * FROM owners WHERE id = $1', [req.user.userId]);
    
    if (owner.rows.length === 0) {
      return res.status(404).json({ error: 'Owner not found' });
    }

    const ownerData = owner.rows[0];

    // Get all reviews
    const reviews = await pool.query(
      'SELECT * FROM reviews WHERE owner_id = $1 ORDER BY submitted_at DESC',
      [req.user.userId]
    );

    // Get stats
    const stats = await pool.query(
      `SELECT 
        COUNT(*) FILTER (WHERE status = 'pending') as pending,
        COUNT(*) FILTER (WHERE status = 'approved') as approved,
        COUNT(*) FILTER (WHERE status = 'rejected') as rejected,
        ROUND(AVG(rating)::numeric, 1) as avg_rating
      FROM reviews WHERE owner_id = $1`,
      [req.user.userId]
    );

    res.json({
      owner: {
        id: ownerData.id,
        email: ownerData.email,
        businessName: ownerData.business_name,
        businessId: ownerData.business_id,
        portalUrl: `${process.env.FRONTEND_URL}/business/${ownerData.business_id}`,
        subscription: ownerData.subscription_status
      },
      stats: stats.rows[0],
      reviews: reviews.rows
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to load dashboard' });
  }
});

// ============ REVIEW ROUTES ============

// Submit review (customer)
app.post('/api/reviews/:businessId', async (req, res) => {
  try {
    const { businessId } = req.params;
    const { rating, text } = req.body;

    // Get owner by business ID
    const owner = await pool.query('SELECT id FROM owners WHERE business_id = $1', [businessId]);
    
    if (owner.rows.length === 0) {
      return res.status(404).json({ error: 'Business not found' });
    }

    const ownerId = owner.rows[0].id;

    // Create review
    const review = await pool.query(
      `INSERT INTO reviews (owner_id, rating, text, status, submitted_at) 
       VALUES ($1, $2, $3, 'pending', NOW()) 
       RETURNING id, rating, text, status, submitted_at`,
      [ownerId, rating, text]
    );

    res.json({
      message: 'Review submitted and pending approval',
      review: review.rows[0]
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to submit review' });
  }
});

// Get reviews for business (customer portal)
app.get('/api/business/:businessId/reviews', async (req, res) => {
  try {
    const { businessId } = req.params;

    const owner = await pool.query('SELECT id, business_name FROM owners WHERE business_id = $1', [businessId]);
    
    if (owner.rows.length === 0) {
      return res.status(404).json({ error: 'Business not found' });
    }

    const ownerId = owner.rows[0].id;

    // Get approved reviews only (for customers to see)
    const reviews = await pool.query(
      `SELECT id, rating, text, submitted_at FROM reviews 
       WHERE owner_id = $1 AND status = 'approved'
       ORDER BY submitted_at DESC LIMIT 10`,
      [ownerId]
    );

    // Calculate stats
    const stats = await pool.query(
      `SELECT 
        COUNT(*) as total,
        ROUND(AVG(rating)::numeric, 1) as avg_rating
       FROM reviews WHERE owner_id = $1 AND status = 'approved'`,
      [ownerId]
    );

    res.json({
      business: {
        name: owner.rows[0].business_name,
        businessId: businessId
      },
      stats: stats.rows[0],
      reviews: reviews.rows
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to load reviews' });
  }
});

// Approve review
app.post('/api/reviews/:reviewId/approve', authenticateToken, async (req, res) => {
  try {
    const { reviewId } = req.params;

    // Verify ownership
    const review = await pool.query(
      'SELECT * FROM reviews WHERE id = $1 AND owner_id = $2',
      [reviewId, req.user.userId]
    );

    if (review.rows.length === 0) {
      return res.status(404).json({ error: 'Review not found or access denied' });
    }

    // Update status
    const updated = await pool.query(
      `UPDATE reviews SET status = 'approved', approved_at = NOW() 
       WHERE id = $1 RETURNING id, status`,
      [reviewId]
    );

    // TODO: Sync to Google My Business API here
    // For now, just update local status

    res.json({
      message: 'Review approved and will post to Google',
      review: updated.rows[0]
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to approve review' });
  }
});

// Reject review
app.post('/api/reviews/:reviewId/reject', authenticateToken, async (req, res) => {
  try {
    const { reviewId } = req.params;

    const review = await pool.query(
      'SELECT * FROM reviews WHERE id = $1 AND owner_id = $2',
      [reviewId, req.user.userId]
    );

    if (review.rows.length === 0) {
      return res.status(404).json({ error: 'Review not found or access denied' });
    }

    const updated = await pool.query(
      `UPDATE reviews SET status = 'rejected' WHERE id = $1 RETURNING id, status`,
      [reviewId]
    );

    res.json({
      message: 'Review rejected',
      review: updated.rows[0]
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to reject review' });
  }
});

// ============ PAYMENT ROUTES ============

// Create Stripe checkout session
app.post('/api/checkout', authenticateToken, async (req, res) => {
  try {
    const owner = await pool.query('SELECT stripe_customer_id FROM owners WHERE id = $1', [req.user.userId]);
    
    if (owner.rows.length === 0) {
      return res.status(404).json({ error: 'Owner not found' });
    }

    const session = await stripe.checkout.sessions.create({
      customer: owner.rows[0].stripe_customer_id,
      payment_method_types: ['card'],
      mode: 'subscription',
      line_items: [
        {
          price: process.env.STRIPE_PRICE_ID, // e.g., price_1234567890
          quantity: 1
        }
      ],
      success_url: `${process.env.FRONTEND_URL}/payment/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.FRONTEND_URL}/payment/cancel`
    });

    res.json({ checkoutUrl: session.url });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to create checkout' });
  }
});

// Handle Stripe webhook
app.post('/api/webhook/stripe', express.raw({type: 'application/json'}), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;

  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  // Handle subscription events
  if (event.type === 'customer.subscription.created' || event.type === 'customer.subscription.updated') {
    const subscription = event.data.object;
    const status = subscription.status === 'active' ? 'active' : 'inactive';

    await pool.query(
      'UPDATE owners SET subscription_status = $1 WHERE stripe_customer_id = $2',
      [status, subscription.customer]
    );
  }

  if (event.type === 'customer.subscription.deleted') {
    await pool.query(
      'UPDATE owners SET subscription_status = $1 WHERE stripe_customer_id = $2',
      ['inactive', event.data.object.customer]
    );
  }

  res.json({received: true});
});

// ============ HEALTH CHECK ============

app.get('/api/health', (req, res) => {
  res.json({ status: 'OK' });
});

// ============ ERROR HANDLING ============

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Internal server error' });
});

// ============ START SERVER ============

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`ReviewVault server running on port ${PORT}`);
});
