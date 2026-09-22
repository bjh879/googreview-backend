import os
from flask import Flask, request, jsonify
from flask_cors import CORS
import psycopg2
import stripe
from dotenv import load_dotenv
import secrets
import base64

load_dotenv()

app = Flask(__name__)
CORS(app)

# Stripe setup
stripe.api_key = os.getenv('STRIPE_SECRET_KEY')

# Database connection
def get_db():
    return psycopg2.connect(os.getenv('DATABASE_URL'))

# Simple session storage
sessions = {}

def generate_token():
    return secrets.token_hex(32)

def validate_session(req):
    token = req.headers.get('X-Session-Token')
    return sessions.get(token)

# ============ OWNER ENDPOINTS ============

@app.route('/api/owners/signup', methods=['POST'])
def owner_signup():
    try:
        data = request.json
        email = data.get('email')
        password = data.get('password')
        business_name = data.get('businessName')
        
        # Hash password (simple base64 for now)
        hashed_pwd = base64.b64encode(password.encode()).decode()
        
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            'INSERT INTO owners (email, password, business_name) VALUES (%s, %s, %s) RETURNING id, email',
            (email, hashed_pwd, business_name)
        )
        owner = cur.fetchone()
        conn.commit()
        cur.close()
        conn.close()
        
        token = generate_token()
        sessions[token] = {'owner_id': owner[0]}
        
        return jsonify({'success': True, 'token': token, 'owner': {'id': owner[0], 'email': owner[1]}})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/owners/login', methods=['POST'])
def owner_login():
    try:
        data = request.json
        email = data.get('email')
        password = data.get('password')
        hashed_pwd = base64.b64encode(password.encode()).decode()
        
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            'SELECT id, email FROM owners WHERE email = %s AND password = %s',
            (email, hashed_pwd)
        )
        owner = cur.fetchone()
        cur.close()
        conn.close()
        
        if not owner:
            return jsonify({'error': 'Invalid credentials'}), 401
        
        token = generate_token()
        sessions[token] = {'owner_id': owner[0]}
        
        return jsonify({'success': True, 'token': token, 'owner': {'id': owner[0], 'email': owner[1]}})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/owners/dashboard', methods=['GET'])
def owner_dashboard():
    try:
        session = validate_session(request)
        if not session:
            return jsonify({'error': 'Unauthorized'}), 401
        
        owner_id = session['owner_id']
        
        conn = get_db()
        cur = conn.cursor()
        cur.execute('SELECT * FROM owners WHERE id = %s', (owner_id,))
        owner = cur.fetchone()
        
        cur.execute(
            'SELECT status, COUNT(*) as count FROM reviews WHERE owner_id = %s GROUP BY status',
            (owner_id,)
        )
        stats = cur.fetchall()
        cur.close()
        conn.close()
        
        return jsonify({'owner': owner, 'stats': stats})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# ============ REVIEW ENDPOINTS ============

@app.route('/api/reviews/<int:business_id>', methods=['POST'])
def submit_review(business_id):
    try:
        data = request.json
        rating = data.get('rating')
        comment = data.get('comment')
        name = data.get('name')
        email = data.get('email')
        
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            'INSERT INTO reviews (owner_id, rating, comment, customer_name, customer_email, status) VALUES (%s, %s, %s, %s, %s, %s) RETURNING id',
            (business_id, rating, comment, name, email, 'pending')
        )
        review_id = cur.fetchone()[0]
        conn.commit()
        cur.close()
        conn.close()
        
        return jsonify({'success': True, 'review_id': review_id})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/business/<int:business_id>/reviews', methods=['GET'])
def get_reviews(business_id):
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            'SELECT * FROM reviews WHERE owner_id = %s ORDER BY created_at DESC',
            (business_id,)
        )
        reviews = cur.fetchall()
        cur.close()
        conn.close()
        
        return jsonify(reviews)
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/reviews/<int:review_id>/approve', methods=['POST'])
def approve_review(review_id):
    try:
        session = validate_session(request)
        if not session:
            return jsonify({'error': 'Unauthorized'}), 401
        
        owner_id = session['owner_id']
        
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            'UPDATE reviews SET status = %s, updated_at = NOW() WHERE id = %s AND owner_id = %s',
            ('approved', review_id, owner_id)
        )
        conn.commit()
        cur.close()
        conn.close()
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/reviews/<int:review_id>/reject', methods=['POST'])
def reject_review(review_id):
    try:
        session = validate_session(request)
        if not session:
            return jsonify({'error': 'Unauthorized'}), 401
        
        owner_id = session['owner_id']
        
        conn = get_db()
        cur = conn.cursor()
        cur.execute(
            'UPDATE reviews SET status = %s, updated_at = NOW() WHERE id = %s AND owner_id = %s',
            ('rejected', review_id, owner_id)
        )
        conn.commit()
        cur.close()
        conn.close()
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# ============ PAYMENT ENDPOINTS ============

@app.route('/api/checkout', methods=['POST'])
def create_checkout():
    try:
        session = validate_session(request)
        if not session:
            return jsonify({'error': 'Unauthorized'}), 401
        
        owner_id = session['owner_id']
        
        conn = get_db()
        cur = conn.cursor()
        cur.execute('SELECT stripe_customer_id FROM owners WHERE id = %s', (owner_id,))
        customer_id = cur.fetchone()[0]
        cur.close()
        conn.close()
        
        checkout_session = stripe.checkout.Session.create(
            customer=customer_id,
            payment_method_types=['card'],
            line_items=[{
                'price': os.getenv('STRIPE_PRICE_ID'),
                'quantity': 1
            }],
            mode='subscription',
            success_url='https://googreview.com/success',
            cancel_url='https://googreview.com/cancel'
        )
        
        return jsonify({'url': checkout_session.url})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/webhook/stripe', methods=['POST'])
def stripe_webhook():
    try:
        sig = request.headers.get('stripe-signature')
        payload = request.data
        
        event = stripe.Webhook.construct_event(
            payload, sig, os.getenv('STRIPE_WEBHOOK_SECRET')
        )
        
        if event['type'] == 'customer.subscription.updated':
            customer_id = event['data']['object']['customer']
            
            conn = get_db()
            cur = conn.cursor()
            cur.execute(
                'UPDATE owners SET subscription_status = %s, subscription_updated_at = NOW() WHERE stripe_customer_id = %s',
                ('active', customer_id)
            )
            conn.commit()
            cur.close()
            conn.close()
        
        return jsonify({'received': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok'})

if __name__ == '__main__':
    port = int(os.getenv('PORT', 3000))
    app.run(host='0.0.0.0', port=port, debug=False)
