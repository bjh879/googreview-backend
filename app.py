import os
import hashlib
import secrets

import psycopg
from psycopg.rows import dict_row
import stripe
from dotenv import load_dotenv
from flask import Flask, request, jsonify
from flask_cors import CORS
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()

app = Flask(__name__)
CORS(app)

stripe.api_key = os.getenv('STRIPE_SECRET_KEY')
FRONTEND_URL = os.getenv('FRONTEND_URL', 'https://googreview.com').rstrip('/')

# Login tokens are signed, so they survive Render restarts and sleep.
_secret = os.getenv('SECRET_KEY') or hashlib.sha256(
    (os.getenv('DATABASE_URL', '') + 'reviewvault').encode()
).hexdigest()
signer = URLSafeTimedSerializer(_secret, salt='owner-session')
TOKEN_MAX_AGE = 60 * 60 * 24 * 30  # 30 days


def get_db():
    return psycopg.connect(os.getenv('DATABASE_URL'), row_factory=dict_row)


def make_token(owner_id):
    return signer.dumps({'owner_id': owner_id})


def current_owner_id():
    token = request.headers.get('X-Session-Token', '')
    if not token:
        return None
    try:
        return signer.loads(token, max_age=TOKEN_MAX_AGE)['owner_id']
    except (BadSignature, SignatureExpired, KeyError, TypeError):
        return None


def new_business_code(cur):
    while True:
        code = secrets.token_hex(4)
        cur.execute('SELECT 1 FROM owners WHERE business_id = %s', (code,))
        if not cur.fetchone():
            return code


def public_owner(row):
    return {
        'id': row['id'],
        'email': row['email'],
        'business_name': row['business_name'],
        'business_id': row['business_id'],
        'subscription_status': row['subscription_status'],
    }


def serialize_review(row):
    return {
        'id': row['id'],
        'rating': row['rating'],
        'text': row['text'],
        'status': row['status'],
        'submitted_at': row['submitted_at'].isoformat() if row.get('submitted_at') else None,
    }


# ============ OWNER ENDPOINTS ============

@app.route('/api/owners/signup', methods=['POST'])
def owner_signup():
    data = request.get_json(silent=True) or {}
    email = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''
    business_name = (data.get('businessName') or '').strip()

    if not email or not business_name or len(password) < 6:
        return jsonify({'error': 'Email, business name and a 6+ character password are required'}), 400

    try:
        with get_db() as conn, conn.cursor() as cur:
            cur.execute('SELECT 1 FROM owners WHERE email = %s', (email,))
            if cur.fetchone():
                return jsonify({'error': 'An account with that email already exists'}), 409
            code = new_business_code(cur)
            cur.execute(
                'INSERT INTO owners (email, password_hash, business_name, business_id) '
                'VALUES (%s, %s, %s, %s) RETURNING *',
                (email, generate_password_hash(password), business_name, code),
            )
            owner = cur.fetchone()
        return jsonify({'success': True, 'token': make_token(owner['id']), 'owner': public_owner(owner)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/owners/login', methods=['POST'])
def owner_login():
    data = request.get_json(silent=True) or {}
    email = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''

    try:
        with get_db() as conn, conn.cursor() as cur:
            cur.execute('SELECT * FROM owners WHERE email = %s', (email,))
            owner = cur.fetchone()
        if not owner or not check_password_hash(owner['password_hash'], password):
            return jsonify({'error': 'Invalid email or password'}), 401
        return jsonify({'success': True, 'token': make_token(owner['id']), 'owner': public_owner(owner)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/owners/dashboard', methods=['GET'])
def owner_dashboard():
    owner_id = current_owner_id()
    if not owner_id:
        return jsonify({'error': 'Unauthorized'}), 401
    try:
        with get_db() as conn, conn.cursor() as cur:
            cur.execute('SELECT * FROM owners WHERE id = %s', (owner_id,))
            owner = cur.fetchone()
            if not owner:
                return jsonify({'error': 'Unauthorized'}), 401
            cur.execute(
                'SELECT status, COUNT(*) AS count FROM reviews WHERE owner_id = %s GROUP BY status',
                (owner_id,),
            )
            stats = {r['status']: r['count'] for r in cur.fetchall()}
            cur.execute(
                "SELECT * FROM reviews WHERE owner_id = %s AND status = 'pending' "
                'ORDER BY submitted_at DESC',
                (owner_id,),
            )
            pending = [serialize_review(r) for r in cur.fetchall()]
        return jsonify({
            'owner': public_owner(owner),
            'stats': stats,
            'pending_reviews': pending,
            'portal_url': f"{FRONTEND_URL}/portal.html?b={owner['business_id']}",
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============ REVIEW ENDPOINTS ============

@app.route('/api/business/<business_id>', methods=['GET'])
def business_info(business_id):
    try:
        with get_db() as conn, conn.cursor() as cur:
            cur.execute('SELECT business_name FROM owners WHERE business_id = %s', (business_id,))
            owner = cur.fetchone()
        if not owner:
            return jsonify({'error': 'Business not found'}), 404
        return jsonify({'business_name': owner['business_name']})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/reviews/<business_id>', methods=['POST'])
def submit_review(business_id):
    data = request.get_json(silent=True) or {}
    try:
        rating = int(data.get('rating'))
    except (TypeError, ValueError):
        rating = 0
    text = (data.get('text') or '').strip()
    name = (data.get('name') or '').strip()

    if rating < 1 or rating > 5:
        return jsonify({'error': 'Rating must be 1 to 5 stars'}), 400
    if name:
        text = f'{text}\n\n— {name}' if text else f'— {name}'

    try:
        with get_db() as conn, conn.cursor() as cur:
            cur.execute('SELECT id FROM owners WHERE business_id = %s', (business_id,))
            owner = cur.fetchone()
            if not owner:
                return jsonify({'error': 'Business not found'}), 404
            cur.execute(
                "INSERT INTO reviews (owner_id, rating, text, status) VALUES (%s, %s, %s, 'pending') RETURNING id",
                (owner['id'], rating, text),
            )
            review_id = cur.fetchone()['id']
        return jsonify({'success': True, 'review_id': review_id})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/business/<business_id>/reviews', methods=['GET'])
def approved_reviews(business_id):
    try:
        with get_db() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT r.* FROM reviews r JOIN owners o ON o.id = r.owner_id "
                "WHERE o.business_id = %s AND r.status = 'approved' ORDER BY r.submitted_at DESC",
                (business_id,),
            )
            rows = cur.fetchall()
        return jsonify([serialize_review(r) for r in rows])
    except Exception as e:
        return jsonify({'error': str(e)}), 500


def _set_review_status(review_id, status):
    owner_id = current_owner_id()
    if not owner_id:
        return jsonify({'error': 'Unauthorized'}), 401
    try:
        with get_db() as conn, conn.cursor() as cur:
            cur.execute(
                'UPDATE reviews SET status = %s, updated_at = NOW(), '
                "approved_at = CASE WHEN %s = 'approved' THEN NOW() ELSE approved_at END "
                'WHERE id = %s AND owner_id = %s',
                (status, status, review_id, owner_id),
            )
            if cur.rowcount == 0:
                return jsonify({'error': 'Review not found'}), 404
            cur.execute(
                'INSERT INTO audit_logs (owner_id, action, review_id) VALUES (%s, %s, %s)',
                (owner_id, status, review_id),
            )
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/reviews/<int:review_id>/approve', methods=['POST'])
def approve_review(review_id):
    return _set_review_status(review_id, 'approved')


@app.route('/api/reviews/<int:review_id>/reject', methods=['POST'])
def reject_review(review_id):
    return _set_review_status(review_id, 'rejected')


# ============ PAYMENT ENDPOINTS ============

@app.route('/api/checkout', methods=['POST'])
def create_checkout():
    owner_id = current_owner_id()
    if not owner_id:
        return jsonify({'error': 'Unauthorized'}), 401
    try:
        with get_db() as conn, conn.cursor() as cur:
            cur.execute('SELECT email, stripe_customer_id FROM owners WHERE id = %s', (owner_id,))
            owner = cur.fetchone()
        params = dict(
            mode='subscription',
            line_items=[{'price': os.getenv('STRIPE_PRICE_ID'), 'quantity': 1}],
            client_reference_id=str(owner_id),
            success_url=f'{FRONTEND_URL}/dashboard.html?paid=1',
            cancel_url=f'{FRONTEND_URL}/dashboard.html',
        )
        if owner and owner['stripe_customer_id']:
            params['customer'] = owner['stripe_customer_id']
        elif owner:
            params['customer_email'] = owner['email']
        session = stripe.checkout.Session.create(**params)
        return jsonify({'url': session.url})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/webhook/stripe', methods=['POST'])
def stripe_webhook():
    try:
        event = stripe.Webhook.construct_event(
            request.data,
            request.headers.get('stripe-signature'),
            os.getenv('STRIPE_WEBHOOK_SECRET'),
        )
    except Exception as e:
        return jsonify({'error': str(e)}), 400

    obj = event['data']['object']
    try:
        with get_db() as conn, conn.cursor() as cur:
            if event['type'] == 'checkout.session.completed' and obj.get('client_reference_id'):
                cur.execute(
                    "UPDATE owners SET stripe_customer_id = %s, subscription_status = 'active', "
                    'updated_at = NOW() WHERE id = %s',
                    (obj.get('customer'), int(obj['client_reference_id'])),
                )
            elif event['type'] in ('customer.subscription.updated', 'customer.subscription.deleted'):
                status = 'active' if obj.get('status') in ('active', 'trialing') else 'canceled'
                cur.execute(
                    'UPDATE owners SET subscription_status = %s, updated_at = NOW() WHERE stripe_customer_id = %s',
                    (status, obj.get('customer')),
                )
        return jsonify({'received': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok'})


if __name__ == '__main__':
    port = int(os.getenv('PORT', 3000))
    app.run(host='0.0.0.0', port=port, debug=False)
