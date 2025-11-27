from flask import Flask, render_template, request, redirect, url_for, jsonify, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from dotenv import load_dotenv
from supabase import create_client, Client
import secrets
import random
import os

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = 'sb_secret_2SAEBmix58tIo2QP3A6JyA_QFZgWJSB'

# ⚠️ HARDCODED CREDENTIALS (Replace with yours!)
SUPABASE_URL = "https://bfbtxwptcomtejzaoiat.supabase.co"
SUPABASE_KEY = "sb_publishable_Kd7T33DlrRkTULWWxZipkQ_Tew9odj1"
print(f"SUPABASE_URL: {SUPABASE_URL}")
print(f"SUPABASE_KEY: {'*' * 20}")

# Initialize Supabase client
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
print("✅ Supabase connected successfully!")

# Check if credentials exist
if not SUPABASE_URL or not SUPABASE_KEY:
    raise Exception("❌ Missing Supabase credentials! Check your .env file")

# Initialize Supabase client
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
print("✅ Supabase connected successfully!")

# ==================== HELPER FUNCTIONS ====================

def parse_datetime(dt_string):
    """Convert ISO datetime string to datetime object"""
    if not dt_string:
        return None
    return datetime.fromisoformat(dt_string.replace('Z', '+00:00'))

# ==================== CONTEXT PROCESSOR ====================

@app.context_processor
def inject_user():
    user = None
    if 'user_id' in session:
        response = supabase.table('users').select('*').eq('id', session['user_id']).execute()
        user = response.data[0] if response.data else None
    return dict(current_user=user)

# ==================== ROUTES ====================

@app.route('/')
def index():
    return render_template('main.html')

@app.route('/scan')
def scan():
    return render_template('index.html')

@app.route('/offers')
def offers():
    return render_template('main.html')

@app.route('/generate-offer', methods=['POST'])
def generate_offer():
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Please login first', 'redirect': '/login'})
    
    data = request.get_json() if request.is_json else {}
    qr_code = data.get('qr_code', None)
    
    # Check if user already scanned this QR code
    if qr_code:
        existing = supabase.table('qr_scans').select('*').eq('qr_code', qr_code).eq('user_id', session['user_id']).execute()
        if existing.data:
            return jsonify({
                'success': False,
                'message': 'You have already scanned this QR code! You can only redeem each QR code once.',
                'already_used': True
            })
    
    offers_list = [
        {'type': 'coffee', 'title': 'Buy 2 Get 1 Free - Coffee', 'description': 'Purchase any 2 coffees and get 1 coffee absolutely free!'},
        {'type': 'noodles', 'title': 'Buy 2 Get 1 Free - Noodles', 'description': 'Get a free noodles bowl when you buy 2 noodles!'},
        {'type': 'chilli_potato', 'title': 'Buy 2 Get 1 Free - Chilli Potato', 'description': 'Enjoy 1 free chilli potato with purchase of 2!'}
    ]
    
    selected_offer = random.choice(offers_list)
    redeem_code = secrets.token_hex(6).upper()
    scan_time = datetime.utcnow()
    expires_at = scan_time + timedelta(days=7)
    
    # Create new offer
    new_offer = {
        'user_id': session['user_id'],
        'offer_type': selected_offer['type'],
        'offer_title': selected_offer['title'],
        'redeem_code': redeem_code,
        'scanned_at': scan_time.isoformat(),
        'expires_at': expires_at.isoformat(),
        'qr_code': qr_code
    }
    
    supabase.table('offers').insert(new_offer).execute()
    
    # Record QR scan
    if qr_code:
        qr_scan = {
            'qr_code': qr_code,
            'user_id': session['user_id'],
            'scanned_at': scan_time.isoformat()
        }
        supabase.table('qr_scans').insert(qr_scan).execute()
    
    return jsonify({
        'success': True,
        'offer': selected_offer,
        'redeem_code': redeem_code,
        'scanned_at': scan_time.strftime('%Y-%m-%d %H:%M'),
        'expires_at': expires_at.strftime('%Y-%m-%d %H:%M'),
        'valid_days': 7
    })

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        print(f"🔍 Login attempt - Email: {email}")
        
        try:
            response = supabase.table('users').select('*').eq('email', email).execute()
            print(f"📊 Database response: {response.data}")
            
            user = response.data[0] if response.data else None
            
            if user:
                print(f"✅ User found: {user['username']}")
                print(f"🔐 Checking password...")
                
                if check_password_hash(user['password'], password):
                    print("✅ Password correct!")
                    session['user_id'] = user['id']
                    session['username'] = user['username']
                    session['account_type'] = user['account_type']
                    
                    print(f"👤 Account type: {user['account_type']}")
                    
                    if user['account_type'] == 'admin':
                        print("➡️ Redirecting to admin dashboard")
                        return redirect(url_for('admin_dashboard'))
                    elif user['account_type'] == 'cafe':
                        print("➡️ Redirecting to cafe dashboard")
                        return redirect(url_for('cafe_dashboard'))
                    else:
                        print("➡️ Redirecting to user dashboard")
                        return redirect(url_for('user_dashboard'))
                else:
                    print("❌ Password incorrect")
                    flash('Invalid email or password', 'error')
            else:
                print("❌ User not found")
                flash('Invalid email or password', 'error')
                
        except Exception as e:
            print(f"🚨 ERROR: {str(e)}")
            flash(f'Login error: {str(e)}', 'error')
    
    return render_template('login.html')
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        # Check if email exists
        email_check = supabase.table('users').select('*').eq('email', email).execute()
        if email_check.data:
            flash('Email already exists', 'error')
            return redirect(url_for('signup'))
        
        # Check if username exists
        username_check = supabase.table('users').select('*').eq('username', username).execute()
        if username_check.data:
            flash('Username already exists', 'error')
            return redirect(url_for('signup'))
        
        hashed_password = generate_password_hash(password)
        new_user = {
            'username': username,
            'email': email,
            'password': hashed_password
        }
        
        supabase.table('users').insert(new_user).execute()
        flash('Account created successfully! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('signup.html')
@app.route('/user-dashboard')
def user_dashboard():
    print("🔍 User dashboard accessed")
    print(f"Session user_id: {session.get('user_id')}")
    print(f"Session account_type: {session.get('account_type')}")
    
    if 'user_id' not in session:
        print("❌ No user_id in session - redirecting to login")
        return redirect(url_for('login'))
    
    if session.get('account_type') != 'user':
        print(f"❌ Wrong account type: {session.get('account_type')}")
        flash('Access denied. This is a user-only page.', 'error')
        return redirect(url_for('login'))
    
    try:
        print(f"📊 Fetching user with ID: {session['user_id']}")
        user_response = supabase.table('users').select('*').eq('id', session['user_id']).execute()
        print(f"✅ User response: {user_response.data}")
        
        user = user_response.data[0] if user_response.data else None
        
        if not user:
            print("❌ User not found in database")
            session.clear()
            flash('User not found. Please login again.', 'error')
            return redirect(url_for('login'))
        
        print(f"✅ User found: {user['username']}")
        
        # Get offers
        print(f"📊 Fetching offers for user_id: {user['id']}")
        offers_response = supabase.table('offers').select('*').eq('user_id', user['id']).order('scanned_at', desc=True).execute()
        offers_list = offers_response.data
        print(f"✅ Found {len(offers_list)} offers")
        
        # Convert ISO datetime strings to datetime objects
        for offer in offers_list:
            print(f"🔄 Converting dates for offer: {offer['id']}")
            offer['scanned_at'] = parse_datetime(offer['scanned_at'])
            offer['expires_at'] = parse_datetime(offer['expires_at'])
            if offer.get('redeemed_at'):
                offer['redeemed_at'] = parse_datetime(offer['redeemed_at'])
        
        # Calculate stats
        now = datetime.utcnow()
        active_offers = [o for o in offers_list if not o['is_redeemed'] and o['expires_at'] > now]
        expired_offers = [o for o in offers_list if not o['is_redeemed'] and o['expires_at'] <= now]
        redeemed_offers = [o for o in offers_list if o['is_redeemed']]
        
        print(f"📊 Stats - Active: {len(active_offers)}, Expired: {len(expired_offers)}, Redeemed: {len(redeemed_offers)}")
        print("✅ Rendering user_dashboard.html")
        
        return render_template('user_dashboard.html',
                             user=user,
                             offers=offers_list,
                             now=now,
                             active_count=len(active_offers),
                             expired_count=len(expired_offers),
                             redeemed_count=len(redeemed_offers))
    
    except Exception as e:
        print(f"🚨 ERROR in user_dashboard: {str(e)}")
        import traceback
        traceback.print_exc()
        flash(f'Dashboard error: {str(e)}', 'error')
        return redirect(url_for('index'))

@app.route('/cafe-dashboard')
def cafe_dashboard():
    if 'user_id' not in session or session.get('account_type') != 'cafe':
        return redirect(url_for('login'))
    
    # Get redeemed offers with user information
    redeemed_response = supabase.table('offers').select('*').eq('is_redeemed', True).order('redeemed_at', desc=True).execute()
    redeemed_offers = redeemed_response.data
    
    # Get user data for each offer and convert datetimes
    for offer in redeemed_offers:
        user_response = supabase.table('users').select('username').eq('id', offer['user_id']).execute()
        if user_response.data:
            # Create a simple object to match the template expectation
            class UserObj:
                def __init__(self, username):
                    self.username = username
            offer['user'] = UserObj(user_response.data[0]['username'])
        
        # Convert datetime strings to datetime objects
        if offer.get('scanned_at'):
            offer['scanned_at'] = parse_datetime(offer['scanned_at'])
        if offer.get('expires_at'):
            offer['expires_at'] = parse_datetime(offer['expires_at'])
        if offer.get('redeemed_at'):
            offer['redeemed_at'] = parse_datetime(offer['redeemed_at'])
    
    # Calculate this week's count
    week_ago = datetime.utcnow() - timedelta(days=7)
    this_week_count = sum(1 for offer in redeemed_offers if offer.get('redeemed_at') and offer['redeemed_at'] >= week_ago)
    
    return render_template('cafe_dashboard.html',
                         redeemed_offers=redeemed_offers,
                         this_week_count=this_week_count)

@app.route('/redeem-offer', methods=['POST'])
def redeem_offer():
    if 'user_id' not in session or session.get('account_type') != 'cafe':
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    redeem_code = request.form.get('redeem_code')
    
    response = supabase.table('offers').select('*').eq('redeem_code', redeem_code.upper()).execute()
    offer = response.data[0] if response.data else None
    
    if not offer:
        return jsonify({'success': False, 'message': 'Invalid redeem code'})
    
    if offer['is_redeemed']:
        return jsonify({'success': False, 'message': 'This code has already been redeemed at a cafe'})
    
    # Check if expired
    expires_at = parse_datetime(offer['expires_at'])
    if datetime.utcnow() > expires_at:
        return jsonify({
            'success': False,
            'message': f'This offer expired on {expires_at.strftime("%d %b %Y at %I:%M %p")}. Redeem codes are valid for 7 days from scan.'
        })
    
    # Update offer as redeemed
    supabase.table('offers').update({
        'is_redeemed': True,
        'redeemed_at': datetime.utcnow().isoformat(),
        'redeemed_by_cafe': session['username']
    }).eq('id', offer['id']).execute()
    
    # Get user info
    user_response = supabase.table('users').select('username').eq('id', offer['user_id']).execute()
    customer_name = user_response.data[0]['username'] if user_response.data else 'Unknown'
    
    return jsonify({
        'success': True,
        'message': 'Offer redeemed successfully!',
        'offer_details': {
            'title': offer['offer_title'],
            'customer': customer_name,
            'scanned_at': parse_datetime(offer['scanned_at']).strftime('%Y-%m-%d %H:%M'),
            'expires_at': expires_at.strftime('%Y-%m-%d %H:%M')
        }
    })

@app.route('/admin-dashboard')
def admin_dashboard():
    if 'user_id' not in session or session.get('account_type') != 'admin':
        return redirect(url_for('login'))
    
    users_response = supabase.table('users').select('*').execute()
    users = users_response.data
    
    # Convert created_at strings to datetime objects for users
    for user in users:
        if user.get('created_at'):
            user['created_at'] = parse_datetime(user['created_at'])
    
    all_offers_response = supabase.table('offers').select('*').order('scanned_at', desc=True).execute()
    all_offers = all_offers_response.data
    
    # Convert datetime strings to datetime objects for offers
    for offer in all_offers:
        if offer.get('scanned_at'):
            offer['scanned_at'] = parse_datetime(offer['scanned_at'])
        if offer.get('expires_at'):
            offer['expires_at'] = parse_datetime(offer['expires_at'])
        if offer.get('redeemed_at'):
            offer['redeemed_at'] = parse_datetime(offer['redeemed_at'])
    
    return render_template('admin_dashboard.html', users=users, offers=all_offers)

@app.route('/admin/change-account-type', methods=['POST'])
def change_account_type():
    if 'user_id' not in session or session.get('account_type') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    user_id = request.form.get('user_id')
    new_type = request.form.get('account_type')
    
    supabase.table('users').update({'account_type': new_type}).eq('id', user_id).execute()
    return jsonify({'success': True, 'message': 'Account type updated'})

@app.route('/admin/delete-user', methods=['POST'])
def delete_user():
    if 'user_id' not in session or session.get('account_type') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    user_id = request.form.get('user_id')
    
    if int(user_id) != session['user_id']:
        supabase.table('users').delete().eq('id', user_id).execute()
        return jsonify({'success': True, 'message': 'User deleted'})
    
    return jsonify({'success': False, 'message': 'Cannot delete your own account'})

@app.route('/admin/reset-password', methods=['POST'])
def reset_password():
    if 'user_id' not in session or session.get('account_type') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'})
    
    user_id = request.form.get('user_id')
    new_password = request.form.get('new_password')
    
    hashed_password = generate_password_hash(new_password)
    supabase.table('users').update({'password': hashed_password}).eq('id', user_id).execute()
    
    return jsonify({'success': True, 'message': 'Password reset successfully'})

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# ==================== DEFAULT ACCOUNTS ====================

def create_default_accounts():
    """Create default admin and cafe accounts"""
    try:
        # Check for admin account
        admin_check = supabase.table('users').select('*').eq('email', 'admin@elyra.com').execute()
        if not admin_check.data:
            admin = {
                'username': 'admin',
                'email': 'admin@elyra.com',
                'password': generate_password_hash('admin123'),
                'account_type': 'admin'
            }
            supabase.table('users').insert(admin).execute()
            print("✅ Admin account created: admin@elyra.com / admin123")
        
        # Check for cafe account
        cafe_check = supabase.table('users').select('*').eq('email', 'cafe@elyra.com').execute()
        if not cafe_check.data:
            cafe = {
                'username': 'elyra_cafe',
                'email': 'cafe@elyra.com',
                'password': generate_password_hash('cafe123'),
                'account_type': 'cafe'
            }
            supabase.table('users').insert(cafe).execute()
            print("✅ Cafe account created: cafe@elyra.com / cafe123")
    except Exception as e:
        print(f"Error creating default accounts: {e}")

# ==================== RUN APP ====================

if __name__ == '__main__':
    create_default_accounts()
    app.run(debug=True)
