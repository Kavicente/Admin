from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from flask_socketio import socketio, SocketIO
import logging
import json
import requests
import os
import zipfile
import tempfile
import shutil
import hmac
import hashlib

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'admin-secret-key')
socketio = SocketIO(app, async_mode='threading', cors_allowed_origins="*", max_http_buffer_size=10000000)
ALERTNOW_URL = 'https://alert-858l.onrender.com'
MAX_LOGIN_ATTEMPTS = 5  # Maximum allowed login attempts before lockout
LOCKOUT_MINUTES = 15  # Lockout duration in minutes

def extract_admin_credentials(zip_password):
    """Extract admin.txt from admin_credentials.zip using the provided password."""
    zip_path = os.path.join(os.path.dirname(__file__), 'static', 'txt', 'admin_credentials.zip')
    temp_dir = tempfile.mkdtemp()
    admin_txt_path = os.path.join(temp_dir, 'admin.txt')
    
    try:
        if not os.path.exists(zip_path):
            logger.error(f"ZIP file not found at {zip_path}")
            raise FileNotFoundError(f"Admin credentials ZIP file not found at {zip_path}")
        
        logger.debug(f"Attempting to extract {zip_path} to {temp_dir} with password")
        with zipfile.ZipFile(zip_path, 'r') as zf:
            zf.setpassword(zip_password.encode('utf-8'))  # Password must be bytes
            zf.extract('admin.txt', path=temp_dir)
        logger.debug(f"Extracted admin.txt to {admin_txt_path}")
        
        if not os.path.exists(admin_txt_path):
            logger.error(f"admin.txt not found in extracted files at {admin_txt_path}")
            raise FileNotFoundError("admin.txt not found in admin_credentials.zip")
        
        with open(admin_txt_path, 'r') as f:
            admin_creds = json.load(f)
        logger.debug(f"Successfully read admin.txt: {admin_creds}")
        
        return admin_creds
    except zipfile.BadZipFile as e:
        logger.error(f"Failed to extract admin.txt: Invalid or corrupted ZIP file - {e}")
        raise Exception("Invalid or corrupted ZIP file")
    except RuntimeError as e:
        logger.error(f"Failed to extract admin.txt: Invalid password - {e}")
        raise Exception("Invalid ZIP password")
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse admin.txt: Invalid JSON format - {e}")
        raise Exception("admin.txt contains invalid JSON")
    except Exception as e:
        logger.error(f"Error extracting admin.txt: {e}")
        raise Exception(f"Failed to extract admin credentials: {e}")
    finally:
        try:
            shutil.rmtree(temp_dir, ignore_errors=True)
            logger.debug(f"Cleaned up temporary directory {temp_dir}")
        except Exception as e:
            logger.warning(f"Failed to clean up temporary directory {temp_dir}: {e}")

@app.route('/')
def index():
    if 'admin_logged_in' in session:
        return redirect(url_for('admin_dashboard'))
    return render_template('AdminLogin.html')

@app.route('/admin_login', methods=['POST'])
def admin_login():
    try:
        # Initialize login attempt counter
        if 'login_attempts' not in session:
            session['login_attempts'] = 0
            session['lockout_time'] = 0

        # Check for lockout
        import time
        current_time = time.time()
        if session['login_attempts'] >= MAX_LOGIN_ATTEMPTS and current_time < session['lockout_time']:
            remaining = int((session['lockout_time'] - current_time) / 60)
            logger.warning(f"Login attempt blocked due to lockout for IP {request.remote_addr}")
            return render_template('AdminLogin.html', error=f"Too many login attempts. Try again in {remaining} minutes")

        # Get form data
        data = request.form
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()

        # Validate input
        if not username or not password:
            session['login_attempts'] += 1
            logger.warning(f"Login failed: Empty username or password (attempt {session['login_attempts']}/{MAX_LOGIN_ATTEMPTS})")
            if session['login_attempts'] >= MAX_LOGIN_ATTEMPTS:
                session['lockout_time'] = current_time + (LOCKOUT_MINUTES * 60)
            return render_template('AdminLogin.html', error='Username and password are required')

        # Extract credentials
        zip_password = os.getenv('ZIP_PASSWORD', 'admin123')
        logger.debug(f"Using ZIP password from environment: {'set' if os.getenv('ZIP_PASSWORD') else 'default'}")
        admin_creds = extract_admin_credentials(zip_password)

        # Secure password comparison
        if (hmac.compare_digest(username.encode('utf-8'), admin_creds['username'].encode('utf-8')) and
            hmac.compare_digest(password.encode('utf-8'), admin_creds['password'].encode('utf-8'))):
            session['admin_logged_in'] = True
            session['login_attempts'] = 0  # Reset attempts on success
            session.pop('lockout_time', None)
            logger.info(f"Admin login successful for username: {username}")
            return redirect(url_for('admin_dashboard'))
        else:
            session['login_attempts'] += 1
            logger.warning(f"Login failed: Invalid credentials for username {username} (attempt {session['login_attempts']}/{MAX_LOGIN_ATTEMPTS})")
            if session['login_attempts'] >= MAX_LOGIN_ATTEMPTS:
                session['lockout_time'] = current_time + (LOCKOUT_MINUTES * 60)
                return render_template('AdminLogin.html', error=f"Too many failed attempts. Locked out for {LOCKOUT_MINUTES} minutes")
            return render_template('AdminLogin.html', error='Invalid username or password')
    except Exception as e:
        session['login_attempts'] += 1
        logger.error(f"Admin login failed: {e} (attempt {session['login_attempts']}/{MAX_LOGIN_ATTEMPTS})")
        if session['login_attempts'] >= MAX_LOGIN_ATTEMPTS:
            session['lockout_time'] = time.time() + (LOCKOUT_MINUTES * 60)
            return render_template('AdminLogin.html', error=f"Too many failed attempts. Locked out for {LOCKOUT_MINUTES} minutes")
        return render_template('AdminLogin.html', error=str(e))

@app.route('/admin_dashboard')
def admin_dashboard():
    if 'admin_logged_in' not in session:
        logger.warning("Unauthorized access to admin_dashboard")
        return redirect(url_for('index'))
    return render_template('AdminDashboard.html')

@app.route('/api/admin_create_user', methods=['POST'])
def admin_create_user():
    if 'admin_logged_in' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.json
    try:
        response = requests.post(f'{ALERTNOW_URL}/api/admin_create_user', json=data)
        if response.status_code == 200:
            logger.info(f"User {data.get('username')} created successfully with role {data.get('role')}")
            return jsonify(response.json())
        else:
            logger.error(f"User creation failed: {response.text}")
            return jsonify({'error': response.text}), response.status_code
    except Exception as e:
        logger.error(f"User creation failed: {e}")
        return jsonify({'error': str(e)}), 400

@app.route('/api/admin_delete_user', methods=['POST'])
def admin_delete_user():
    if 'admin_logged_in' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.json
    try:
        response = requests.post(f'{ALERTNOW_URL}/api/admin_delete_user', json=data)
        if response.status_code == 200:
            logger.info(f"User with contact_no {data.get('contact_no')} deleted successfully")
            return jsonify(response.json())
        else:
            logger.error(f"User deletion failed: {response.text}")
            return jsonify({'error': response.text}), response.status_code
    except Exception as e:
        logger.error(f"User deletion failed for contact_no {data.get('contact_no')}: {e}")
        return jsonify({'error': str(e)}), 400

@app.route('/api/admin_warn', methods=['POST'])
def admin_warn():
    if 'admin_logged_in' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.json
    try:
        response = requests.post(f'{ALERTNOW_URL}/api/admin_warn', json=data)
        if response.status_code == 200:
            logger.info(f"Warning sent to user with contact_no {data.get('contact_no')}")
            return jsonify(response.json())
        else:
            logger.error(f"Failed to send warning: {response.text}")
            return jsonify({'error': response.text}), response.status_code
    except Exception as e:
        logger.error(f"Failed to send warning to contact_no {data.get('contact_no')}: {e}")
        return jsonify({'error': str(e)}), 400

@app.route('/api/admin_suspend', methods=['POST'])
def admin_suspend():
    if 'admin_logged_in' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.json
    try:
        response = requests.post(f'{ALERTNOW_URL}/api/admin_suspend', json=data)
        if response.status_code == 200:
            logger.info(f"User with contact_no {data.get('contact_no')} suspended")
            return jsonify(response.json())
        else:
            logger.error(f"Failed to suspend user: {response.text}")
            return jsonify({'error': response.text}), response.status_code
    except Exception as e:
        logger.error(f"Failed to suspend user with contact_no {data.get('contact_no')}: {e}")
        return jsonify({'error': str(e)}), 400

@app.route('/api/admin_accounts', methods=['GET'])
def admin_accounts():
    if 'admin_logged_in' not in session:
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        response = requests.get(f'{ALERTNOW_URL}/api/admin_accounts')
        if response.status_code == 200:
            return jsonify(response.json())
        else:
            logger.error(f"Failed to fetch accounts: {response.text}")
            return jsonify({'error': response.text}), response.status_code
    except Exception as e:
        logger.error(f"Error fetching accounts: {e}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    socketio.run(app, host="0.0.0.0", port=port, debug=True, allow_unsafe_werkzeug=True)