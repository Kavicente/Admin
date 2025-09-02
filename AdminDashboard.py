from flask import Flask, request, jsonify, render_template, redirect, url_for, session
import logging
import json
import requests
import os
import secrets
import string
import smtplib
from email.mime.text import MIMEText
import hmac
import hashlib
import time

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'admin-secret-key')
ALERTNOW_URL = 'https://alert-858l.onrender.com'
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES = 15

def generate_and_email_admin_credentials():
    """Generate a random password, store it in admin.txt, and email it."""
    admin_txt_path = os.path.join(os.path.dirname(__file__), 'static', 'txt', 'admin.txt')
    smtp_email = os.getenv('SMTP_EMAIL', 'castillovinceb@gmail.com')  # Replace with your email
    smtp_password = os.getenv('SMTP_PASSWORD', 'paulvincentbcastillo')  # Replace with your app password
    recipient_email = os.getenv('ADMIN_EMAIL', 'vncbcstll@gmail.com')  # Replace with recipient email

    # Generate a secure 16-character password
    alphabet = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(alphabet) for _ in range(16))
    admin_creds = {'username': 'admin', 'password': password}

    # Write credentials to admin.txt
    try:
        os.makedirs(os.path.dirname(admin_txt_path), exist_ok=True)
        with open(admin_txt_path, 'w') as f:
            json.dump(admin_creds, f)
        logger.debug(f"Admin credentials written to {admin_txt_path}")
    except Exception as e:
        logger.error(f"Failed to write admin.txt: {e}")
        raise Exception(f"Failed to create admin credentials: {e}")

    # Send email with password
    try:
        msg = MIMEText(f"Your Admin Dashboard credentials:\n\nUsername: admin\nPassword: {password}\n\nStore this securely and do not share.")
        msg['Subject'] = 'Admin Dashboard Credentials'
        msg['From'] = smtp_email
        msg['To'] = recipient_email

        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(smtp_email, smtp_password)
            server.sendmail(smtp_email, recipient_email, msg.as_string())
        logger.info(f"Admin credentials emailed to {recipient_email}")
    except Exception as e:
        logger.error(f"Failed to send email: {e}")
        raise Exception(f"Failed to send admin credentials email: {e}")

    return admin_creds

def read_admin_credentials():
    """Read admin credentials from admin.txt."""
    admin_txt_path = os.path.join(os.path.dirname(__file__), 'static', 'txt', 'admin.txt')
    try:
        if not os.path.exists(admin_txt_path):
            logger.warning(f"admin.txt not found at {admin_txt_path}. Generating new credentials.")
            return generate_and_email_admin_credentials()
        
        with open(admin_txt_path, 'r') as f:
            admin_creds = json.load(f)
        logger.debug(f"Successfully read admin.txt: {admin_creds}")
        return admin_creds
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse admin.txt: Invalid JSON format - {e}")
        raise Exception("admin.txt contains invalid JSON")
    except Exception as e:
        logger.error(f"Error reading admin.txt: {e}")
        raise Exception(f"Failed to read admin credentials: {e}")

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
        current_time = time.time()
        if session['login_attempts'] >= MAX_LOGIN_ATTEMPTS and current_time < session['lockout_time']:
            remaining = int((session['lockout_time'] - current_time) / 60) + 1
            logger.warning(f"Login attempt blocked due to lockout for IP {request.remote_addr}")
            return render_template('AdminLogin.html', error=f"Too many login attempts. Try again in {remaining} minute{'s' if remaining > 1 else ''}")

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

        # Read credentials
        admin_creds = read_admin_credentials()

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
            session['lockout_time'] = current_time + (LOCKOUT_MINUTES * 60)
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
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5001)))
