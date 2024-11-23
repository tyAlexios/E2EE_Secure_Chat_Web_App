# -*- coding: utf-8 -*-
# ==============================================================================
# Copyright (c) 2024 Xavier de Carné de Carnavalet
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
# 
# 3. The name of the author may not be used to endorse or promote products
#    derived from this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# ==============================================================================

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, abort, flash
from flask_mysqldb import MySQL
from flask_session import Session
import yaml
import hashlib
import os
import requests
import json
import base64
import pyotp
import time
import qrcode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from io import BytesIO
from base64 import b64encode, b32encode
# from Crypto.Cipher import AES
# from Crypto.Random import get_random_bytes

IS_DEBUG = False

app = Flask(__name__)

# reference: https://flask-session.readthedocs.io/en/latest/config.html
# Configure secret key and Flask-Session
app.config['SECRET_KEY'] = os.urandom(40) # Section 7.1
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict' # CSRF defense
app.config['SESSION_TYPE'] = 'filesystem'  # Options: 'filesystem', 'redis', 'memcached', etc.
app.config['PERMANENT_SESSION_LIFETIME'] = 43200 # Auto expire session after 12 hour # 4.3.3
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True  # To sign session cookies for extra security
app.config['SESSION_FILE_DIR'] = './sessions'  # Needed if using filesystem type
app.config['MAX_FAILED_LOGIN_TIMES'] = 100 # rate limiting

# Load database configuration from db.yaml or configure directly here
db_config = yaml.load(open('db.yaml'), Loader=yaml.FullLoader)
app.config['MYSQL_HOST'] = db_config['mysql_host']
app.config['MYSQL_USER'] = db_config['mysql_user']
app.config['MYSQL_PASSWORD'] = db_config['mysql_password']
app.config['MYSQL_DB'] = db_config['mysql_db']

mysql = MySQL(app)

# Initialize the Flask-Session
Session(app)

def generate_salt(): # store the salt in the database when generating a new user
    return  b64encode(os.urandom(64)).decode('utf-8')

def hash_with_salt(password, salt):
    return hashlib.sha256(salt.encode() + password.encode()).hexdigest()

def get_otp(username, totp_key):
    totp = pyotp.TOTP(totp_key)
    qr_code_content = totp.provisioning_uri(name=username, issuer_name='E2EE Chat Web App')              
    qrCode = qrcode.QRCode(version=1, box_size=20, border=2)
    qrCode.add_data(qr_code_content)
    qrCode.make(fit=True)
    qrImg = qrCode.make_image(fill='black', back_color='white')
    
    bf = BytesIO()
    qrImg.save(bf)
    otpQRCode = b64encode(bf.getvalue()).decode("utf-8")
    return totp, otpQRCode

# get a random recovery key with a length of 19 characters (at least 112 bits of entropy, Section 5.1.2.2), uppercase, lowercase, and digits
def generate_recovery_key(key_len=19):
    str_list = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    random_bytes = os.urandom(key_len)
    random_string = ''.join(str_list[byte % len(str_list)] for byte in random_bytes)
    return random_string

def check_is_pwned(password):
    password = password.encode('utf-8')
    password_hash1 = hashlib.sha1(password).hexdigest().upper()
    password_hash1_prefix = password_hash1[:5]
    url = "https://api.pwnedpasswords.com/range/" + password_hash1_prefix
    res = requests.get(url).content.decode('utf-8')
    pwned_list = res.split('\r\n')
    for pwned_item in pwned_list:
        pwned_hash = pwned_item.split(':')[0]
        if password_hash1 == password_hash1_prefix+pwned_hash:
            return True
    return False

def is_potential_sql_injection(inStr):
    if ";" in inStr or "#" in inStr or "$" in inStr:
        return True
    return False

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    sender_id = session['user_id']
    return render_template('chat.html', sender_id=sender_id)

@app.route('/users')
def users():
    if 'user_id' not in session:
        return redirect(url_for('index'))
    cur = mysql.connection.cursor()
    query = """SELECT user_id, username FROM users;"""
    cur.execute(query)
    user_data = cur.fetchall()
    cur.close()
    filtered_users = [[user[0], user[1]] for user in user_data if user[0] != session['user_id']]
    return {'users': filtered_users}

@app.route('/fetch_encrypted_messages', methods=['POST'])
def fetch_encrypted_messages():
    if not request.json or not 'last_message_id' in request.json or not 'peer_id' in request.json: 
        return jsonify({'error': 'Bad request'}), 400
    if 'user_id' not in session:
        return jsonify({'error': 'user does not login'}), 403

    last_message_id = request.json['last_message_id']
    peer_id = request.json['peer_id']
    cur = mysql.connection.cursor()
    query = """SELECT * FROM messages
               WHERE message_id > %s AND 
               ((sender_id = %s AND receiver_id = %s) OR (sender_id = %s AND receiver_id = %s))
               ORDER BY message_id ASC;"""
    cur.execute(query, (last_message_id, peer_id, session['user_id'], session['user_id'], peer_id))
    # Fetch the column names
    result = cur.fetchall()
    if result:
        column_names = [desc[0] for desc in cur.description]
        # Fetch all rows, and create a list of dictionaries, each representing a message
        messages = [dict(zip(column_names, row)) for row in result]
    else:
        return jsonify({'messages': None}), 200
    cur.close()
    return jsonify({'messages': messages}), 200


@app.route('/get_otp_image', methods=['POST'])
def get_otp_image():
    username = request.json.get("username")
    totp_key = b32encode(os.urandom(20)).decode('utf-8')
    totp, otpQRCode = get_otp(username,totp_key)
    session['totp_reg'] = totp
    session['totp_key'] = totp_key
    return jsonify(otpQRCode=otpQRCode)

@app.route('/get_recovery_key', methods=['POST'])
def get_recovery_key():
    recovery_key = generate_recovery_key()
    session['show_recovery_key'] = recovery_key
    return jsonify(recoveryKey=recovery_key)

@app.route('/change_otp_image', methods=['POST'])
def change_otp_image():
    totp_key = b32encode(os.urandom(20)).decode('utf-8')
    totp, otpQRCode = get_otp(session['username'],totp_key)
    session['totp_reg'] = totp
    session['totp_key'] = totp_key
    return jsonify(otpQRCode=otpQRCode)

@app.route('/validate_and_save_totp', methods=['POST'])
def validate_and_save_totp():
    totp_code = request.json.get("new_totp_code")
    totp = session['totp_reg']
    totp_key = session['totp_key']
    if totp is None or totp_key is None:
        return jsonify({'error': 'Please generate an TOTP first'}), 400
    if not (totp.verify(totp_code)):
        return jsonify({'error': 'Invalid TOTP'}), 400
    cur = mysql.connection.cursor()
    query = """UPDATE users 
                SET totp_key=%s 
                WHERE user_id=%s;"""
    cur.execute(query, (totp_key, session['user_id'],))
    mysql.connection.commit()
    cur.close()
    return jsonify({'status': 'success'}), 200

@app.route('/change_recovery_key', methods=['POST'])
def change_recovery_key():
    recovery_key = generate_recovery_key()
    session['show_new_recovery_key'] = recovery_key
    return jsonify(recoveryKey=recovery_key)

@app.route('/validate_and_save_recovery_key', methods=['POST'])
def validate_and_save_recovery_key():
    recovery_key = session['show_new_recovery_key']
    input_recovery_key = request.json.get("input_new_recovery_key")
    if recovery_key is None or input_recovery_key is None:
        return jsonify({'error': 'Please generate a look-up secret first'}), 400
    if recovery_key != input_recovery_key:
        return jsonify({'error': 'Look-up secret does not match'}), 400
    recovery_key_salt = generate_salt()
    recovery_key = hash_with_salt(recovery_key, recovery_key_salt)
    cur = mysql.connection.cursor()
    query = """UPDATE users 
                SET recovery_key=%s, recovery_key_salt=%s 
                WHERE user_id=%s;"""
    cur.execute(query, (recovery_key, recovery_key_salt, session['user_id'],))
    mysql.connection.commit()
    cur.close()
    return jsonify({'status': 'success'}), 200

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        userDetails = request.form
        if 'username' not in userDetails or 'password' not in userDetails or 'totp_code' not in userDetails or 'recovery_key' not in userDetails:
            return render_template('login.html', error='Bad login form')
        username = userDetails['username']
        password = userDetails['password']
        totp_code = userDetails['totp_code']
        recovery_key = userDetails['recovery_key']
        
        if (not username or not password or not totp_code or not recovery_key) and not IS_DEBUG:
            return render_template('login.html', error='Empty field exists')
        
        if is_potential_sql_injection(username):
            return render_template('login.html', error='Illegal character in username')
        
        cur = mysql.connection.cursor()
        query = """SELECT user_id, password, password_salt, totp_key, failed_login_times, recovery_key, recovery_key_salt 
                    FROM users 
                    WHERE BINARY username=%s;"""
        cur.execute(query, (username,))
        account = cur.fetchone()
        
        if account: # 1. check whether the account exists
            user_id = account[0]
            password_hash_salt_gt = account[1]
            password_salt = account[2]
            totp_key = account[3]
            failed_login_times = account[4]
            failed_login_count = 0
            recovery_key_hash_salt_gt = account[5]
            recovery_key_salt = account[6]
            # 2. check whether the account failed login times is less than 100
            if failed_login_times < app.config['MAX_FAILED_LOGIN_TIMES'] or IS_DEBUG:
                totp, otpQRCode = get_otp(username,totp_key)
                
                if (totp.verify(totp_code)) or IS_DEBUG: # 3. verify the OTP
                    recovery_key_hash_salt_input = hash_with_salt(recovery_key, recovery_key_salt)
                    if (recovery_key_hash_salt_input == recovery_key_hash_salt_gt) or IS_DEBUG: # 4. verify the recovery key
                        password_hash_salt_input = hash_with_salt(password, password_salt)
                        if (password_hash_salt_input == password_hash_salt_gt): # 5. verify the password
                            session['username'] = username
                            session['user_id'] = user_id
                            session['login_time'] = time.time()
                            return redirect(url_for('index'))
                        else:
                            error = 'Invalid username or password or look-up secret or TOTP.'
                            failed_login_count += 1
                    else:
                        error = 'Invalid username or password or look-up secret or TOTP.'
                        failed_login_count += 1
                else:
                    error = 'Invalid username or password or look-up secret or TOTP.'
                    failed_login_count += 1
            else:
                error = 'Too many failed login attempts, account locked, please contact the website administrator'
        else:
            error = 'Invalid username or password or look-up secret or TOTP.'
        
        # update the failed login times
        if account and failed_login_count > 0:
            update_failed_login_times = failed_login_times+failed_login_count
            query = """UPDATE users 
                        SET failed_login_times=%s 
                        WHERE user_id=%s;"""
            cur.execute(query, (update_failed_login_times, user_id,))
            mysql.connection.commit()
    return render_template('login.html', error=error)


@app.route('/registration', methods=['GET', 'POST'])
def registration():
    error = None 
    if request.method == 'POST':
        if not request.is_json:
            return jsonify({'error': 'Registration form should be a JSON'}), 400
        
        if 'username' not in request.json or 'password' not in request.json or 'repeatPassword' not in request.json or 'otpCode' not in request.json or 'recoveryKey' not in request.json or 'publicKey' not in request.json:
            return jsonify({'error': 'Bad registration form'}), 400
        
        userDetails = request.json
        username = userDetails['username']
        password = userDetails['password']
        repeatPassword = userDetails['repeatPassword']
        totp_code = userDetails['otpCode']
        input_recovery_key = userDetails['recoveryKey']
        publicKey = userDetails['publicKey']
        
        if not username or not password or not repeatPassword or not totp_code or not input_recovery_key or not publicKey:
            return jsonify({'error': 'Empty field exists'}), 400

        # check if username already exists
        cur = mysql.connection.cursor()
        query = """SELECT user_id 
                    FROM users 
                    WHERE BINARY username=%s;"""
        cur.execute(query, (username,))
        account = cur.fetchone()
        if account:
            return jsonify({'error': 'Username already exists'}), 400
        
        # check password == repeatPassword
        if password != repeatPassword:
            return jsonify({'error': 'Passwords do not match'}), 400

        # check if username is empty
        if not username:
            return jsonify({'error': 'Username cannot be empty'}), 400
        
        # protect against potential SQL injection attacks
        if is_potential_sql_injection(username):
            return jsonify({'error': 'Illegal character in username'}), 400
        
        # check "Memorized secrets SHALL be at least 8 characters in length if chosen by the subscriber"
        passwordLen = len(password)
        if passwordLen < 8:
            return jsonify({'error': 'Password SHALL be at least 8 characters in length'}), 400
        
        # check the password with PwnedPasswords (Memorized Secret Verifiers (§5.1.1.2))
        # https://haveibeenpwned.com/API/v3#PwnedPasswords
        """Dataset reference: https://github.com/pfoy/Bad-Passwords-and-the-NIST-Guidelines"""
        if (check_is_pwned(password)):
            return jsonify({'error': 'The password is weak, please change it'}), 400
        
        # hash the password
        password_salt = generate_salt()
        password = hash_with_salt(password, password_salt)
        
        totp = session['totp_reg']
        totp_key = session['totp_key']
        session['totp_reg'] = None
        session['totp_key'] = None

        if totp is None or totp_key is None:
            return jsonify({'error': 'Please generate an TOTP first'}), 400
        
        recovery_key_plaint_text = session['show_recovery_key']
        session['show_recovery_key'] = None
        
        if recovery_key_plaint_text is None or input_recovery_key is None:
            return jsonify({'error': 'Please generate a look-up secret first'}), 400
        
        if recovery_key_plaint_text != input_recovery_key:
            return jsonify({'error': 'Look-up secret does not match'}), 400
        
        recovery_key_salt = generate_salt()
        recovery_key = hash_with_salt(recovery_key_plaint_text, recovery_key_salt)
        
        if not (totp.verify(totp_code)): # 2. verify the OTP
            return jsonify({'error': 'Invalid TOTP'}), 400
        
        # register the new user
        cur = mysql.connection.cursor()
        query = """INSERT INTO users (username, password, password_salt, totp_key, recovery_key, recovery_key_salt, public_key) 
                    VALUES (%s, %s, %s, %s, %s, %s, %s);"""
        cur.execute(query, (username, password, password_salt, totp_key, recovery_key, recovery_key_salt, publicKey))
        mysql.connection.commit()
        cur.close()

        cur = mysql.connection.cursor()
        query = """SELECT user_id 
                    FROM users 
                    WHERE BINARY username = %s;"""
        cur.execute(query, (username,))
        result = cur.fetchone()
        cur.close()

        user_id = result[0]
        return jsonify({'status': 'success', 'user_id': user_id}), 200
    else:
        return render_template('registration.html', error=error)

@app.route('/send_encrypted_message', methods=['POST'])
def send_encrypted_message():
    if not request.json or not 'encrypted_message' in request.json:
        return jsonify({'error': 'Bad request'}), 400
    if 'user_id' not in session:
        return jsonify({'error': 'user does not login'}), 403
    sender_id = session['user_id']

    receiver_id = request.json['receiver_id']
    ciphertext = request.json['encrypted_message']
    salt = request.json['salt']
    iv = request.json['iv']
    HMAC_iv = request.json['HMAC_iv']

    save_encryptedMessage(sender_id, receiver_id, ciphertext, salt, iv, HMAC_iv)
    
    return jsonify({'status': 'success', 'message': 'Message sent'}), 200

def save_encryptedMessage(sender_id, receiver_id, ciphertext, salt, iv, HMAC_iv):
    cur = mysql.connection.cursor()
    query = """INSERT INTO messages (sender_id, receiver_id, ciphertext, salt, iv, HMAC_iv) 
                VALUES (%s, %s, %s, %s, %s, %s);"""
    cur.execute(query, (sender_id, receiver_id, ciphertext, salt, iv, HMAC_iv,))
    mysql.connection.commit()
    cur.close()    


@app.route('/erase_chat', methods=['POST'])
def erase_chat():
    if 'user_id' not in session:
        jsonify({'error': 'user does not login'}), 403

    peer_id = request.json['peer_id']
    cur = mysql.connection.cursor()
    query = """DELETE FROM messages 
                WHERE ((sender_id = %s AND receiver_id = %s) OR (sender_id = %s AND receiver_id = %s));"""
    cur.execute(query, (peer_id, session['user_id'], session['user_id'], peer_id))
    mysql.connection.commit()

    # Check if the operation was successful by evaluating affected rows
    if cur.rowcount > 0:
        return jsonify({'status': 'success'}), 200
    else:
        return jsonify({'status': 'failure'}), 200

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')  # Flash a logout success message
    return redirect(url_for('index'))


###################################################################################################
###################################################################################################
###################################################################################################
###################################################################################################
###################################################################################################
###################################################################################################
###################################################################################################
###################################################################################################
###################################################################################################
###################################################################################################
###################################################################################################
###################################################################################################
###################################################################################################
###################################################################################################
###################################################################################################
###################################################################################################
###################################################################################################
###################################################################################################
###################################################################################################
###################################################################################################

@app.route('/fetch_publicKey', methods=['POST'])
def fetch_publicKey():
    if 'user_id' not in session:
        jsonify({'error': 'user does not login'}), 403
    if not request.json or not 'user_id' in request.json:
        return jsonify({'error': 'Bad request'}), 400
    peer_id = request.json['user_id']
    if not peer_id:
        return jsonify({'error': 'Missing or invalid peer_id'}), 400
    cur = mysql.connection.cursor()
    try:
        query = """SELECT public_key 
                    FROM users WHERE user_id = %s;"""
        cur.execute(query, (peer_id,))
        result = cur.fetchone()
        if not result:
            return jsonify({'public_key': None})
        public_key = result[0] if result else None
        return jsonify({'public_key': public_key})
    finally:
        cur.close()


@app.route('/fetch_salt_iv', methods=['POST'])
def fetch_salt_iv():
    if 'user_id' not in session:
        return jsonify({'error': 'user does not login'}), 403
    if not request.json or not 'sender_id' in request.json or not 'receiver_id' in request.json:
        return jsonify({'error': 'Bad request'}), 400
    sender_id = request.json['sender_id']
    receiver_id = request.json['receiver_id']
    cur = mysql.connection.cursor()
    try:
        query = """SELECT last_salt
                    FROM salts
                    WHERE user_id = %s;"""
        cur.execute(query, (sender_id,))
        row = cur.fetchone()
        if row:
            salt = row[0] + 1
            query = """SELECT IV
                    FROM ivs
                    WHERE sender_id = %s AND receiver_id = %s AND salt = %s;"""
            cur.execute(query, (sender_id, receiver_id, salt, ))
            exist_iv = cur.fetchone()
            if exist_iv:
                iv = exist_iv[0] + 1
            else:
                iv = 1
        else:
            salt = 1
            iv = 1
        # Update last salt
        update_salt_iv(sender_id, receiver_id, salt, iv)
        update_last_salt(sender_id, salt)
        return jsonify({'salt': salt, 'iv': iv}), 200
    except Exception as e:
        mysql.connection.rollback()
        print(">>> Error",e, flush=True)
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()

# insert or update salt&iv
def update_last_salt(user_id, salt):
    cur = mysql.connection.cursor()
    query = """INSERT INTO salts (user_id, last_salt) 
                VALUES (%s, %s)
                ON DUPLICATE KEY UPDATE last_salt = %s;"""
    cur.execute(query, (user_id, salt, salt))
    mysql.connection.commit()
    
@app.route('/refresh_keys', methods=['POST'])
def refresh_keys():
    if 'user_id' not in session:
        return jsonify({'error': 'user does not login'}), 403
    if not request.json or not 'user_id' in request.json:
        return jsonify({'error': 'Bad request'}), 400
    user_id = request.json['user_id']
    cur=mysql.connection.cursor()
    try:
        query = """SELECT last_salt FROM salts WHERE user_id = %s;"""
        cur.execute(query, (user_id,))
        old_salt = cur.fetchone()
        new_salt = old_salt[0] + 1
        mysql.connection.commit()
        cur.close()
        return jsonify({'salt': new_salt}), 200
    except Exception as e:
        mysql.connection.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()

def update_salt_iv(sender_id, receiver_id, salt, iv):
    try:
        cur = mysql.connection.cursor()
        query = """INSERT INTO ivs (sender_id, receiver_id, salt, IV) 
                    VALUES (%s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE IV = %s;""" # salt collision !!!!!!!!!1 -> key reused -> IV reuse?
        cur.execute(query, (sender_id, receiver_id, salt, iv, iv))
        mysql.connection.commit()
        return jsonify({'data': request.json}), 200
    except Exception as e:
        mysql.connection.rollback()
        return jsonify({'error': str(e)}), 500

# update_salt_IV 
@app.route('/update_salt_IV', methods=['POST'])
def update_salt_IV():
    if 'user_id' not in session:
        return jsonify({'error': 'user does not login'}), 403
    if not request.json or not 'sender_id' in request.json or not 'receiver_id' in request.json or not 'salt' in request.json or not 'iv' in request.json:
        return jsonify({'error': 'Bad request'}), 400
    sender_id = request.json['sender_id']
    receiver_id = request.json['receiver_id']
    salt = request.json['salt']
    iv = request.json['iv']
    try:
        update_salt_iv(sender_id, receiver_id, salt, iv)
    except Exception as e:
        mysql.connection.rollback()
        return jsonify({'error': str(e)}), 500

# @app.route('/refresh_keys', methods=['POST'])
# def refresh_keys():
#     if 'user_id' not in session:
#         return jsonify({'error': 'user does not login'}), 403
    
if __name__ == '__main__':
    app.run(debug=True)

