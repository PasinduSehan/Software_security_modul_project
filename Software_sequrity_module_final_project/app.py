import os
from flask import Flask, render_template, request, redirect, url_for
import mysql.connector
from Content.KeyGeneration import KeyGeneration
from Content.KeyFactory import KeyFactory
import re

# Initialize the Flask application
app = Flask(__name__)

# Connect to the MySQL database
db = mysql.connector.connect(
    host="localhost",
    user="chami",
    password="2002",
    database="SecureChatSystem"
)
cursor = db.cursor()

# Load ECC keys from files, or generate new ones if they don't exist
if not os.path.exists("private_key.pem") or not os.path.exists("public_key.pem"):
    private_key, public_key = KeyGeneration.generate_ecc_keys()
else:
    with open("private_key.pem", "rb") as priv_file:
        private_key = priv_file.read()
    with open("public_key.pem", "rb") as pub_file:
        public_key = pub_file.read()

# Function to validate the password based on specific rules
def is_valid_password(password):
    length_regex = r'^.{8,}$'
    uppercase_regex = r'[A-Z]'
    lowercase_regex = r'[a-z]'
    digit_regex = r'\d'
    special_char_regex = r'[\W_]'
    return (re.search(length_regex, password) and
            re.search(uppercase_regex, password) and
            re.search(lowercase_regex, password) and
            re.search(digit_regex, password) and
            re.search(special_char_regex, password))

# Route for the login page
@app.route('/')
def login():
    return render_template('login.html')

# Route for the sign-up page
@app.route('/signup')
def signup():
    return render_template('signup.html')

# Route to handle the sign-up form submission
@app.route('/signup', methods=['POST'])
def handle_signup():
    email = request.form['email']
    password = request.form['password']
    role = request.form['role']

    if not is_valid_password(password):
        return "Password does not meet the requirements"

    # Hash the password
    hashed_password = KeyGeneration.hash_password(password)

    # Insert the new user into the database
    cursor.execute("INSERT INTO users (email, password, role) VALUES (%s, %s, %s)",
                   (email, hashed_password, role))
    db.commit()

    return redirect(url_for('login'))

# Route to handle the login form submission
@app.route('/login', methods=['POST'])
def handle_login():
    email = request.form['email']
    password = request.form['password']

    # Hash the password
    hashed_password = KeyGeneration.hash_password(password)

    # Check if the user exists
    cursor.execute("SELECT role FROM users WHERE email = %s AND password = %s", (email, hashed_password))
    user = cursor.fetchone()

    if not user:
        return "Invalid email or password"

    role = user[0]
    return redirect(url_for('encrypt_page', role=role))

# Route for the encrypted message page
@app.route('/encrypt')
def encrypt_page():
    return render_template('encrypted_message.html')

# Route to encrypt a message and stay on the same page
@app.route('/encrypt', methods=['POST'])
def encrypt_message():
    message = request.form['original-message']
    role = request.form['role']

    # Encrypt the message using the public key
    encrypted_data = KeyFactory.encrypt_message(message, "public_key.pem")

    # Insert the encrypted message and related data into the database
    cursor.execute("INSERT INTO encrypted_messages (role, enc_key, nonce, ciphertext, tag) VALUES (%s, %s, %s, %s, %s)",
                   (role, encrypted_data['enc_key'], encrypted_data['iv'],
                    encrypted_data['ciphertext'], encrypted_data.get('tag', '')))
    db.commit()

    # Return the encrypted message as plain text
    return encrypted_data['ciphertext']


@app.route('/decrypt', methods=['POST'])
def decrypt_message():
    email = request.form['decryption-email']
    password = request.form['decryption-password']

    # Hash the password
    hashed_password = KeyGeneration.hash_password(password)

    # Retrieve the user's role from the database
    cursor.execute("SELECT role FROM users WHERE email = %s AND password = %s", (email, hashed_password))
    user = cursor.fetchone()

    if not user:
        return "Invalid email or password"

    role = user[0]

    # Retrieve the most recent encrypted message for the user's role
    cursor.execute("SELECT enc_key, nonce, ciphertext, tag FROM encrypted_messages WHERE role = %s ORDER BY id DESC LIMIT 1", (role,))
    data = cursor.fetchone()

    if not data:
        return "No message found for this role"

    encrypted_data = {
        'enc_key': data[0],
        'nonce': data[1],
        'ciphertext': data[2],
        'tag': data[3]
    }

    # Decrypt the message using the private key
    decrypted_message = KeyFactory.decrypt_message(encrypted_data, "private_key.pem")

    return render_template('decrypted_message.html', message=decrypted_message)


# Run the Flask application
if __name__ == '__main__':
    app.run(debug=True)
