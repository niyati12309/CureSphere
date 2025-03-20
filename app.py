from flask import Flask, render_template, request, redirect, url_for, send_from_directory, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import psycopg2
import os
from werkzeug.utils import secure_filename
import pytesseract
from PIL import Image
import bcrypt
import uuid

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'static/uploads/'
app.config['SECRET_KEY'] = 'your_secret_key'

# Flask-Login Setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User Class for Flask-Login
class User(UserMixin):
    def __init__(self, user_id):
        self.id = user_id

@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

# Database connection
def get_db_connection():
    conn = psycopg2.connect(
        dbname="curesphere",
        user="curesphereuser",
        password="78Pw888qGgoOCWjDJOLwcEaY0FM0XUSy",
        host="dpg-cve83bd6l47c73abvq00-a.oregon-postgres.render.com",
        port="5432"
    )
    return conn

# Home route
@app.route('/')
@login_required
def index():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Fetch folders
    cursor.execute("SELECT * FROM folders WHERE user_id = %s", (current_user.id,))
    folders = cursor.fetchall()

    # Fetch records
    cursor.execute("SELECT * FROM medical_records WHERE user_id = %s", (current_user.id,))
    records = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template('index.html', folders=folders, records=records)

# User Registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        user_id = str(uuid.uuid4())

        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO users (email, password_hash, user_id) VALUES (%s, %s, %s)",
                (email, hashed_password, user_id)
            )
            conn.commit()
            flash('Registration successful! Please log in.', 'success')
        except psycopg2.Error as err:
            flash(f'Error: {err}', 'error')
        finally:
            cursor.close()
            conn.close()

        return redirect(url_for('login'))

    return render_template('register.html')

# User Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user and bcrypt.checkpw(password.encode('utf-8'), user[1].encode('utf-8')):
            user_obj = User(user[2])
            login_user(user_obj)
            return redirect(url_for('index'))
        else:
            flash('Invalid email or password.', 'error')

    return render_template('login.html')

# User Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

# File upload route
@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        flash('No file uploaded.', 'error')
        return redirect(url_for('index'))

    file = request.files['file']
    if file.filename == '':
        flash('No file selected.', 'error')
        return redirect(url_for('index'))

    filename = secure_filename(file.filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)

    # Extract text using OCR (for images)
    if filename.lower().endswith(('.png', '.jpg', '.jpeg')):
        text = pytesseract.image_to_string(Image.open(file_path))
    else:
        text = "OCR not supported for this file type."

    # Save to database
    category = request.form.get('category', 'diagnostics')
    folder_id = request.form.get('folder_id', None)

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO medical_records (user_id, file_name, file_path, file_type, category, folder_id, metadata) VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (current_user.id, filename, file_path, file.content_type, category, folder_id, text)
        )
        conn.commit()
        flash('File uploaded successfully!', 'success')
    except psycopg2.Error as err:
        flash(f'Error: {err}', 'error')
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('index'))

# Serve uploaded files
@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# Search functionality
@app.route('/search', methods=['GET'])
@login_required
def search():
    query = request.args.get('query', '')
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM medical_records WHERE user_id = %s AND (file_name LIKE %s OR metadata LIKE %s)",
        (current_user.id, f"%{query}%", f"%{query}%")
    )
    results = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template('search_results.html', results=results)

# Create custom folder
@app.route('/create_folder', methods=['POST'])
@login_required
def create_folder():
    folder_name = request.form['folder_name']
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO folders (user_id, folder_name) VALUES (%s, %s)",
            (current_user.id, folder_name)
        )
        conn.commit()
        flash('Folder created successfully!', 'success')
    except psycopg2.Error as err:
        flash(f'Error: {err}', 'error')
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for('index'))

# Delete record
@app.route('/delete_record/<int:record_id>', methods=['DELETE'])
@login_required
def delete_record(record_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM medical_records WHERE id = %s AND user_id = %s", (record_id, current_user.id))
        conn.commit()
        flash('Record deleted successfully!', 'success')
    except psycopg2.Error as err:
        flash(f'Error: {err}', 'error')
    finally:
        cursor.close()
        conn.close()

    return '', 204  # No content response

# Run the application
if __name__ == '__main__':
    app.run(debug=True)