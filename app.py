from flask import Flask, render_template, redirect, url_for, request, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import mysql.connector

app = Flask(__name__)
app.secret_key = 'your_secret_key'

def get_db_connection():
    return mysql.connector.connect(
        host="localhost", # add uour database host
        user="", # add your database password 
        password="turkish777",
        database="online_voting"
    )

@app.route('/')
def home():
    return render_template('base.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        cnic = request.form.get('cnic').strip()
        father_name = request.form.get('father_name')
        gender = request.form.get('gender')
        password = request.form.get('password')

        if len(cnic) != 13:
            flash("CNIC must be exactly 13 characters long.", "danger")
            return redirect(url_for('register'))

        if len(password) < 6:
            flash("Password must be at least 6 characters long.", "danger")
            return redirect(url_for('register'))

        if not name or not cnic or not father_name or not gender or not password:
            flash("All fields are required.", "danger")
            return redirect(url_for('register'))

        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM Users WHERE cnic = %s", (cnic,))
            if cursor.fetchone():
                flash("This CNIC is already registered. Please use a different one.", "danger")
                return redirect(url_for('register'))

            hashed_password = generate_password_hash(password)
            cursor.execute(
                "INSERT INTO Users (name, cnic, father_name, gender, password, role) VALUES (%s, %s, %s, %s, %s, 'user')",
                (name, cnic, father_name, gender, hashed_password)
            )
            conn.commit()
            flash("Registration successful! You are now registered as a user.", "success")
            return redirect(url_for('login'))
        except mysql.connector.Error as err:
            flash(f"Database error: {err}", "danger")
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        cnic = request.form['cnic']
        password = request.form['password']

        if len(cnic) != 13 or not cnic.isdigit():
            flash("CNIC must be exactly 13 digits long.", "danger")
            return redirect(url_for('login'))

        try:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)

            if cnic == '1350362777011' and check_password_hash(generate_password_hash("admin"), password):
                session['user_id'] = 'admin'
                session['role'] = 'admin'
                flash('Admin login successful!', 'success')
                return redirect(url_for('admin'))

            cursor.execute("SELECT id, password, role FROM Users WHERE cnic = %s", (cnic,))
            user = cursor.fetchone()

            if user and check_password_hash(user['password'], password):
                session['user_id'] = user['id']
                session['role'] = user['role']
                flash('Login successful!', 'success')
                return redirect(url_for('home'))

            flash('Invalid CNIC or password.', 'danger')
        except mysql.connector.Error as err:
            flash(f"Database error: {err}", "danger")
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('role', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@app.route('/candidates')
def candidates():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT C.id, C.name, C.party, C.votes, C.picture_url, COUNT(V.id) AS total_votes
            FROM Candidates C
            LEFT JOIN Votes V ON C.id = V.candidate_id
            GROUP BY C.id
        """)
        candidates = cursor.fetchall()

        return render_template('candidates.html', candidates=candidates)
    except mysql.connector.Error as err:
        flash(f"Database error: {err}", "danger")
        return redirect(url_for('home'))
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.route('/user_page')
def user_page():
    if 'user_id' not in session:
        flash('Please log in to view your profile.', 'danger')
        return redirect(url_for('login'))

    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)  
        cursor.execute("SELECT name, cnic, role, father_name, gender FROM Users WHERE id = %s", (session['user_id'],))
        user = cursor.fetchone()
        
        if user:
            return render_template('user_page.html', user=user)
        else:
            flash('User not found.', 'danger')
            return redirect(url_for('home'))

    except mysql.connector.Error as err:
        flash(f"Database error: {err}", 'danger')
        return redirect(url_for('home'))
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()


@app.route('/admin')
def admin():
    if session.get('role') != 'admin':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('home'))

    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id, name, party, picture_url FROM Candidates")
        candidates = cursor.fetchall()
        return render_template('admin.html', candidates=candidates)
    except mysql.connector.Error as err:
        flash(f"Database error: {err}", "danger")
        return redirect(url_for('home'))
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.route('/vote', methods=['POST'])
def vote():
    if 'user_id' not in session or session['role'] == 'admin':
        flash('Unauthorized to vote.', 'danger')
        return redirect(url_for('home'))

    candidate_id = request.form.get('candidate_id', type=int)
    if not candidate_id:
        flash('No candidate selected.', 'danger')
        return redirect(url_for('candidates'))

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM Votes WHERE user_id = %s", (session['user_id'],))
        if cursor.fetchone()[0] > 0:
            flash('You have already voted!', 'warning')
            return redirect(url_for('candidates'))

        cursor.execute("INSERT INTO Votes (user_id, candidate_id) VALUES (%s, %s)", (session['user_id'], candidate_id))
        cursor.execute("UPDATE Candidates SET votes = votes + 1 WHERE id = %s", (candidate_id,))
        conn.commit()
        flash('Vote cast successfully!', 'success')
    except mysql.connector.Error as err:
        conn.rollback()
        flash(f"Error while casting vote: {err}", 'danger')
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

    return redirect(url_for('candidates'))

@app.route('/add_candidate', methods=['POST'])
def add_candidate():
    if session.get('role') != 'admin':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('home'))

    name = request.form['name']
    party = request.form['party']
    picture_url = request.form['picture_url']

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO Candidates (name, party, picture_url) VALUES (%s, %s, %s)", (name, party, picture_url))
        conn.commit()
        flash('Candidate added successfully!', 'success')
    except mysql.connector.Error as err:
        flash(f"Error adding candidate: {err}", "danger")
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

    return redirect(url_for('admin'))

@app.route('/delete_candidate/<int:candidate_id>', methods=['POST'])
def delete_candidate(candidate_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("DELETE FROM Votes WHERE candidate_id = %s", (candidate_id,))
        cursor.execute("DELETE FROM Candidates WHERE id = %s", (candidate_id,))
        conn.commit()
        flash("Candidate deleted successfully.", "success")
    except mysql.connector.Error as err:
        conn.rollback()
        flash(f"Error deleting candidate: {err}", "danger")
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

    return redirect(url_for('admin'))

@app.route('/users_data')
def users_data():
    if session.get('role') != 'admin':
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('home'))

    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("""
            SELECT U.id, U.name, U.father_name, U.cnic, U.gender, C.party 
            FROM Users U
            LEFT JOIN Votes V ON U.id = V.user_id
            LEFT JOIN Candidates C ON V.candidate_id = C.id
            ORDER BY U.id
        """)
        users = cursor.fetchall()

        users_list = [
            {
                'name': user['name'],
                'father_name': user['father_name'],
                'cnic': user['cnic'],
                'gender': user['gender'],
                'party_voted': user['party'] if user['party'] else 'Not Voted'
            }
            for user in users
        ]

        return render_template('user_data.html', users=users_list)

    except mysql.connector.Error as err:
        flash(f"Database error: {err}", 'danger')
        return redirect(url_for('home'))
    
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()






if __name__ == "__main__":
    app.run(debug=True)
