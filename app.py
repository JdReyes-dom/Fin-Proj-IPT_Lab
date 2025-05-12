from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from functools import wraps
from datetime import datetime
from flask import Flask, g

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Change this in production

# Database configuration
DATABASE = 'database.db'

from datetime import datetime

# Add this after creating your Flask app
@app.template_filter('datetimeformat')
def datetimeformat(value, format='%b %d, %Y %I:%M %p'):
    if value is None:
        return ""
    if isinstance(value, str):
        try:
            value = datetime.strptime(value, '%Y-%m-%d %H:%M:%S')
        except:
            return value
    return value.strftime(format)

def get_db():
    """Get a database connection"""
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

def close_db(e=None):
    """Close the database connection"""
    db = g.pop('db', None)
    if db is not None:
        db.close()

app.teardown_appcontext(close_db)

def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        
        # Create users table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            is_admin INTEGER DEFAULT 0,
            has_voted INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Create categories table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            description TEXT,
            max_votes INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Create candidates table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS candidates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            party TEXT NOT NULL,
            category_id INTEGER NOT NULL,
            votes INTEGER DEFAULT 0,
            FOREIGN KEY (category_id) REFERENCES categories(id)
        )
        ''')
        
        # Create votes table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS votes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            category_id INTEGER NOT NULL,
            candidate_id INTEGER NOT NULL,
            voted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (category_id) REFERENCES categories(id),
            FOREIGN KEY (candidate_id) REFERENCES candidates(id)
        )
        ''')
        
        # Insert sample data
        cursor.execute('SELECT COUNT(*) FROM categories')
        if cursor.fetchone()[0] == 0:
            categories = [
                ('President', 'Vote for your preferred presidential candidate', 1),
                ('Vice President', 'Vote for your preferred vice presidential candidate', 1),
                ('Secretary', 'Vote for your preferred secretary candidate', 1)
            ]
            cursor.executemany('INSERT INTO categories (name, description, max_votes) VALUES (?, ?, ?)', categories)
        
            cursor.execute('SELECT id FROM categories WHERE name = "President"')
            president_id = cursor.fetchone()[0]
            cursor.execute('SELECT id FROM categories WHERE name = "Vice President"')
            vp_id = cursor.fetchone()[0]
            
            candidates = [
                ('John Doe', 'Independent', president_id),
                ('Jane Smith', 'Democratic Party', president_id),
                ('Michael Johnson', 'Republican Party', vp_id),
                ('Sarah Williams', 'Green Party', vp_id)
            ]
            cursor.executemany('INSERT INTO candidates (name, party, category_id) VALUES (?, ?, ?)', candidates)
            
            # Create an admin user
            admin_password = generate_password_hash('admin')
            cursor.execute('''
                INSERT INTO users (username, email, password, is_admin)
                VALUES (?, ?, ?, ?)
            ''', ('admin', 'admin@example.com', admin_password, 1))
            
        db.commit()

init_db()

# Decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or not session.get('is_admin', 0):
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        db = get_db()
        user = db.execute('SELECT id, username, password, is_admin FROM users WHERE username = ?', (username,)).fetchone()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = user['is_admin']
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'danger')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('register'))
        
        hashed_password = generate_password_hash(password)
        db = get_db()
        
        try:
            db.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', 
                      (username, email, hashed_password))
            db.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists.', 'danger')
    
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db()
    
    has_voted = db.execute(
        'SELECT has_voted FROM users WHERE id = ?', 
        (session['user_id'],)
    ).fetchone()['has_voted']
    
    categories = db.execute('''
        SELECT DISTINCT c.id, c.name, c.description, c.max_votes 
        FROM categories c
        JOIN candidates cd ON c.id = cd.category_id
    ''').fetchall()
    
    candidates_by_category = {}
    for category in categories:
        candidates = db.execute('''
            SELECT id, name, party 
            FROM candidates 
            WHERE category_id = ?
        ''', (category['id'],)).fetchall()
        
        candidates_by_category[category['id']] = {
            'category_info': dict(category),
            'candidates': candidates
        }
    
    return render_template('dashboard.html',
                         username=session['username'],
                         is_admin=session.get('is_admin', 0),
                         has_voted=has_voted,
                         candidates_by_category=candidates_by_category)

@app.route('/vote', methods=['POST'])
@login_required
def vote():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    db = get_db()
    
    # Check if user has already voted
    has_voted = db.execute(
        'SELECT has_voted FROM users WHERE id = ?', 
        (session['user_id'],)
    ).fetchone()['has_voted']
    
    if has_voted:
        flash('You have already voted.', 'danger')
        return redirect(url_for('dashboard'))
    
    # Get all categories that have candidates
    categories_with_candidates = db.execute('''
        SELECT c.id, c.max_votes FROM categories c
        WHERE EXISTS (SELECT 1 FROM candidates WHERE category_id = c.id)
    ''').fetchall()
    
    # Process votes for each category
    for category in categories_with_candidates:
        category_id = category['id']
        max_votes = category['max_votes']
        
        # Get all selected candidates for this category
        selected_candidates = request.form.getlist(f'category_{category_id}')
        
        # Validate selections
        if not selected_candidates:
            flash(f'Please select at least one candidate for {category["name"]}', 'danger')
            return redirect(url_for('dashboard'))
        
        if len(selected_candidates) > max_votes:
            flash(f'You can select maximum {max_votes} candidates for {category["name"]}', 'danger')
            return redirect(url_for('dashboard'))
        
        # Record each vote
        for candidate_id in selected_candidates:
            db.execute('UPDATE candidates SET votes = votes + 1 WHERE id = ?', (candidate_id,))
            db.execute('''
                INSERT INTO votes (user_id, category_id, candidate_id)
                VALUES (?, ?, ?)
            ''', (session['user_id'], category_id, candidate_id))
    
    # Mark user as voted
    db.execute('UPDATE users SET has_voted = 1 WHERE id = ?', (session['user_id'],))
    
    db.commit()
    flash('Thank you for voting!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/results')
@login_required
def results():
    db = get_db()
    
    if session.get('is_admin', 0):
        # Admin sees full results
        categories = db.execute('SELECT id, name FROM categories').fetchall()
        
        results_by_category = {}
        for category in categories:
            candidates = db.execute('''
                SELECT name, party, votes 
                FROM candidates 
                WHERE category_id = ?
                ORDER BY votes DESC
            ''', (category['id'],)).fetchall()
            
            total_votes = sum(candidate['votes'] for candidate in candidates)
            results_by_category[category] = {
                'candidates': candidates,
                'total_votes': total_votes
            }
        
        return render_template('admin_results.html', 
                             results_by_category=results_by_category,
                             is_admin=True)
    else:
        # Regular user sees their own votes
        # In your results route
        user_votes = db.execute('''
            SELECT 
                c.id as candidate_id,
                c.name as candidate_name,
                c.party,
                cat.id as category_id,
                cat.name as category_name,
                cat.max_votes,
                cat.created_at as category_created,
                v.voted_at
            FROM votes v
            JOIN candidates c ON v.candidate_id = c.id
            JOIN categories cat ON v.category_id = cat.id
            WHERE v.user_id = ?
            ORDER BY cat.created_at, v.voted_at
        ''', (session['user_id'],)).fetchall()

        # Organize votes by category (maintaining creation order)
        votes_by_category = {}
        category_order = []  # To maintain creation order
        
        for vote in user_votes:
            category_id = vote['category_id']
            if category_id not in votes_by_category:
                votes_by_category[category_id] = {
                    'category_name': vote['category_name'],
                    'max_votes': vote['max_votes'],
                    'created_at': vote['category_created'],
                    'candidates': []
                }
                category_order.append(category_id)
            votes_by_category[category_id]['candidates'].append({
                'name': vote['candidate_name'],
                'party': vote['party'],
                'voted_at': vote['voted_at']
            })
        
        # Sort categories by creation date (oldest first)
        category_order.sort(key=lambda x: votes_by_category[x]['created_at'])
        
        return render_template('user_votes.html', 
                            votes_by_category=votes_by_category,
                            category_order=category_order,
                            username=session['username'])

@app.route('/profile')
@login_required
def profile():
    db = get_db()
    user = db.execute('''
        SELECT id, username, email, created_at 
        FROM users 
        WHERE id = ?
    ''', (session['user_id'],)).fetchone()
    
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('dashboard'))
    
    # Convert created_at to datetime object if it exists
    created_at = None
    if user['created_at']:
        try:
            created_at = datetime.strptime(user['created_at'], '%Y-%m-%d %H:%M:%S')
        except:
            pass
    
    user_dict = {
        'id': user['id'],
        'username': user['username'],
        'email': user['email'],
        'created_at': created_at
    }
    
    return render_template('profile.html', user=user_dict)

@app.route('/update_username', methods=['POST'])
@login_required
def update_username():
    new_username = request.form['username']
    current_password = request.form['current_password']
    
    db = get_db()
    
    # Verify current password
    user = db.execute(
        'SELECT password FROM users WHERE id = ?', 
        (session['user_id'],)
    ).fetchone()
    
    if not user or not check_password_hash(user['password'], current_password):
        flash('Current password is incorrect', 'danger')
        return redirect(url_for('profile'))
    
    # Update username
    try:
        db.execute(
            'UPDATE users SET username = ? WHERE id = ?', 
            (new_username, session['user_id'])
        )
        db.commit()
        session['username'] = new_username
        flash('Username updated successfully', 'success')
    except sqlite3.IntegrityError:
        flash('Username already exists', 'danger')
    
    return redirect(url_for('profile'))

@app.route('/update_email', methods=['POST'])
@login_required
def update_email():
    new_email = request.form['email']
    current_password = request.form['current_password']
    
    db = get_db()
    
    # Verify current password
    user = db.execute(
        'SELECT password FROM users WHERE id = ?', 
        (session['user_id'],)
    ).fetchone()
    
    if not user or not check_password_hash(user['password'], current_password):
        flash('Current password is incorrect', 'danger')
        return redirect(url_for('profile'))
    
    # Update email
    try:
        db.execute(
            'UPDATE users SET email = ? WHERE id = ?', 
            (new_email, session['user_id'])
        )
        db.commit()
        flash('Email updated successfully', 'success')
    except sqlite3.IntegrityError:
        flash('Email already exists', 'danger')
    
    return redirect(url_for('profile'))

@app.route('/update_password', methods=['POST'])
@login_required
def update_password():
    current_password = request.form['current_password']
    new_password = request.form['new_password']
    confirm_password = request.form['confirm_password']
    
    if new_password != confirm_password:
        flash('New passwords do not match', 'danger')
        return redirect(url_for('profile'))
    
    db = get_db()
    
    # Verify current password
    user = db.execute(
        'SELECT password FROM users WHERE id = ?', 
        (session['user_id'],)
    ).fetchone()
    
    if not user or not check_password_hash(user['password'], current_password):
        flash('Current password is incorrect', 'danger')
        return redirect(url_for('profile'))
    
    # Update password
    hashed_password = generate_password_hash(new_password)
    db.execute(
        'UPDATE users SET password = ? WHERE id = ?', 
        (hashed_password, session['user_id'])
    )
    db.commit()
    
    flash('Password updated successfully', 'success')
    return redirect(url_for('profile'))

@app.route('/admin')
@admin_required
def admin():
    db = get_db()
    
    users = db.execute('SELECT id, username, email, has_voted FROM users').fetchall()
    categories = db.execute('SELECT id, name, description FROM categories').fetchall()
    candidates = db.execute('''
        SELECT c.id, c.name, c.party, cat.name, c.votes 
        FROM candidates c
        JOIN categories cat ON c.category_id = cat.id
    ''').fetchall()
    
    return render_template('admin.html',
                         users=users,
                         categories=categories,
                         candidates=candidates,
                         username=session.get('username'))

@app.route('/admin/add_category', methods=['POST'])
@admin_required
def add_category():
    name = request.form['name']
    description = request.form.get('description', '')
    max_votes = int(request.form.get('max_votes', 1))
    
    db = get_db()
    
    try:
        db.execute(
            'INSERT INTO categories (name, description, max_votes) VALUES (?, ?, ?)', 
            (name, description, max_votes)
        )
        db.commit()
        flash('Category added successfully!', 'success')
    except sqlite3.IntegrityError:
        flash('Category with this name already exists.', 'danger')
    
    return redirect(url_for('admin'))

@app.route('/admin/add_candidate', methods=['POST'])
@admin_required
def add_candidate():
    name = request.form['name']
    party = request.form['party']
    category_id = request.form['category_id']
    
    db = get_db()
    db.execute(
        'INSERT INTO candidates (name, party, category_id) VALUES (?, ?, ?)', 
        (name, party, category_id)
    )
    db.commit()
    
    flash('Candidate added successfully!', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/reset_votes', methods=['POST'])
@admin_required
def reset_votes():
    db = get_db()
    
    # Reset all candidate votes
    db.execute('UPDATE candidates SET votes = 0')
    
    # Reset all user voting status
    db.execute('UPDATE users SET has_voted = 0')
    
    # Clear all individual votes
    db.execute('DELETE FROM votes')
    
    db.commit()
    
    flash('Votes have been reset successfully!', 'success')
    return redirect(url_for('admin'))

@app.route('/admin/delete_user', methods=['POST'])
@admin_required
def delete_user():
    user_id = request.form.get('user_id')
    
    db = get_db()
    
    try:
        # Prevent deleting yourself
        if int(user_id) == session['user_id']:
            flash('You cannot delete your own account!', 'danger')
            return redirect(url_for('admin'))
        
        db.execute('DELETE FROM users WHERE id = ?', (user_id,))
        db.commit()
        flash('User deleted successfully', 'success')
    except Exception as e:
        db.rollback()
        flash(f'Error deleting user: {str(e)}', 'danger')
    
    return redirect(url_for('admin'))

@app.route('/admin/delete_category', methods=['POST'])
@admin_required
def delete_category():
    category_id = request.form.get('category_id')
    
    db = get_db()
    
    try:
        # First delete candidates in this category to maintain referential integrity
        db.execute('DELETE FROM candidates WHERE category_id = ?', (category_id,))
        db.execute('DELETE FROM categories WHERE id = ?', (category_id,))
        db.commit()
        flash('Category and associated candidates deleted successfully', 'success')
    except Exception as e:
        db.rollback()
        flash(f'Error deleting category: {str(e)}', 'danger')
    
    return redirect(url_for('admin'))

@app.route('/admin/delete_candidate', methods=['POST'])
@admin_required
def delete_candidate():
    candidate_id = request.form.get('candidate_id')
    
    db = get_db()
    
    try:
        db.execute('DELETE FROM candidates WHERE id = ?', (candidate_id,))
        db.commit()
        flash('Candidate deleted successfully', 'success')
    except Exception as e:
        db.rollback()
        flash(f'Error deleting candidate: {str(e)}', 'danger')
    
    return redirect(url_for('admin'))

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)