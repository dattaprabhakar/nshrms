import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
from pymongo import MongoClient
from bson import ObjectId  # For working with MongoDB ObjectIDs
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, date
from functools import wraps
from dotenv import load_dotenv

load_dotenv() # Load environment variables from .env

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY") # Load secret key from .env

# --- Database Setup ---
try:
    client = MongoClient(os.getenv("MONGO_URI"))
    db = client.get_database() # Get database name from URI or specify: client['hrms_db']
    users_collection = db.users
    attendance_collection = db.attendance
    leaves_collection = db.leaves
    payslips_collection = db.payslips
    print("MongoDB connected successfully!")
except Exception as e:
    print(f"Error connecting to MongoDB: {e}")
    # Handle connection error appropriately in a real app (e.g., exit or retry)
    exit()

# --- Helper Functions ---
def login_required(f):
    """ Decorator to ensure user is logged in """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("You need to be logged in to access this page.", "warning")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def get_current_user():
    """ Fetches the logged-in user's data from DB """
    if 'user_id' in session:
        try:
            return users_collection.find_one({'_id': ObjectId(session['user_id'])})
        except Exception as e:
            print(f"Error fetching user: {e}")
            session.clear() # Clear session if user ID is invalid
            return None
    return None

def get_today_attendance_status(user_id):
    """ Checks if user clocked in/out today """
    today_start = datetime.combine(date.today(), datetime.min.time())
    today_end = datetime.combine(date.today(), datetime.max.time())
    
    # Find the latest record for today
    record = attendance_collection.find_one(
        {'user_id': user_id, 'clock_in': {'$gte': today_start, '$lt': today_end}},
        sort=[('clock_in', -1)] # Get the latest clock-in if multiple exist
    )
    
    status = {
        "clocked_in": False,
        "clocked_out": False,
        "clock_in_time": None,
        "clock_out_time": None,
        "record_id": None
    }
    
    if record:
        status["clocked_in"] = True
        status["clock_in_time"] = record.get('clock_in')
        status["record_id"] = record.get('_id')
        if record.get('clock_out'):
            status["clocked_out"] = True
            status["clock_out_time"] = record.get('clock_out')
            
    return status

# --- Routes ---

@app.route('/setup_user') # Temporary route to add a user (REMOVE IN PRODUCTION)
def setup_user():
    """ A simple way to add a first user for testing """
    username = "testuser"
    password = "password123"
    existing_user = users_collection.find_one({'username': username})
    if not existing_user:
        hashed_password = generate_password_hash(password)
        users_collection.insert_one({
            'username': username,
            'password': hashed_password,
            'full_name': 'Test User',
            'employee_id': 'EMP001'
            # Add other relevant user details here
        })
        return f"User '{username}' created. Login with password '{password}'."
    return f"User '{username}' already exists."

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = users_collection.find_one({'username': username})

        if user and check_password_hash(user['password'], password):
            session['user_id'] = str(user['_id']) # Store user ID in session
            session['username'] = user['username']
            flash("Login successful!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid username or password.", "danger")
            return redirect(url_for('login'))

    # If already logged in, redirect to dashboard
    if 'user_id' in session:
         return redirect(url_for('dashboard'))
         
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear() # Clear all session data
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))

@app.route('/')
@app.route('/dashboard')
@login_required
def dashboard():
    user = get_current_user()
    if not user:
         return redirect(url_for('login')) # Redirect if user fetch failed

    attendance_status = get_today_attendance_status(user['_id'])
    
    return render_template('dashboard.html', user=user, attendance_status=attendance_status)

# --- Attendance Routes ---
@app.route('/clock_in', methods=['POST'])
@login_required
def clock_in():
    user = get_current_user()
    if not user: return redirect(url_for('login'))
    
    user_id = user['_id']
    attendance_status = get_today_attendance_status(user_id)

    if attendance_status["clocked_in"] and not attendance_status["clocked_out"]:
        flash("You have already clocked in today.", "warning")
    elif attendance_status["clocked_in"] and attendance_status["clocked_out"]:
         flash("You have already completed your attendance for today.", "info")
    else:
        try:
            now = datetime.now()
            attendance_collection.insert_one({
                'user_id': user_id,
                'clock_in': now,
                'clock_out': None,
                'date': date.today().strftime('%Y-%m-%d') # Store date as string for easier querying if needed
            })
            flash("Clocked in successfully!", "success")
        except Exception as e:
            flash(f"An error occurred during clock-in: {e}", "danger")

    return redirect(url_for('dashboard'))

@app.route('/clock_out', methods=['POST'])
@login_required
def clock_out():
    user = get_current_user()
    if not user: return redirect(url_for('login'))
    
    user_id = user['_id']
    attendance_status = get_today_attendance_status(user_id)

    if not attendance_status["clocked_in"]:
        flash("You need to clock in first.", "warning")
    elif attendance_status["clocked_out"]:
        flash("You have already clocked out today.", "warning")
    elif attendance_status["record_id"]:
        try:
            now = datetime.now()
            attendance_collection.update_one(
                {'_id': attendance_status["record_id"]},
                {'$set': {'clock_out': now}}
            )
            flash("Clocked out successfully!", "success")
        except Exception as e:
             flash(f"An error occurred during clock-out: {e}", "danger")
    else:
         flash("Could not find your clock-in record for today.", "danger") # Should not happen if clocked_in is True

    return redirect(url_for('dashboard'))

@app.route('/attendance')
@login_required
def view_attendance():
    user = get_current_user()
    if not user: return redirect(url_for('login'))

    try:
        # Fetch attendance records sorted by clock-in time descending
        user_attendance = list(attendance_collection.find(
            {'user_id': user['_id']}
        ).sort('clock_in', -1)) # -1 for descending order
    except Exception as e:
        flash(f"Error fetching attendance: {e}", "danger")
        user_attendance = []
        
    return render_template('attendance.html', user=user, attendance_records=user_attendance)

# --- Leave Routes ---
@app.route('/leaves')
@login_required
def view_leaves():
    user = get_current_user()
    if not user: return redirect(url_for('login'))

    try:
        user_leaves = list(leaves_collection.find(
            {'user_id': user['_id']}
        ).sort('applied_date', -1))
    except Exception as e:
        flash(f"Error fetching leave requests: {e}", "danger")
        user_leaves = []
        
    return render_template('leaves.html', user=user, leave_requests=user_leaves)

@app.route('/apply_leave', methods=['GET', 'POST'])
@login_required
def apply_leave():
    user = get_current_user()
    if not user: return redirect(url_for('login'))

    if request.method == 'POST':
        try:
            start_date_str = request.form['start_date']
            end_date_str = request.form['end_date']
            reason = request.form['reason']

            # Basic validation
            if not start_date_str or not end_date_str or not reason:
                 flash("All fields are required.", "warning")
                 return render_template('apply_leave.html', user=user)

            start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()

            if end_date < start_date:
                flash("End date cannot be before start date.", "warning")
                return render_template('apply_leave.html', user=user)

            leaves_collection.insert_one({
                'user_id': user['_id'],
                'start_date': start_date_str, # Store as string for consistency or use datetime objects
                'end_date': end_date_str,
                'reason': reason,
                'status': 'Pending', # Default status
                'applied_date': datetime.now()
            })
            flash("Leave request submitted successfully!", "success")
            return redirect(url_for('view_leaves'))
        except ValueError:
             flash("Invalid date format. Please use YYYY-MM-DD.", "danger")
        except Exception as e:
            flash(f"An error occurred: {e}", "danger")

    return render_template('apply_leave.html', user=user)

# --- Payslip Routes ---
@app.route('/payslips')
@login_required
def view_payslips():
    user = get_current_user()
    if not user: return redirect(url_for('login'))

    try:
        # Assumes payslips collection has documents like:
        # {'user_id': ObjectId(...), 'month': 1, 'year': 2023, 'file_name': 'payslip_jan_2023.pdf', 'net_pay': 5000}
        user_payslips = list(payslips_collection.find(
            {'user_id': user['_id']}
        ).sort([('year', -1), ('month', -1)])) # Sort by year then month descending
        
        # Example: Add dummy data if empty for testing (REMOVE IN PRODUCTION)
        if not user_payslips and payslips_collection.count_documents({'user_id': user['_id']}) == 0:
             payslips_collection.insert_many([
                 {'user_id': user['_id'], 'month': 1, 'year': 2024, 'file_name': 'payslip_jan_2024.pdf', 'net_pay': 5100, 'generated_date': datetime(2024, 1, 31)},
                 {'user_id': user['_id'], 'month': 12, 'year': 2023, 'file_name': 'payslip_dec_2023.pdf', 'net_pay': 5050, 'generated_date': datetime(2023, 12, 31)}
             ])
             user_payslips = list(payslips_collection.find(
                 {'user_id': user['_id']}
             ).sort([('year', -1), ('month', -1)]))
             
    except Exception as e:
        flash(f"Error fetching payslips: {e}", "danger")
        user_payslips = []
        
    return render_template('payslips.html', user=user, payslips=user_payslips)


# --- Main Execution ---
if __name__ == '__main__':
    # Use debug=True only for development, False for production
    host = os.environ.get('FLASK_RUN_HOST', '0.0.0.0') # Default to all interfaces
    app.run(debug=True, port=5001) # Changed port to avoid conflicts if 5000 is busy