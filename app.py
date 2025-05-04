# hrms_portal/app.py
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
    mongo_uri = os.getenv("MONGO_URI")
    if not mongo_uri:
        raise ValueError("MONGO_URI not found in environment variables.")

    client = MongoClient(mongo_uri)
    # Attempt to get DB name from URI, default if needed
    try:
        db_name = mongo_uri.split('/')[-1].split('?')[0]
        if not db_name: # Handle cases like mongodb://localhost:27017/
             raise IndexError
    except IndexError:
        db_name = 'hrms_db' # Default database name if not in URI
        print(f"Warning: Could not parse DB name from MONGO_URI, using default '{db_name}'.")

    db = client[db_name]
    users_collection = db.users
    attendance_collection = db.attendance
    leaves_collection = db.leaves
    payslips_collection = db.payslips
    print(f"MongoDB connected successfully to database: {db.name}")
    # Optional: Test connection further
    client.admin.command('ping')
    print("MongoDB connection confirmed.")

except ValueError as ve:
     print(f"Configuration Error: {ve}")
     exit()
except Exception as e:
    print(f"Error connecting to MongoDB: {e}")
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
            user = users_collection.find_one({'_id': ObjectId(session['user_id'])})
            if not user:
                print(f"Warning: User ID {session['user_id']} found in session but not in DB.")
                session.clear()
                return None
            return user
        except Exception as e:
            print(f"Error fetching user {session.get('user_id')}: {e}")
            session.clear() # Clear session if user ID is invalid or causes error
            return None
    return None

def get_today_attendance_status(user_id):
    """ Checks if user clocked in/out today """
    if not isinstance(user_id, ObjectId):
         print(f"Warning: Invalid user_id type for attendance check: {type(user_id)}")
         return { "clocked_in": False, "clocked_out": False, "clock_in_time": None, "clock_out_time": None, "record_id": None }

    today_start = datetime.combine(date.today(), datetime.min.time())
    today_end = datetime.combine(date.today(), datetime.max.time())

    try:
        # Find the latest record for today for the specific user
        record = attendance_collection.find_one(
            {'user_id': user_id, 'clock_in': {'$gte': today_start, '$lt': today_end}},
            sort=[('clock_in', -1)] # Get the latest clock-in if multiple exist
        )
    except Exception as e:
        print(f"Error fetching attendance status for user {user_id}: {e}")
        record = None

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

# --- Context Processor to make 'now' available in templates ---
@app.context_processor
def inject_now():
    return {'now': datetime.now()} # Makes 'now' accessible in all templates

# --- Routes ---

@app.route('/setup_user') # Temporary route to add a user (REMOVE IN PRODUCTION)
def setup_user():
    """ A simple way to add a first user for testing """
    username = "testuser"
    password = "password123"
    try:
        existing_user = users_collection.find_one({'username': username})
        if not existing_user:
            hashed_password = generate_password_hash(password)
            user_data = {
                'username': username,
                'password': hashed_password,
                'full_name': 'Test User',
                'employee_id': 'EMP001',
                'created_at': datetime.utcnow()
                # Add other relevant user details here (department, role, etc.)
            }
            users_collection.insert_one(user_data)
            return f"User '{username}' created. Login with password '{password}'. Please restart the server if login doesn't work immediately."
        else:
             return f"User '{username}' already exists."
    except Exception as e:
        return f"Error setting up user: {e}"


@app.route('/login', methods=['GET', 'POST'])
def login():
    # If already logged in, redirect to dashboard
    if 'user_id' in session:
         return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash("Username and password are required.", "warning")
            return redirect(url_for('login'))

        try:
            user = users_collection.find_one({'username': username})

            if user and check_password_hash(user['password'], password):
                session['user_id'] = str(user['_id']) # Store user ID in session
                session['username'] = user['username']
                flash(f"Welcome back, {user.get('full_name', user['username'])}!", "success")
                return redirect(url_for('dashboard'))
            else:
                flash("Invalid username or password.", "danger")
                # No redirect here, show login page again with flash message
        except Exception as e:
             print(f"Error during login for user {username}: {e}")
             flash("An error occurred during login. Please try again.", "danger")


    return render_template('login.html') # Render login page for GET or failed POST

@app.route('/logout')
@login_required # Ensure user is logged in to log out
def logout():
    user_name = session.get('username', 'User')
    session.clear() # Clear all session data
    flash(f"{user_name} logged out successfully.", "info")
    return redirect(url_for('login'))

@app.route('/')
@app.route('/dashboard')
@login_required
def dashboard():
    user = get_current_user()
    if not user:
         # get_current_user already cleared session and printed error
         flash("Session expired or user not found. Please log in again.", "warning")
         return redirect(url_for('login'))

    attendance_status = get_today_attendance_status(user['_id'])

    # Later: Fetch actual leave balances, inbox items, announcements etc.
    # leave_balances = get_leave_balances(user['_id'])
    # inbox_items = get_inbox_items(user['_id'])
    # announcements = get_announcements()

    return render_template('dashboard.html',
                           user=user,
                           attendance_status=attendance_status)
                           # Pass fetched data here later, e.g., leave_balances=leave_balances)

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
                'username': user['username'], # Store username for easier debugging/reporting
                'clock_in': now,
                'clock_out': None,
                'date': date.today().strftime('%Y-%m-%d')
            })
            flash("Clocked in successfully!", "success")
        except Exception as e:
            print(f"Error during clock-in for user {user_id}: {e}")
            flash(f"An error occurred during clock-in.", "danger")

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
            result = attendance_collection.update_one(
                {'_id': attendance_status["record_id"], 'clock_out': None}, # Ensure we only update if not already clocked out
                {'$set': {'clock_out': now}}
            )
            if result.modified_count > 0:
                 flash("Clocked out successfully!", "success")
            else:
                 # This might happen in a race condition or if already clocked out somehow
                 flash("Could not clock out. You might already be clocked out.", "warning")

        except Exception as e:
             print(f"Error during clock-out for user {user_id} record {attendance_status['record_id']}: {e}")
             flash(f"An error occurred during clock-out.", "danger")
    else:
         # Should not happen if clocked_in is True and clocked_out is False
         flash("Could not find your clock-in record for today to clock out.", "danger")

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
        print(f"Error fetching attendance for user {user['_id']}: {e}")
        flash("Error fetching attendance history.", "danger")
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
        print(f"Error fetching leave requests for user {user['_id']}: {e}")
        flash("Error fetching leave requests.", "danger")
        user_leaves = []

    # Later: Also fetch leave balances here
    # leave_balances = get_leave_balances(user['_id'])

    return render_template('leaves.html', user=user, leave_requests=user_leaves) # Pass balances later

@app.route('/apply_leave', methods=['GET', 'POST'])
@login_required
def apply_leave():
    user = get_current_user()
    if not user: return redirect(url_for('login'))

    if request.method == 'POST':
        try:
            start_date_str = request.form.get('start_date')
            end_date_str = request.form.get('end_date')
            leave_type = request.form.get('leave_type') # Added leave type
            reason = request.form.get('reason')

            # Basic validation
            if not start_date_str or not end_date_str or not reason or not leave_type:
                 flash("All fields (start date, end date, type, reason) are required.", "warning")
                 # Return the template with existing form data if needed (more advanced)
                 return render_template('apply_leave.html', user=user)

            start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()

            if end_date < start_date:
                flash("End date cannot be before start date.", "warning")
                return render_template('apply_leave.html', user=user)

            # Add more validation (e.g., check against leave balance) here later

            leave_data = {
                'user_id': user['_id'],
                'username': user['username'],
                'start_date': start_date_str,
                'end_date': end_date_str,
                'leave_type': leave_type,
                'reason': reason,
                'status': 'Pending', # Default status (Needs approval workflow later)
                'applied_date': datetime.now()
            }
            leaves_collection.insert_one(leave_data)

            flash("Leave request submitted successfully!", "success")
            return redirect(url_for('view_leaves'))
        except ValueError:
             flash("Invalid date format. Please use YYYY-MM-DD.", "danger")
             return render_template('apply_leave.html', user=user)
        except Exception as e:
            print(f"Error applying leave for user {user['_id']}: {e}")
            flash(f"An error occurred while submitting leave request.", "danger")
            return render_template('apply_leave.html', user=user)

    # For GET request
    return render_template('apply_leave.html', user=user)

# --- Payslip Routes ---
@app.route('/payslips')
@login_required
def view_payslips():
    user = get_current_user()
    if not user: return redirect(url_for('login'))

    try:
        # Assumes payslips collection has documents like:
        # {'user_id': ObjectId(...), 'month': 1, 'year': 2023, 'file_name': 'payslip_jan_2023.pdf', 'net_pay': 5000, 'generated_date': datetime(...)}
        user_payslips = list(payslips_collection.find(
            {'user_id': user['_id']}
        ).sort([('year', -1), ('month', -1)])) # Sort by year then month descending

        # Example: Add dummy data if empty for testing (REMOVE IN PRODUCTION or use setup_user)
        # if not user_payslips and payslips_collection.count_documents({'user_id': user['_id']}) == 0:
        #      payslips_collection.insert_many([
        #          {'user_id': user['_id'], 'username': user['username'], 'month': 1, 'year': 2024, 'file_name': 'payslip_jan_2024.pdf', 'net_pay': 5100.75, 'generated_date': datetime(2024, 1, 31)},
        #          {'user_id': user['_id'], 'username': user['username'], 'month': 12, 'year': 2023, 'file_name': 'payslip_dec_2023.pdf', 'net_pay': 5050.50, 'generated_date': datetime(2023, 12, 31)}
        #      ])
        #      user_payslips = list(payslips_collection.find( {'user_id': user['_id']} ).sort([('year', -1), ('month', -1)]))

    except Exception as e:
        print(f"Error fetching payslips for user {user['_id']}: {e}")
        flash("Error fetching payslips.", "danger")
        user_payslips = []

    return render_template('payslips.html', user=user, payslips=user_payslips)


# --- Main Execution ---
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5001)) # Allow PORT env var override
    # host='0.0.0.0' makes the server accessible from any device on your network
    # Use debug=True only for development, False for production
    is_debug = os.environ.get("FLASK_DEBUG", "True").lower() == "true" # Check FLASK_DEBUG env var

    print("--- HRMS Portal Starting ---")
    if is_debug:
        print("WARNING: Debug mode is ON. This is a development server.")
        print("         Do not use it in a production deployment.")
    print(f"         Listening on host 0.0.0.0, port {port}")
    print(f"--> Access locally: http://127.0.0.1:{port}")
    print(f"--> Access on your network: http://<YOUR_MACHINE_IP>:{port}")
    print("         (Replace <YOUR_MACHINE_IP> with your actual IP address)")
    print("--- Press CTRL+C to quit ---")

    app.run(host='0.0.0.0', port=port, debug=is_debug)