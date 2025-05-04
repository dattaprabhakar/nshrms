# hrms_portal/app.py
import os
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from pymongo import MongoClient, ReturnDocument
from bson import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, date, timedelta
from functools import wraps
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8) # Example: Session timeout

# --- Database Setup ---
try:
    mongo_uri = os.getenv("MONGO_URI")
    if not mongo_uri: raise ValueError("MONGO_URI not found in environment variables.")

    client = MongoClient(mongo_uri)
    # Attempt to get DB name from URI, default if needed
    try:
        db_name = mongo_uri.split('/')[-1].split('?')[0]
        if not db_name or db_name == 'admin': # Avoid using 'admin' db directly if URI is like mongodb://host/
             raise IndexError
    except IndexError:
        db_name = 'hrms_db' # Default database name
        print(f"Warning: Could not parse DB name from MONGO_URI or it was invalid, using default '{db_name}'.")

    db = client[db_name]
    users_collection = db.users
    attendance_collection = db.attendance
    leaves_collection = db.leaves
    payslips_collection = db.payslips
    # Ensure indexes for performance (optional but recommended)
    users_collection.create_index("username", unique=True)
    attendance_collection.create_index([("user_id", 1), ("clock_in", -1)])
    leaves_collection.create_index([("user_id", 1), ("applied_date", -1)])
    leaves_collection.create_index("status")
    payslips_collection.create_index([("user_id", 1), ("year", -1), ("month", -1)])

    print(f"MongoDB connected successfully to database: '{db.name}'")
    client.admin.command('ping') # Verify connection
    print("MongoDB connection confirmed.")

except ValueError as ve:
     print(f"Configuration Error: {ve}")
     exit()
except Exception as e:
    print(f"CRITICAL: Error connecting to MongoDB - {e}")
    exit()


# --- Helper Functions & Decorators ---
def login_required(f):
    """Decorator to ensure user is logged in (checks standard users and admins)."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in to access this page.", "warning")
            session['next_url'] = request.url # Store intended URL
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator to ensure user is logged in AND is an admin."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # First, check if logged in at all
        if 'user_id' not in session:
            flash("Please log in to access the admin area.", "warning")
            session['next_url'] = request.url # Store intended URL
            return redirect(url_for('login'))
        # Then, check if the logged-in user is an admin
        if not session.get('is_admin'):
            flash("You do not have permission to access the admin area.", "danger")
            # Redirect non-admins trying to access admin pages to their regular dashboard
            return redirect(url_for('dashboard'))
        # If logged in and is admin, proceed
        return f(*args, **kwargs)
    return decorated_function


def get_current_user():
    """ Fetches the logged-in user's data from DB, handles errors. """
    user_id_str = session.get('user_id')
    if not user_id_str:
        return None # Not logged in

    try:
        user = users_collection.find_one({'_id': ObjectId(user_id_str)})
        if not user:
            # Logged in user ID not found in DB - session is invalid
            print(f"Warning: User ID {user_id_str} from session not found in DB. Clearing session.")
            session.clear()
            return None
        return user
    except Exception as e:
        # Includes InvalidId for ObjectId conversion or DB errors
        print(f"Error fetching user for session ID {user_id_str}: {e}")
        session.clear() # Clear potentially corrupt session
        return None


def get_today_attendance_status(user_id):
    """ Checks if user clocked in/out today, returns status dict. """
    if not isinstance(user_id, ObjectId):
         print(f"Warning: Invalid user_id type for attendance check: {type(user_id)}")
         # Return default status to avoid errors down the line
         return { "clocked_in": False, "clocked_out": False, "clock_in_time": None, "clock_out_time": None, "record_id": None }

    # Define today's date range accurately
    today_start = datetime.combine(date.today(), datetime.min.time())
    today_end = datetime.combine(date.today(), datetime.max.time())

    status = { "clocked_in": False, "clocked_out": False, "clock_in_time": None, "clock_out_time": None, "record_id": None }

    try:
        # Find the latest record for this user within today's range
        record = attendance_collection.find_one(
            {'user_id': user_id, 'clock_in': {'$gte': today_start, '$lt': today_end}},
            sort=[('clock_in', -1)] # Get the latest clock-in if multiple exist today
        )
        if record:
            status["clocked_in"] = True
            status["clock_in_time"] = record.get('clock_in')
            status["record_id"] = record.get('_id')
            if record.get('clock_out'):
                status["clocked_out"] = True
                status["clock_out_time"] = record.get('clock_out')

    except Exception as e:
        print(f"Error fetching attendance status for user {user_id}: {e}")
        # Keep default status if DB error occurs

    return status


# --- Context Processors ---
@app.context_processor
def inject_global_vars():
    """ Makes common variables available to all templates. """
    is_admin = session.get('is_admin', False)
    # Check if user_id exists and corresponds to a valid user before confirming admin status
    if 'user_id' not in session:
        is_admin = False # Ensure not admin if not logged in
    # Add more global template vars here if needed
    return {
        'now': datetime.now(),
        'is_admin': is_admin
    }

# --- Routes ---

@app.route('/setup_user') # Temporary route (REMOVE/PROTECT IN PRODUCTION)
def setup_user():
    """ Creates a default admin user if one doesn't exist. """
    admin_username = "adminuser"
    admin_password = "password123" # Change this!
    try:
        existing_user = users_collection.find_one({'username': admin_username})
        if not existing_user:
            hashed_password = generate_password_hash(admin_password)
            user_data = {
                'username': admin_username,
                'password': hashed_password,
                'full_name': 'Administrator',
                'employee_id': 'ADM001',
                'is_admin': True, # Explicitly set admin flag
                'created_at': datetime.utcnow()
            }
            users_collection.insert_one(user_data)
            return f"Admin user '{admin_username}' created with password '{admin_password}'. Please login. Restart server if login fails immediately."
        else:
            # Optionally ensure existing user is admin
            if not existing_user.get('is_admin'):
                 users_collection.update_one({'_id': existing_user['_id']}, {'$set': {'is_admin': True}})
                 return f"User '{admin_username}' already exists. Updated to be an admin."
            return f"Admin user '{admin_username}' already exists."
    except Exception as e:
        print(f"Error in /setup_user: {e}")
        return f"Error setting up admin user: {e}", 500


@app.route('/login', methods=['GET', 'POST'])
def login():
    """ Handles user login for both regular users and admins. """
    if 'user_id' in session:
         # Redirect already logged-in users to appropriate dashboard
         return redirect(url_for('admin_dashboard' if session.get('is_admin') else 'dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if not username or not password:
            flash("Username and password are required.", "warning")
            return render_template('login.html'), 400 # Bad request

        try:
            user = users_collection.find_one({'username': username})

            if user and check_password_hash(user['password'], password):
                # Login successful - Set session variables
                session.permanent = True # Use default timeout from config
                session['user_id'] = str(user['_id'])
                session['username'] = user['username']
                session['is_admin'] = user.get('is_admin', False) # Store admin status

                flash(f"Welcome back, {user.get('full_name', user['username'])}!", "success")

                # Redirect to intended page or appropriate dashboard
                next_url = session.pop('next_url', None)
                if next_url:
                    return redirect(next_url)
                elif session['is_admin']:
                    return redirect(url_for('admin_dashboard'))
                else:
                    return redirect(url_for('dashboard'))
            else:
                # Invalid credentials
                flash("Invalid username or password.", "danger")
        except Exception as e:
             print(f"Error during login attempt for user '{username}': {e}")
             flash("An error occurred during login. Please try again later.", "danger")
        # If login fails (invalid creds or error), show login page again
        return render_template('login.html'), 401 # Unauthorized status

    # GET request
    return render_template('login.html')

@app.route('/logout')
@login_required # Must be logged in to log out
def logout():
    """ Clears the session and logs the user out. """
    user_name = session.get('username', 'User') # Get name before clearing
    session.clear()
    flash(f"{user_name} logged out successfully.", "info")
    return redirect(url_for('login'))


# --- Standard User Routes ---

@app.route('/')
@app.route('/dashboard')
@login_required
def dashboard():
    """ Standard user dashboard. """
    # Redirect admins accessing the standard dashboard to the admin one
    if session.get('is_admin'):
       return redirect(url_for('admin_dashboard'))

    user = get_current_user()
    if not user: # Should be caught by @login_required, but good practice
         flash("Session invalid. Please log in again.", "warning")
         return redirect(url_for('login'))

    attendance_status = get_today_attendance_status(user['_id'])
    # Future: Fetch real balances etc.
    # leave_balances = ...
    return render_template('dashboard.html',
                           user=user,
                           attendance_status=attendance_status)

@app.route('/clock_in', methods=['POST'])
@login_required
def clock_in():
    user = get_current_user()
    if not user: return redirect(url_for('login'))
    # Prevent admins from clocking in/out via user dashboard if needed
    # if user.get('is_admin'): flash("Admins cannot clock in here.", "warning"); return redirect(url_for('admin_dashboard'))

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
                'user_id': user_id, 'username': user['username'],
                'clock_in': now, 'clock_out': None,
                'date': date.today().strftime('%Y-%m-%d') })
            flash("Clocked in successfully!", "success")
        except Exception as e:
            print(f"Error clock-in user {user_id}: {e}")
            flash("An error occurred during clock-in.", "danger")
    return redirect(url_for('dashboard'))

@app.route('/clock_out', methods=['POST'])
@login_required
def clock_out():
    user = get_current_user()
    if not user: return redirect(url_for('login'))
    # if user.get('is_admin'): flash("Admins cannot clock out here.", "warning"); return redirect(url_for('admin_dashboard'))

    user_id = user['_id']
    attendance_status = get_today_attendance_status(user_id)

    if not attendance_status["clocked_in"]: flash("You need to clock in first.", "warning")
    elif attendance_status["clocked_out"]: flash("You have already clocked out today.", "warning")
    elif attendance_status["record_id"]:
        try:
            now = datetime.now()
            result = attendance_collection.update_one(
                {'_id': attendance_status["record_id"], 'clock_out': None},
                {'$set': {'clock_out': now}} )
            if result.modified_count > 0: flash("Clocked out successfully!", "success")
            else: flash("Could not clock out (already clocked out?).", "warning")
        except Exception as e:
             print(f"Error clock-out user {user_id}, rec {attendance_status['record_id']}: {e}")
             flash("An error occurred during clock-out.", "danger")
    else: flash("Cannot find clock-in record.", "danger")
    return redirect(url_for('dashboard'))

@app.route('/attendance')
@login_required
def view_attendance():
    # if session.get('is_admin'): return redirect(url_for('admin_dashboard')) # Or an admin attendance view
    user = get_current_user()
    if not user: return redirect(url_for('login'))
    try:
        user_attendance = list(attendance_collection.find({'user_id': user['_id']}).sort('clock_in', -1))
    except Exception as e:
        print(f"Error fetch user att {user['_id']}: {e}"); flash("Error fetching attendance.", "danger"); user_attendance = []
    return render_template('attendance.html', user=user, attendance_records=user_attendance)

@app.route('/leaves')
@login_required
def view_leaves():
    # if session.get('is_admin'): return redirect(url_for('admin_manage_leaves'))
    user = get_current_user()
    if not user: return redirect(url_for('login'))
    try:
        user_leaves = list(leaves_collection.find({'user_id': user['_id']}).sort('applied_date', -1))
    except Exception as e:
        print(f"Error fetch user leaves {user['_id']}: {e}"); flash("Error fetching leaves.", "danger"); user_leaves = []
    return render_template('leaves.html', user=user, leave_requests=user_leaves)

@app.route('/apply_leave', methods=['GET', 'POST'])
@login_required
def apply_leave():
    # if session.get('is_admin'): flash("Admins apply leave differently.", "warning"); return redirect(url_for('admin_dashboard'))
    user = get_current_user()
    if not user: return redirect(url_for('login'))

    if request.method == 'POST':
        try:
            start_date_str = request.form.get('start_date'); end_date_str = request.form.get('end_date')
            leave_type = request.form.get('leave_type'); reason = request.form.get('reason')

            if not all([start_date_str, end_date_str, leave_type, reason]):
                 flash("All fields are required.", "warning")
                 return render_template('apply_leave.html', user=user, form_data=request.form), 400 # Pass back form data

            start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()

            if end_date < start_date:
                flash("End date cannot be before start date.", "warning")
                return render_template('apply_leave.html', user=user, form_data=request.form), 400

            # Future: Add validation against balances, overlapping dates etc.

            leave_data = {'user_id': user['_id'], 'username': user['username'], 'start_date': start_date_str,
                          'end_date': end_date_str, 'leave_type': leave_type, 'reason': reason,
                          'status': 'Pending', 'applied_date': datetime.now()}
            leaves_collection.insert_one(leave_data)
            flash("Leave request submitted successfully!", "success")
            return redirect(url_for('view_leaves'))
        except ValueError:
             flash("Invalid date format (YYYY-MM-DD required).", "danger")
             return render_template('apply_leave.html', user=user, form_data=request.form), 400
        except Exception as e:
            print(f"Error apply leave user {user['_id']}: {e}")
            flash("An error occurred submitting leave request.", "danger")
            # Don't redirect on error, show form again
            return render_template('apply_leave.html', user=user, form_data=request.form), 500

    # GET request
    return render_template('apply_leave.html', user=user, form_data={})

@app.route('/payslips')
@login_required
def view_payslips():
    # if session.get('is_admin'): return redirect(url_for('admin_dashboard')) # Or admin payslip management
    user = get_current_user()
    if not user: return redirect(url_for('login'))
    try:
        user_payslips = list(payslips_collection.find({'user_id': user['_id']}).sort([('year', -1), ('month', -1)]))
    except Exception as e:
        print(f"Error fetch user payslips {user['_id']}: {e}"); flash("Error fetching payslips.", "danger"); user_payslips = []
    return render_template('payslips.html', user=user, payslips=user_payslips)


# =========================
# === ADMIN PORTAL ROUTES ===
# =========================

@app.route('/admin')
@app.route('/admin/dashboard')
@admin_required # Use the admin decorator
def admin_dashboard():
    """ Displays the main dashboard for administrators. """
    stats = {'user_count': 'N/A', 'pending_leaves_count': 'N/A'}
    try:
        stats['user_count'] = users_collection.count_documents({})
        stats['pending_leaves_count'] = leaves_collection.count_documents({'status': 'Pending'})
        # Add more stats (e.g., distinct users clocked in today)
    except Exception as e:
        print(f"Error fetching admin dashboard stats: {e}")
        flash("Could not load dashboard statistics.", "warning")

    return render_template('admin/dashboard.html', **stats)

@app.route('/admin/users')
@admin_required
def admin_manage_users():
    """ Page for admins to view and manage users. """
    try:
        # Exclude password field from results for security
        all_users = list(users_collection.find({}, {'password': 0}).sort('username', 1))
    except Exception as e:
        print(f"Error fetching users for admin: {e}")
        flash("Could not load user list.", "danger")
        all_users = []
    return render_template('admin/users.html', users=all_users)

@app.route('/admin/leaves')
@admin_required
def admin_manage_leaves():
    """ Page for admins to view and manage leave requests. """
    try:
        filter_status = request.args.get('status', 'All') # Default to 'All'
        query = {}
        if filter_status != 'All':
            # Validate status to prevent injection - allow only known statuses
            allowed_statuses = ['Pending', 'Approved', 'Rejected']
            if filter_status in allowed_statuses:
                query['status'] = filter_status
            else:
                flash(f"Invalid status filter: {filter_status}", "warning")
                filter_status = 'All' # Reset to default if invalid

        # Sort pending first, then by date applied
        all_leaves = list(leaves_collection.find(query).sort([('status', 1), ('applied_date', -1)]))
    except Exception as e:
        print(f"Error fetching leaves for admin (filter: {filter_status}): {e}")
        flash("Could not load leave requests.", "danger")
        all_leaves = []

    return render_template('admin/leaves.html', leaves=all_leaves, current_filter=filter_status)

@app.route('/admin/leaves/action/<leave_id>/<action>', methods=['POST'])
@admin_required
def admin_action_leave(leave_id, action):
    """ Handles approving or rejecting a leave request. """
    if action not in ['approve', 'reject']:
        flash("Invalid action specified.", "danger")
        return redirect(url_for('admin_manage_leaves'))

    new_status = 'Approved' if action == 'approve' else 'Rejected'
    admin_username = session.get('username', 'UNKNOWN_ADMIN')

    try:
        # Find the document first to ensure it's pending
        leave_request = leaves_collection.find_one({'_id': ObjectId(leave_id), 'status': 'Pending'})

        if leave_request:
            result = leaves_collection.update_one(
                {'_id': ObjectId(leave_id)}, # Match by ID is enough now
                {'$set': {
                    'status': new_status,
                    'action_by': admin_username,
                    'action_date': datetime.now()
                    # Optionally add rejection_reason field if action is 'reject' and reason is provided
                }}
            )
            if result.modified_count > 0:
                flash(f"Leave request {new_status.lower()} successfully.", "success")
                # Future: Trigger notification to the user
            else:
                # Should not happen if find_one succeeded, but handle race conditions
                flash("Failed to update leave status (already actioned or DB error?).", "warning")
        else:
            flash("Leave request not found or is not pending.", "warning")

    except Exception as e:
        print(f"Error actioning leave {leave_id} ({action}): {e}")
        flash(f"An error occurred while actioning the leave request.", "danger")

    # Redirect back to the leaves page, possibly preserving filter
    status_filter = request.referrer.split('status=')[-1] if request.referrer and 'status=' in request.referrer else 'All'
    return redirect(url_for('admin_manage_leaves', status=status_filter))


# --- Main Execution ---
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5001))
    # Default to False for production, check env var FLASK_DEBUG or similar
    is_debug = os.environ.get("FLASK_ENV", "production") == "development"
    # OR use: is_debug = os.environ.get("FLASK_DEBUG", "False").lower() in ["true", "1"]

    print(f"--- HRMS Portal ({'Development' if is_debug else 'Production'}) ---")
    if is_debug: print("WARNING: Debug mode is ON.")
    print(f" * Environment: {os.environ.get('FLASK_ENV', 'production')}")
    print(f" * Database: mongodb://.../{db.name}") # Obscure sensitive parts if logging publicly
    print(f" * Listening on http://0.0.0.0:{port}")
    print("--- Press CTRL+C to quit ---")

    # Use threaded=True for slightly better handling of concurrent requests in dev
    # For production, use a proper WSGI server like Gunicorn or uWSGI
    app.run(host='0.0.0.0', port=port, debug=is_debug, threaded=True)