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

# --- Configuration ---
app.secret_key = os.getenv("SECRET_KEY")
if not app.secret_key:
    print("CRITICAL: SECRET_KEY not found in environment variables. Application will not run securely.")
    exit()
# Set session timeout (e.g., 8 hours)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)

# --- Database Setup ---
try:
    mongo_uri = os.getenv("MONGO_URI")
    if not mongo_uri:
        raise ValueError("MONGO_URI not found in environment variables.")

    client = MongoClient(mongo_uri)
    # Determine database name from URI or use default
    try:
        db_name = mongo_uri.split('/')[-1].split('?')[0]
        if not db_name or db_name == 'admin':
             raise IndexError
    except IndexError:
        db_name = 'hrms_db' # Default database name
        print(f"Warning: Could not parse DB name from MONGO_URI, using default '{db_name}'. Ensure this is correct.")

    db = client[db_name]

    # Collections
    users_collection = db.users
    attendance_collection = db.attendance
    leaves_collection = db.leaves
    payslips_collection = db.payslips

    # Ensure indexes for performance (create if they don't exist)
    users_collection.create_index("username", unique=True, background=True)
    attendance_collection.create_index([("user_id", 1), ("clock_in", -1)], background=True)
    leaves_collection.create_index([("user_id", 1), ("applied_date", -1)], background=True)
    leaves_collection.create_index("status", background=True)
    payslips_collection.create_index([("user_id", 1), ("year", -1), ("month", -1)], background=True)

    print(f"MongoDB connected successfully to database: '{db.name}'")
    client.admin.command('ping') # Verify connection is active
    print("MongoDB connection confirmed.")

except ValueError as ve:
     print(f"Configuration Error: {ve}")
     exit()
except Exception as e:
    # Catch specific connection errors if possible (e.g., pymongo.errors.ConnectionFailure)
    print(f"CRITICAL: Error connecting to or setting up MongoDB - {e}")
    print("Please ensure MongoDB is running and MONGO_URI is correct.")
    exit()


# --- Helper Functions & Decorators ---
def login_required(f):
    """Decorator: Ensures user is logged in (standard or admin)."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in to access this page.", "warning")
            session['next_url'] = request.url # Store intended URL for redirect after login
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator: Ensures user is logged in AND is marked as an admin."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in to access the admin area.", "warning")
            session['next_url'] = request.url
            return redirect(url_for('login'))
        if not session.get('is_admin'):
            # Log attempt to access admin area by non-admin?
            print(f"Access Denied: User {session.get('username')} (ID: {session.get('user_id')}) attempted to access admin route {request.path}")
            flash("You do not have permission to access the admin area.", "danger")
            return redirect(url_for('dashboard')) # Redirect non-admins to their dashboard
        return f(*args, **kwargs)
    return decorated_function


def get_current_user():
    """ Fetches the logged-in user's data from DB safely. Returns user dict or None. """
    user_id_str = session.get('user_id')
    if not user_id_str: return None

    try:
        user = users_collection.find_one({'_id': ObjectId(user_id_str)})
        if not user:
            print(f"Auth Warning: User ID {user_id_str} in session not found in DB. Clearing session.")
            session.clear()
            return None
        return user
    except Exception as e: # Catches InvalidId, DB errors etc.
        print(f"Error fetching user for session ID {user_id_str}: {e}")
        session.clear()
        return None


def get_today_attendance_status(user_id):
    """ Checks current day's clock-in/out status for a given user_id (ObjectId). """
    if not isinstance(user_id, ObjectId):
         print(f"Error: Invalid user_id type for attendance check: {type(user_id)}")
         return { "clocked_in": False, "clocked_out": False, "clock_in_time": None, "clock_out_time": None, "record_id": None }

    today_start = datetime.combine(date.today(), datetime.min.time())
    today_end = datetime.combine(date.today(), datetime.max.time())
    status = { "clocked_in": False, "clocked_out": False, "clock_in_time": None, "clock_out_time": None, "record_id": None }

    try:
        # Index should make this efficient: find latest record for user_id today
        record = attendance_collection.find_one(
            {'user_id': user_id, 'clock_in': {'$gte': today_start, '$lt': today_end}},
            sort=[('clock_in', -1)] )
        if record:
            status.update({
                "clocked_in": True, "clock_in_time": record.get('clock_in'),
                "record_id": record.get('_id'), "clocked_out": bool(record.get('clock_out')),
                "clock_out_time": record.get('clock_out') })
    except Exception as e:
        print(f"Error fetching attendance status for user {user_id}: {e}")
    return status


# --- Context Processors (Variables available to all templates) ---
@app.context_processor
def inject_global_vars():
    """ Injects common variables needed in base templates. """
    is_admin = False
    if 'user_id' in session: # Only check admin status if user is potentially logged in
        is_admin = session.get('is_admin', False)

    return {
        'now': datetime.now(),
        'is_admin': is_admin
    }

# --- Routes ---

# Development only route - REMOVE or PROTECT in production
@app.route('/setup_user')
def setup_user():
    """ Creates a default admin user if not present. Use with caution. """
    admin_username = "adminuser"
    # NEVER hardcode passwords like this in real applications
    admin_password = "password123"
    try:
        existing_user = users_collection.find_one({'username': admin_username})
        if not existing_user:
            hashed_password = generate_password_hash(admin_password)
            user_data = {'username': admin_username, 'password': hashed_password, 'full_name': 'Administrator',
                         'employee_id': 'ADM001', 'is_admin': True, 'created_at': datetime.utcnow()}
            users_collection.insert_one(user_data)
            msg = f"Admin user '{admin_username}' created. Login with password '{admin_password}'."
            print(f"SETUP: {msg}")
            return msg
        else:
            # Ensure existing user is admin
            if not existing_user.get('is_admin'):
                 users_collection.update_one({'_id': existing_user['_id']}, {'$set': {'is_admin': True}})
                 msg = f"User '{admin_username}' already exists. Updated to be an admin."
                 print(f"SETUP: {msg}")
                 return msg
            msg = f"Admin user '{admin_username}' already exists."
            print(f"SETUP: {msg}")
            return msg
    except Exception as e:
        print(f"Error in /setup_user: {e}")
        return f"Error setting up admin user: {e}", 500


@app.route('/login', methods=['GET', 'POST'])
def login():
    """ Handles user login and session creation. """
    if 'user_id' in session:
         return redirect(url_for('admin_dashboard' if session.get('is_admin') else 'dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if not username or not password:
            flash("Username and password are required.", "warning")
            return render_template('login.html'), 400

        try:
            user = users_collection.find_one({'username': username})
            if user and check_password_hash(user['password'], password):
                session.permanent = True # Use timeout from app.config
                session['user_id'] = str(user['_id'])
                session['username'] = user['username']
                session['is_admin'] = user.get('is_admin', False)

                flash(f"Welcome back, {user.get('full_name', user['username'])}!", "success")
                next_url = session.pop('next_url', None) # Redirect to previous page if stored
                if next_url: return redirect(next_url)
                return redirect(url_for('admin_dashboard' if session['is_admin'] else 'dashboard'))
            else:
                flash("Invalid username or password.", "danger")
        except Exception as e:
             print(f"Error during login attempt for user '{username}': {e}")
             flash("An error occurred during login.", "danger")
        return render_template('login.html'), 401 # Show login again on failure

    # GET request
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """ Clears session and redirects to login. """
    user_name = session.get('username', 'User')
    session.clear()
    flash(f"{user_name} logged out successfully.", "info")
    return redirect(url_for('login'))


# --- Standard User Routes ---

@app.route('/')
@app.route('/dashboard')
@login_required
def dashboard():
    """ Standard user dashboard. """
    if session.get('is_admin'): return redirect(url_for('admin_dashboard')) # Redirect admins away
    user = get_current_user()
    if not user: flash("Session invalid.", "warning"); return redirect(url_for('login'))
    attendance_status = get_today_attendance_status(user['_id'])
    return render_template('dashboard.html', user=user, attendance_status=attendance_status)

@app.route('/clock_in', methods=['POST'])
@login_required
def clock_in():
    user = get_current_user();
    if not user: return redirect(url_for('login'))
    if user.get('is_admin'): flash("Action not available for admins.", "warning"); return redirect(url_for('admin_dashboard'))

    user_id = user['_id']; attendance_status = get_today_attendance_status(user_id)
    if attendance_status["clocked_in"] and not attendance_status["clocked_out"]: flash("Already clocked in.", "warning")
    elif attendance_status["clocked_in"] and attendance_status["clocked_out"]: flash("Attendance complete for today.", "info")
    else:
        try:
            attendance_collection.insert_one({'user_id': user_id, 'username': user['username'], 'clock_in': datetime.now(), 'clock_out': None, 'date': date.today().strftime('%Y-%m-%d') })
            flash("Clocked in!", "success")
        except Exception as e: print(f"Err clock-in {user_id}: {e}"); flash("Clock-in error.", "danger")
    return redirect(url_for('dashboard'))

@app.route('/clock_out', methods=['POST'])
@login_required
def clock_out():
    user = get_current_user();
    if not user: return redirect(url_for('login'))
    if user.get('is_admin'): flash("Action not available for admins.", "warning"); return redirect(url_for('admin_dashboard'))

    user_id = user['_id']; attendance_status = get_today_attendance_status(user_id)
    if not attendance_status["clocked_in"]: flash("Clock in first.", "warning")
    elif attendance_status["clocked_out"]: flash("Already clocked out.", "warning")
    elif attendance_status["record_id"]:
        try:
            result = attendance_collection.update_one({'_id': attendance_status["record_id"], 'clock_out': None}, {'$set': {'clock_out': datetime.now()}} )
            if result.modified_count > 0: flash("Clocked out!", "success")
            else: flash("Already clocked out?", "warning")
        except Exception as e: print(f"Err clock-out {user_id} rec {attendance_status['record_id']}: {e}"); flash("Clock-out error.", "danger")
    else: flash("Cannot find clock-in record.", "danger")
    return redirect(url_for('dashboard'))

@app.route('/attendance')
@login_required
def view_attendance():
    if session.get('is_admin'): return redirect(url_for('admin_dashboard'))
    user = get_current_user();
    if not user: return redirect(url_for('login'))
    try: user_attendance = list(attendance_collection.find({'user_id': user['_id']}).sort('clock_in', -1))
    except Exception as e: print(f"Err fetch user att {user['_id']}: {e}"); flash("Error fetching attendance.", "danger"); user_attendance = []
    return render_template('attendance.html', user=user, attendance_records=user_attendance)

@app.route('/leaves')
@login_required
def view_leaves():
    if session.get('is_admin'): return redirect(url_for('admin_manage_leaves'))
    user = get_current_user();
    if not user: return redirect(url_for('login'))
    try: user_leaves = list(leaves_collection.find({'user_id': user['_id']}).sort('applied_date', -1))
    except Exception as e: print(f"Err fetch user leaves {user['_id']}: {e}"); flash("Error fetching leaves.", "danger"); user_leaves = []
    return render_template('leaves.html', user=user, leave_requests=user_leaves)

@app.route('/apply_leave', methods=['GET', 'POST'])
@login_required
def apply_leave():
    if session.get('is_admin'): flash("Admin leave process may differ.", "info"); return redirect(url_for('admin_dashboard'))
    user = get_current_user();
    if not user: return redirect(url_for('login'))

    form_data = request.form if request.method == 'POST' else {} # Preserve form data on error

    if request.method == 'POST':
        try:
            start_date_str=request.form.get('start_date'); end_date_str=request.form.get('end_date')
            leave_type=request.form.get('leave_type'); reason=request.form.get('reason','').strip()
            if not all([start_date_str, end_date_str, leave_type, reason]):
                 flash("All fields are required.", "warning"); return render_template('apply_leave.html', user=user, form_data=form_data), 400
            start_date=datetime.strptime(start_date_str, '%Y-%m-%d').date(); end_date=datetime.strptime(end_date_str, '%Y-%m-%d').date()
            if end_date < start_date: flash("End date cannot be before start date.", "warning"); return render_template('apply_leave.html', user=user, form_data=form_data), 400
            # TODO: Add validation: check against leave balance, check for overlapping approved leaves

            leave_data = {'user_id': user['_id'], 'username': user['username'], 'start_date': start_date_str, 'end_date': end_date_str,
                          'leave_type': leave_type, 'reason': reason, 'status': 'Pending', 'applied_date': datetime.now()}
            leaves_collection.insert_one(leave_data)
            flash("Leave request submitted successfully!", "success")
            return redirect(url_for('view_leaves'))
        except ValueError: flash("Invalid date format.", "danger"); return render_template('apply_leave.html', user=user, form_data=form_data), 400
        except Exception as e: print(f"Err apply leave {user['_id']}: {e}"); flash("Error submitting request.", "danger"); return render_template('apply_leave.html', user=user, form_data=form_data), 500

    # GET request
    return render_template('apply_leave.html', user=user, form_data={})

@app.route('/payslips')
@login_required
def view_payslips():
    if session.get('is_admin'): return redirect(url_for('admin_dashboard')) # TODO: Create admin payslip management page
    user = get_current_user();
    if not user: return redirect(url_for('login'))
    try: user_payslips = list(payslips_collection.find({'user_id': user['_id']}).sort([('year', -1), ('month', -1)]))
    except Exception as e: print(f"Err fetch user payslips {user['_id']}: {e}"); flash("Error fetching payslips.", "danger"); user_payslips = []
    return render_template('payslips.html', user=user, payslips=user_payslips)


# =========================
# === ADMIN PORTAL ROUTES ===
# =========================

@app.route('/admin')
@app.route('/admin/dashboard')
@admin_required # Use the admin decorator
def admin_dashboard():
    """ Admin dashboard displaying key statistics. """
    stats = {'user_count': 'N/A', 'pending_leaves_count': 'N/A', 'attendance_today': 'N/A'}
    try:
        stats['user_count'] = users_collection.count_documents({})
        stats['pending_leaves_count'] = leaves_collection.count_documents({'status': 'Pending'})
        # Example: Count distinct users who clocked in today
        today_start = datetime.combine(date.today(), datetime.min.time())
        today_end = datetime.combine(date.today(), datetime.max.time())
        stats['attendance_today'] = len(attendance_collection.distinct('user_id', {'clock_in': {'$gte': today_start, '$lt': today_end}}))
    except Exception as e:
        print(f"Error fetching admin dashboard stats: {e}")
        flash("Could not load some dashboard statistics.", "warning")
    return render_template('admin/dashboard.html', **stats) # Pass stats as keyword args

@app.route('/admin/users')
@admin_required
def admin_manage_users():
    """ Admin page to view users. """
    try: all_users = list(users_collection.find({}, {'password': 0}).sort('username', 1)) # Exclude password
    except Exception as e: print(f"Error admin fetch users: {e}"); flash("Could not load user list.", "danger"); all_users = []
    return render_template('admin/users.html', users=all_users)

@app.route('/admin/leaves')
@admin_required
def admin_manage_leaves():
    """ Admin page to view and filter leave requests. """
    try:
        filter_status = request.args.get('status', 'All')
        query = {}
        allowed_statuses = ['Pending', 'Approved', 'Rejected']
        if filter_status != 'All':
            if filter_status in allowed_statuses: query['status'] = filter_status
            else: flash(f"Invalid status filter: {filter_status}", "warning"); filter_status = 'All'
        all_leaves = list(leaves_collection.find(query).sort([('status', 1), ('applied_date', -1)]))
    except Exception as e: print(f"Error admin fetch leaves (filter: {filter_status}): {e}"); flash("Could not load leaves.", "danger"); all_leaves = []
    return render_template('admin/leaves.html', leaves=all_leaves, current_filter=filter_status)

@app.route('/admin/leaves/action/<leave_id>/<action>', methods=['POST'])
@admin_required
def admin_action_leave(leave_id, action):
    """ Admin endpoint to approve or reject a leave request. """
    if action not in ['approve', 'reject']: abort(400, "Invalid action.") # Bad request

    new_status = 'Approved' if action == 'approve' else 'Rejected'
    admin_username = session.get('username', 'SYSTEM') # Log who performed the action

    try:
        # Use find_one_and_update to be more atomic, check it was pending before updating
        updated_leave = leaves_collection.find_one_and_update(
            {'_id': ObjectId(leave_id), 'status': 'Pending'}, # Condition: Must be pending
            {'$set': {
                'status': new_status,
                'action_by': admin_username,
                'action_date': datetime.now()
            }},
            return_document=ReturnDocument.AFTER # Return the document *after* update
        )

        if updated_leave:
            flash(f"Leave request for {updated_leave.get('username', 'user')} {new_status.lower()} successfully.", "success")
            # TODO: Send notification to user updated_leave['user_id']
        else:
            # Check if it exists but wasn't pending
            existing_leave = leaves_collection.find_one({'_id': ObjectId(leave_id)})
            if existing_leave:
                 flash(f"Leave request already actioned (Status: {existing_leave.get('status','Unknown')}).", "warning")
            else:
                 flash("Leave request not found.", "warning")

    except Exception as e:
        print(f"Error actioning leave {leave_id} ({action}) by {admin_username}: {e}")
        flash("An error occurred while actioning the leave request.", "danger")

    # Redirect back to the leaves page, preserving previous filter if possible
    status_filter = request.referrer.split('status=')[-1] if request.referrer and 'status=' in request.referrer else 'All'
    # Validate the extracted filter before using it
    allowed_statuses = ['All', 'Pending', 'Approved', 'Rejected']
    if status_filter not in allowed_statuses: status_filter = 'All'

    return redirect(url_for('admin_manage_leaves', status=status_filter))


# --- Error Handling ---
@app.errorhandler(404)
def page_not_found(e):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    # Log the error e
    print(f"Internal Server Error: {e}") # Log detailed error to console/file
    return render_template('errors/500.html'), 500

@app.errorhandler(403)
def forbidden(e):
    return render_template('errors/403.html'), 403


# --- Main Execution ---
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5001))
    is_debug = os.environ.get("FLASK_ENV", "production").lower() == "development"

    print(f"--- HRMS Portal ({'Development' if is_debug else 'Production'}) ---")
    if is_debug: print("WARNING: Debug mode is ON. Do NOT use in production.")
    print(f" * Environment: {os.environ.get('FLASK_ENV', 'production')}")
    print(f" * Database: mongodb://.../{db.name}")
    print(f" * Listening on http://0.0.0.0:{port}")
    print("--- Press CTRL+C to quit ---")

    # Use threaded=True only for development, use WSGI server in production
    app.run(host='0.0.0.0', port=port, debug=is_debug, threaded=is_debug)