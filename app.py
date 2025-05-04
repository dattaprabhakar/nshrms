# hrms_portal/app.py
import os
import calendar
# --- Flask and related imports ---
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
# --- Database and ObjectId ---
from pymongo import MongoClient, ReturnDocument
from bson import ObjectId
# --- Standard Python Libraries ---
from datetime import datetime, date, timedelta
from functools import wraps
from dotenv import load_dotenv

load_dotenv() # Load environment variables from .env file

app = Flask(__name__)

# --- Core Application Configuration ---
app.secret_key = os.getenv("SECRET_KEY")
if not app.secret_key:
    print("CRITICAL: SECRET_KEY not found in environment variables. Application startup aborted.")
    exit(1) # Exit if secret key is missing

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8) # Example session timeout
# Set debug status based on FLASK_ENV (Flask >= 2.3 reads this)
# For production, set FLASK_ENV=production
app.config['DEBUG'] = os.environ.get('FLASK_ENV', 'production').lower() == 'development'

# --- Payslip Storage Configuration ---
PAYSLIP_STORAGE_PATH = os.getenv("PAYSLIP_FOLDER")
if not PAYSLIP_STORAGE_PATH:
    print("CRITICAL: PAYSLIP_FOLDER environment variable not set. Payslip downloads will fail.")
    # You might want to default to a clearly invalid path or exit depending on requirements
    PAYSLIP_STORAGE_PATH = None # Indicate that it's not configured
    # exit(1) # Alternatively, force exit if payslips are critical
elif not os.path.isdir(PAYSLIP_STORAGE_PATH):
    print(f"CRITICAL: Configured PAYSLIP_FOLDER '{PAYSLIP_STORAGE_PATH}' does not exist or is not a directory.")
    exit(1) # Exit if configured path is invalid
else:
     print(f"INFO: Payslip storage configured at: {PAYSLIP_STORAGE_PATH}")


# --- Database Setup ---
try:
    mongo_uri = os.getenv("MONGO_URI")
    if not mongo_uri: raise ValueError("MONGO_URI not found in environment variables.")

    client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5000) # Added timeout
    # Determine database name from URI or use default
    try:
        db_name_part = mongo_uri.split('/')[-1]
        db_name = db_name_part.split('?')[0]
        if not db_name or db_name == 'admin': # Avoid using 'admin' db directly
             raise IndexError("Invalid or missing database name in URI")
    except IndexError:
        db_name = 'hrms_db' # Default database name
        print(f"Warning: Could not parse DB name from MONGO_URI, using default '{db_name}'. Ensure this is correct.")

    db = client[db_name]

    # Define collections
    users_collection = db.users
    attendance_collection = db.attendance
    leaves_collection = db.leaves
    payslips_collection = db.payslips

    # Verify connection by pinging the server
    client.admin.command('ping')
    print(f"INFO: MongoDB connected successfully to database: '{db.name}'")

    # Ensure indexes exist (create if not present, run in background)
    users_collection.create_index("username", unique=True, background=True)
    users_collection.create_index("employee_id", unique=True, background=True, sparse=True)
    attendance_collection.create_index([("user_id", 1), ("clock_in", -1)], background=True)
    leaves_collection.create_index([("user_id", 1), ("applied_date", -1)], background=True)
    leaves_collection.create_index("status", background=True)
    payslips_collection.create_index([("user_id", 1), ("year", -1), ("month", -1)], background=True)
    print("INFO: MongoDB indexes checked/created.")

except ValueError as ve:
     print(f"CRITICAL Config Error: {ve}")
     exit(1)
except Exception as e: # Catch more specific pymongo errors later if needed
    print(f"CRITICAL: Error connecting to or setting up MongoDB - {e}")
    print("Please ensure MongoDB is running and MONGO_URI is configured correctly.")
    exit(1)


# --- Helper Functions & Decorators ---
def login_required(f):
    """Decorator: Ensures user is logged in (standard or admin)."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in to access this page.", "warning")
            session['next_url'] = request.url
            return redirect(url_for('login'))
        # Optional: Check if user still exists in DB? (more robust session check)
        # user = get_current_user()
        # if not user:
        #    flash("Session expired or invalid. Please log in again.", "warning")
        #    return redirect(url_for('login'))
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
            print(f"Access Denied: User {session.get('username')} ({session.get('user_id')}) attempted admin route {request.path}")
            flash("Admin access required for this page.", "danger")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def get_current_user():
    """ Fetches the logged-in user's data from DB safely. Returns user dict or None. """
    user_id_str = session.get('user_id')
    if not user_id_str: return None
    try:
        # Ensure ID is valid before querying
        user_object_id = ObjectId(user_id_str)
        user = users_collection.find_one({'_id': user_object_id})
        if not user:
            print(f"Auth Warning: User ID {user_id_str} in session not found. Clearing session.")
            session.clear()
            return None
        return user
    except Exception as e: # Catches InvalidId (from ObjectId) or DB errors
        print(f"Error fetching user for session ID {user_id_str}: {e}")
        session.clear()
        return None

def get_today_attendance_status(user_id):
    """ Checks current day's clock-in/out status for a given user_id (ObjectId). """
    default_status = {"clocked_in":False,"clocked_out":False,"clock_in_time":None,"clock_out_time":None,"record_id":None}
    if not isinstance(user_id, ObjectId):
        print(f"Error: Invalid user_id type ({type(user_id)}) for attendance check.")
        return default_status

    today_start = datetime.combine(date.today(), datetime.min.time())
    today_end = datetime.combine(date.today(), datetime.max.time())
    status = default_status.copy() # Start with default

    try:
        record = attendance_collection.find_one(
            {'user_id': user_id, 'clock_in': {'$gte': today_start, '$lt': today_end}},
            sort=[('clock_in', -1)] ) # Get latest record for today
        if record:
            status.update({
                "clocked_in": True,
                "clock_in_time": record.get('clock_in'),
                "record_id": record.get('_id'),
                "clocked_out": bool(record.get('clock_out')), # Check if clock_out exists and is not None
                "clock_out_time": record.get('clock_out')
            })
    except Exception as e:
        print(f"Error fetching attendance status for user {user_id}: {e}")
        # Return default status on error
    return status


# --- Context Processors (Variables available to all templates) ---
@app.context_processor
def inject_global_vars():
    """ Injects common variables into all templates' contexts. """
    is_admin = False
    if 'user_id' in session: # Only check admin status if user is potentially logged in
        is_admin = session.get('is_admin', False)
    # Pass debug status for conditional rendering in templates
    debug_status = app.config.get('DEBUG', False)
    return {
        'now': datetime.now(),
        'is_admin': is_admin,
        'debug_status': debug_status
    }

# --- Routes ---

@app.route('/setup_user') # Development only route - REMOVE or PROTECT in production
def setup_user():
    """ Creates/updates a default admin user AND a standard user with sample data. """
    admin_username = "adminuser"; admin_password = "password123" # CHANGE THIS IN PRODUCTION
    user_username = "testuser"; user_password = "password123" # CHANGE THIS
    messages = []
    try:
        # Admin User Setup
        existing_admin = users_collection.find_one({'username': admin_username})
        if not existing_admin:
            hashed_pw = generate_password_hash(admin_password)
            user_data={'username':admin_username,'password':hashed_pw,'full_name':'Administrator','employee_id':'ADM001','is_admin':True,'created_at':datetime.utcnow()}
            users_collection.insert_one(user_data)
            msg = f"Admin '{admin_username}' created."
        else:
            msg = f"Admin '{admin_username}' exists."
            if not existing_admin.get('is_admin'): users_collection.update_one({'_id': existing_admin['_id']}, {'$set': {'is_admin': True}}); msg += " (Promoted to Admin)"
        messages.append(msg)

        # Standard User Setup
        existing_user = users_collection.find_one({'username': user_username})
        if not existing_user:
             hashed_pw = generate_password_hash(user_password)
             user_data={'username':user_username,'password':hashed_pw,'full_name':'Test User', 'employee_id':'EMP001','is_admin':False,'created_at':datetime.utcnow(), 'job_title':'Software Engineer', 'department':'Technology', 'location':'Remote', 'email':'test@example.com', 'mobile':'123-456-7890'}
             users_collection.insert_one(user_data)
             msg = f"Standard user '{user_username}' created."
        else: msg = f"Standard user '{user_username}' exists."
        messages.append(msg)

        final_message = " | ".join(messages)
        print(f"SETUP: {final_message}")
        return final_message
    except Exception as e:
        print(f"Error during /setup_user: {e}")
        return f"Error during setup: {e}", 500


@app.route('/login', methods=['GET', 'POST'])
def login():
    """ Handles user login and session creation. """
    if 'user_id' in session: return redirect(url_for('admin_dashboard' if session.get('is_admin') else 'dashboard'))

    if request.method == 'POST':
        username = request.form.get('username','').strip()
        password = request.form.get('password','')
        if not username or not password:
            flash("Username and password required.", "warning")
            return render_template('login.html'), 400
        try:
            user = users_collection.find_one({'username': username})
            if user and check_password_hash(user['password'], password):
                session.permanent = True # Use timeout from app.config
                session['user_id'] = str(user['_id'])
                session['username'] = user['username']
                session['is_admin'] = user.get('is_admin', False) # Store admin status
                flash(f"Welcome, {user.get('full_name', user['username'])}!", "success")
                next_url = session.pop('next_url', None) # Redirect to previous page if stored
                return redirect(next_url or url_for('admin_dashboard' if session['is_admin'] else 'dashboard'))
            else: flash("Invalid username or password.", "danger") # Invalid credentials
        except Exception as e:
             print(f"Error during login attempt for user '{username}': {e}")
             flash("An error occurred during login. Please try again later.", "danger")
        return render_template('login.html'), 401 # Show login again on failure

    # GET request
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """ Clears session and redirects to login. """
    user_name = session.get('username', 'User'); session.clear()
    flash(f"{user_name} logged out successfully.", "info"); return redirect(url_for('login'))


# --- Standard User Routes ---
@app.route('/')
@app.route('/dashboard')
@login_required
def dashboard():
    """ Standard user dashboard. """
    if session.get('is_admin'): return redirect(url_for('admin_dashboard')) # Redirect admins
    user=get_current_user();
    if not user: flash("Session invalid.", "warning"); return redirect(url_for('login'))
    attendance_status = get_today_attendance_status(user['_id'])
    return render_template('dashboard.html', user=user, attendance_status=attendance_status)

@app.route('/clock_in', methods=['POST'])
@login_required
def clock_in():
    user=get_current_user();
    if not user: return redirect(url_for('login'))
    if user.get('is_admin'): flash("Action not available for admins.", "warning"); return redirect(url_for('admin_dashboard'))
    user_id=user['_id']; attendance_status=get_today_attendance_status(user_id)
    if attendance_status["clocked_in"] and not attendance_status["clocked_out"]: flash("Already clocked in.", "warning")
    elif attendance_status["clocked_in"] and attendance_status["clocked_out"]: flash("Attendance complete for today.", "info")
    else:
        try: attendance_collection.insert_one({'user_id':user_id,'username':user['username'],'clock_in':datetime.now(),'clock_out':None,'date':date.today().strftime('%Y-%m-%d')}); flash("Clocked in!", "success")
        except Exception as e: print(f"Err clock-in {user_id}: {e}"); flash("Clock-in error.", "danger")
    return redirect(request.referrer or url_for('dashboard')) # Redirect back to previous page or dashboard

@app.route('/clock_out', methods=['POST'])
@login_required
def clock_out():
    user = get_current_user();
    if not user: return redirect(url_for('login'))
    if user.get('is_admin'): flash("Action not available for admins.", "warning"); return redirect(url_for('admin_dashboard'))
    user_id=user['_id']; attendance_status=get_today_attendance_status(user_id)
    if not attendance_status["clocked_in"]: flash("Clock in first.", "warning")
    elif attendance_status["clocked_out"]: flash("Already clocked out.", "warning")
    elif attendance_status["record_id"]:
        try: result=attendance_collection.update_one({'_id':attendance_status["record_id"],'clock_out':None},{'$set':{'clock_out':datetime.now()}}); flash("Clocked out!" if result.modified_count>0 else "Already clocked out?", "success" if result.modified_count>0 else "warning")
        except Exception as e: print(f"Err clock-out {user_id} rec {attendance_status['record_id']}: {e}"); flash("Clock-out error.", "danger")
    else: flash("Cannot find clock-in record to clock out.", "danger")
    return redirect(request.referrer or url_for('dashboard')) # Redirect back

@app.route('/attendance')
@login_required
def view_attendance():
    """ Displays detailed attendance page for the logged-in user. """
    if session.get('is_admin'): flash("Admin attendance view TBD.", "info"); return redirect(url_for('admin_dashboard'))
    user=get_current_user();
    if not user: return redirect(url_for('login'))
    user_attendance = []; attendance_status = {"clocked_in":False,"clocked_out":False,"clock_in_time":None,"clock_out_time":None,"record_id":None}
    try:
        user_attendance = list(attendance_collection.find({'user_id':user['_id']}).sort('clock_in',-1))
        attendance_status = get_today_attendance_status(user['_id']) # Needed for Actions widget on this page
    except Exception as e: print(f"Err fetch user att data {user['_id']}: {e}"); flash("Error fetching attendance data.", "danger")
    return render_template('attendance.html', user=user, attendance_records=user_attendance, attendance_status=attendance_status)

@app.route('/leaves')
@login_required
def view_leaves():
    if session.get('is_admin'): return redirect(url_for('admin_manage_leaves'))
    user=get_current_user();
    if not user: return redirect(url_for('login'))
    try: user_leaves = list(leaves_collection.find({'user_id':user['_id']}).sort('applied_date',-1))
    except Exception as e: print(f"Err fetch user leaves {user['_id']}: {e}"); flash("Error fetching leaves.", "danger"); user_leaves=[]
    return render_template('leaves.html', user=user, leave_requests=user_leaves)

@app.route('/apply_leave', methods=['GET', 'POST'])
@login_required
def apply_leave():
    if session.get('is_admin'): flash("Admin leave differs.", "info"); return redirect(url_for('admin_dashboard'))
    user=get_current_user();
    if not user: return redirect(url_for('login'))
    form_data = request.form if request.method == 'POST' else {}
    if request.method == 'POST':
        try:
            start_date_str=request.form.get('start_date'); end_date_str=request.form.get('end_date')
            leave_type=request.form.get('leave_type'); reason=request.form.get('reason','').strip()
            if not all([start_date_str,end_date_str,leave_type,reason]): flash("All fields required.", "warning"); return render_template('apply_leave.html',user=user,form_data=form_data), 400
            start_date=datetime.strptime(start_date_str,'%Y-%m-%d').date(); end_date=datetime.strptime(end_date_str,'%Y-%m-%d').date()
            if end_date < start_date: flash("End date before start date.", "warning"); return render_template('apply_leave.html',user=user,form_data=form_data), 400
            leave_data = {'user_id':user['_id'],'username':user['username'],'start_date':start_date_str,'end_date':end_date_str,'leave_type':leave_type,'reason':reason,'status':'Pending','applied_date':datetime.now()}
            leaves_collection.insert_one(leave_data)
            flash("Leave request submitted!", "success"); return redirect(url_for('view_leaves'))
        except ValueError: flash("Invalid date format.", "danger"); return render_template('apply_leave.html',user=user,form_data=form_data), 400
        except Exception as e: print(f"Err apply leave {user['_id']}: {e}"); flash("Error submitting request.", "danger"); return render_template('apply_leave.html',user=user,form_data=form_data), 500
    return render_template('apply_leave.html', user=user, form_data={})

@app.route('/payslips')
@login_required
def view_payslips():
    if session.get('is_admin'): return redirect(url_for('admin_dashboard'))
    user=get_current_user();
    if not user: return redirect(url_for('login'))
    try: user_payslips = list(payslips_collection.find({'user_id':user['_id']}).sort([('year',-1),('month',-1)]))
    except Exception as e: print(f"Err fetch user payslips {user['_id']}: {e}"); flash("Error fetching payslips.", "danger"); user_payslips=[]
    return render_template('payslips.html', user=user, payslips=user_payslips)

@app.route('/download/payslip/<payslip_id>')
@login_required
def download_payslip(payslip_id):
    """ Securely sends a payslip file for download if user owns it. """
    if not PAYSLIP_STORAGE_PATH: # Check if storage path is configured
         flash("Payslip download is currently unavailable. Please contact support.", "danger")
         print("Error: Download attempted but PAYSLIP_FOLDER is not configured.")
         return redirect(url_for('view_payslips'))

    user = get_current_user();
    if not user: abort(401)
    safe_filename = None # Initialize for error logging

    try:
        payslip_object_id = ObjectId(payslip_id)
        payslip_doc = payslips_collection.find_one({'_id': payslip_object_id})
        if not payslip_doc: abort(404)
        # SECURITY CHECK: Ensure the logged-in user owns this payslip
        if payslip_doc.get('user_id') != user['_id']: abort(403)

        db_filename = payslip_doc.get('file_name')
        if not db_filename: flash("Payslip record has no file.", "warning"); return redirect(url_for('view_payslips'))

        safe_filename = secure_filename(db_filename)
        if safe_filename != db_filename: abort(400, "Invalid filename.") # Potential manipulation

        print(f"Download request: User {user['_id']}, Payslip {payslip_id}, File '{safe_filename}'")
        return send_from_directory(directory=PAYSLIP_STORAGE_PATH, path=safe_filename, as_attachment=True)

    except InvalidId: abort(404) # Bad payslip_id format
    except FileNotFoundError:
        print(f"Download Error: File not found: {os.path.join(PAYSLIP_STORAGE_PATH, safe_filename if safe_filename else payslip_id)}")
        flash(f"Payslip file not found. Contact support.", "danger"); return redirect(url_for('view_payslips'))
    except Exception as e:
        print(f"Error during payslip download {payslip_id} for user {user['_id']}: {e}")
        flash("Error downloading payslip.", "danger"); return redirect(url_for('view_payslips'))


@app.route('/my_team')
@login_required
def my_team():
    if session.get('is_admin'): flash("Team view NA for admin.", "info"); return redirect(url_for('admin_dashboard'))
    user = get_current_user();
    if not user: return redirect(url_for('login'))
    team_stats = {"off_today_list":[], "not_in_yet_list":[], "on_time_count":0, "late_arrivals_count":0, "wfh_od_count":0, "remote_clockins_count":0}
    current_date = date.today(); calendar_data = {"year": current_date.year, "month": current_date.month, "month_name": current_date.strftime("%B"), "weeks": []}
    try:
        today_str = current_date.strftime('%Y-%m-%d'); current_user_id = user['_id']
        users_off_today = list(leaves_collection.find({"status":"Approved","start_date":{"$lte":today_str},"end_date":{"$gte":today_str},"user_id":{"$ne":current_user_id}},{"username":1,"leave_type":1,"_id":1}))
        team_stats["off_today_list"] = users_off_today; off_today_ids = {u['_id'] for u in users_off_today}
        today_start=datetime.combine(current_date,datetime.min.time()); today_end=datetime.combine(current_date,datetime.max.time())
        clocked_in_ids = set(attendance_collection.distinct('user_id', {'clock_in': {'$gte':today_start, '$lt':today_end}}))
        # TODO: Define "team" more accurately later (e.g., based on manager field)
        all_team_users = list(users_collection.find({"_id":{"$ne": current_user_id},"is_admin":{"$ne":True}},{"_id":1,"username":1}))
        not_in_yet_list = [team_user['username'] for team_user in all_team_users if team_user['_id'] not in clocked_in_ids and team_user['_id'] not in off_today_ids]
        team_stats["not_in_yet_list"] = not_in_yet_list
        calendar_data["weeks"] = calendar.monthcalendar(calendar_data["year"], calendar_data["month"])
        team_stats['on_time_count'] = len(clocked_in_ids) # Placeholder stat
    except Exception as e: print(f"Err My Team {user['_id']}: {e}"); flash("Could not load team data.", "warning")
    return render_template('my_team.html', user=user, team_stats=team_stats, calendar_data=calendar_data)

@app.route('/organization/employees')
@login_required
def view_employee_directory():
    if session.get('is_admin'): return redirect(url_for('admin_manage_users'))
    user = get_current_user();
    if not user: return redirect(url_for('login'))
    employees = []
    try: employees = list(users_collection.find({'is_admin': {'$ne': True}}, {'password': 0}).sort('full_name', 1))
    except Exception as e: print(f"Error fetching employee directory: {e}"); flash("Could not load directory.", "danger")
    return render_template('org/employee_directory.html', user=user, employees=employees)

# =========================
# === ADMIN PORTAL ROUTES ===
# =========================
@app.route('/admin')
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    user = get_current_user();
    if not user: flash("Admin session invalid.", "warning"); return redirect(url_for('login'))
    stats = {'user_count':'N/A', 'pending_leaves_count':'N/A', 'attendance_today':'N/A'}
    try:
        stats['user_count'] = users_collection.count_documents({})
        stats['pending_leaves_count'] = leaves_collection.count_documents({'status': 'Pending'})
        today_start=datetime.combine(date.today(),datetime.min.time()); today_end=datetime.combine(date.today(),datetime.max.time())
        stats['attendance_today'] = len(attendance_collection.distinct('user_id', {'clock_in':{'$gte':today_start,'$lt':today_end}}))
    except Exception as e: print(f"Err admin dashboard stats: {e}"); flash("Could not load stats.", "warning")
    return render_template('admin/dashboard.html', user=user, **stats)

@app.route('/admin/users')
@admin_required
def admin_manage_users():
    user = get_current_user();
    if not user: return redirect(url_for('login'))
    try: all_users = list(users_collection.find({}, {'password':0}).sort('username',1))
    except Exception as e: print(f"Err admin fetch users: {e}"); flash("Could not load users.", "danger"); all_users=[]
    return render_template('admin/users.html', user=user, users=all_users)

@app.route('/admin/users/add', methods=['GET', 'POST'])
@admin_required
def admin_add_user():
    user = get_current_user()
    if not user: return redirect(url_for('login'))
    form_data = request.form if request.method == 'POST' else {}
    if request.method == 'POST':
        username=request.form.get('username','').strip(); password=request.form.get('password','')
        full_name=request.form.get('full_name','').strip(); employee_id=request.form.get('employee_id','').strip()
        email=request.form.get('email','').strip() or None; mobile=request.form.get('mobile','').strip() or None
        job_title=request.form.get('job_title','').strip() or None; department=request.form.get('department','').strip() or None
        location=request.form.get('location','').strip() or None; is_admin=request.form.get('is_admin') == 'on'
        # Validation
        required_fields={'Username':username,'Password':password,'Full Name':full_name,'Employee ID':employee_id}
        errors = {k:f"{k} required." for k,v in required_fields.items() if not v}
        if not errors:
            check_exist = users_collection.find_one({'$or': [{'username': username}, {'employee_id': employee_id}]})
            if check_exist: field = 'Username' if check_exist['username'] == username else 'Employee ID'; errors['unique'] = f"{field} '{check_exist[field.lower().replace(' ','_')]}' already exists."
        if errors:
            for error_msg in errors.values(): flash(error_msg, 'danger')
            return render_template('admin/add_user.html', user=user, form_data=form_data), 400
        # Process Valid Data
        try:
            hashed_password = generate_password_hash(password)
            new_user_data = {'username':username,'password':hashed_password,'full_name':full_name,'employee_id':employee_id,'email':email,'mobile':mobile,'job_title':job_title,'department':department,'location':location,'is_admin':is_admin,'created_at':datetime.utcnow()}
            result = users_collection.insert_one(new_user_data)
            if result.inserted_id: flash(f"Employee '{full_name}' added!", 'success'); return redirect(url_for('admin_manage_users'))
            else: flash("DB issue adding employee.", 'danger')
        except Exception as e: print(f"Err adding user '{username}': {e}"); flash(f"Error: {e}", 'danger')
        return render_template('admin/add_user.html', user=user, form_data=form_data), 500
    return render_template('admin/add_user.html', user=user, form_data={}) # GET

@app.route('/admin/leaves')
@admin_required
def admin_manage_leaves():
    user = get_current_user();
    if not user: return redirect(url_for('login'))
    try:
        filter_status = request.args.get('status','All')
        query={}; allowed_statuses=['Pending','Approved','Rejected']
        if filter_status != 'All':
            if filter_status in allowed_statuses: query['status'] = filter_status
            else: flash(f"Invalid filter: {filter_status}", "warning"); filter_status='All'
        all_leaves = list(leaves_collection.find(query).sort([('status',1),('applied_date',-1)]))
    except Exception as e: print(f"Err admin fetch leaves (filter: {filter_status}): {e}"); flash("Could not load leaves.", "danger"); all_leaves=[]
    return render_template('admin/leaves.html', user=user, leaves=all_leaves, current_filter=filter_status)

@app.route('/admin/leaves/action/<leave_id>/<action>', methods=['POST'])
@admin_required
def admin_action_leave(leave_id, action):
    if action not in ['approve','reject']: abort(400, "Invalid action.")
    new_status = 'Approved' if action == 'approve' else 'Rejected'
    admin_username = session.get('username','SYSTEM')
    try:
        updated_leave = leaves_collection.find_one_and_update(
            {'_id':ObjectId(leave_id),'status':'Pending'}, {'$set':{'status':new_status,'action_by':admin_username,'action_date':datetime.now()}},
            return_document=ReturnDocument.AFTER )
        if updated_leave: flash(f"Leave for {updated_leave.get('username','user')} {new_status.lower()}.", "success")
        else:
            existing = leaves_collection.find_one({'_id':ObjectId(leave_id)})
            flash(f"Leave already actioned (Status: {existing.get('status','?')})." if existing else "Leave not found.", "warning")
    except Exception as e: print(f"Err action leave {leave_id} ({action}) by {admin_username}: {e}"); flash("Error actioning leave.", "danger")
    status_filter=request.referrer.split('status=')[-1] if request.referrer and 'status=' in request.referrer else 'All'
    allowed_statuses=['All','Pending','Approved','Rejected']
    if status_filter not in allowed_statuses: status_filter='All'
    return redirect(url_for('admin_manage_leaves', status=status_filter))

@app.route('/admin/settings')
@admin_required
def admin_settings():
    user = get_current_user();
    if not user: return redirect(url_for('login'))
    return render_template('admin/settings.html', user=user)

# --- Error Handling ---
@app.errorhandler(404)
def page_not_found(e): user = get_current_user(); return render_template('errors/404.html', user=user), 404
@app.errorhandler(500)
def internal_server_error(e): user = get_current_user(); print(f"Internal Server Error: {e}"); return render_template('errors/500.html', user=user), 500
@app.errorhandler(403)
def forbidden(e): user = get_current_user(); return render_template('errors/403.html', user=user), 403

# --- Main Execution ---
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5001))
    is_debug = app.config['DEBUG']
    print(f"--- HRMS Portal ({'Development' if is_debug else 'Production'}) ---")
    if is_debug: print("WARNING: Debug mode is ON.")
    print(f" * Environment: {os.environ.get('FLASK_ENV', 'production')}")
    print(f" * Database: mongodb://.../{db.name}")
    print(f" * Listening on http://0.0.0.0:{port}")
    print("--- Press CTRL+C to quit ---")
    app.run(host='0.0.0.0', port=port, threaded=is_debug) # Use default Flask debug setting