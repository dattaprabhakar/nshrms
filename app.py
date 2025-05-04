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
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8) # Session timeout
app.config['DEBUG'] = os.environ.get('FLASK_ENV', 'production').lower() == 'development'

# --- Database Setup ---
try:
    mongo_uri = os.getenv("MONGO_URI")
    if not mongo_uri: raise ValueError("MONGO_URI not found in environment variables.")
    client = MongoClient(mongo_uri)
    try:
        db_name = mongo_uri.split('/')[-1].split('?')[0]
        if not db_name or db_name == 'admin': raise IndexError
    except IndexError: db_name = 'hrms_db'
    db = client[db_name]
    users_collection = db.users; attendance_collection = db.attendance
    leaves_collection = db.leaves; payslips_collection = db.payslips
    # Ensure indexes
    users_collection.create_index("username", unique=True, background=True)
    attendance_collection.create_index([("user_id", 1), ("clock_in", -1)], background=True)
    leaves_collection.create_index([("user_id", 1), ("applied_date", -1)], background=True)
    leaves_collection.create_index("status", background=True)
    payslips_collection.create_index([("user_id", 1), ("year", -1), ("month", -1)], background=True)
    print(f"MongoDB connected successfully to database: '{db.name}'")
    client.admin.command('ping')
    print("MongoDB connection confirmed.")
except ValueError as ve: print(f"Config Error: {ve}"); exit()
except Exception as e: print(f"CRITICAL: Error connecting to MongoDB - {e}"); exit()


# --- Helper Functions & Decorators ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in to access this page.", "warning")
            session['next_url'] = request.url
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in to access the admin area.", "warning")
            session['next_url'] = request.url
            return redirect(url_for('login'))
        if not session.get('is_admin'):
            print(f"Access Denied: User {session.get('username')} attempted admin route {request.path}")
            flash("Admin access required.", "danger")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def get_current_user():
    user_id_str = session.get('user_id')
    if not user_id_str: return None
    try:
        user = users_collection.find_one({'_id': ObjectId(user_id_str)})
        if not user: session.clear(); return None
        return user
    except Exception as e: print(f"Err fetch user {user_id_str}: {e}"); session.clear(); return None

def get_today_attendance_status(user_id):
    if not isinstance(user_id, ObjectId): return {"clocked_in":False,"clocked_out":False,"clock_in_time":None,"clock_out_time":None,"record_id":None}
    today_start = datetime.combine(date.today(), datetime.min.time())
    today_end = datetime.combine(date.today(), datetime.max.time())
    status = {"clocked_in":False,"clocked_out":False,"clock_in_time":None,"clock_out_time":None,"record_id":None}
    try:
        record = attendance_collection.find_one({'user_id': user_id, 'clock_in': {'$gte': today_start, '$lt': today_end}}, sort=[('clock_in', -1)])
        if record: status.update({"clocked_in":True,"clock_in_time":record.get('clock_in'), "record_id":record.get('_id'), "clocked_out":bool(record.get('clock_out')), "clock_out_time":record.get('clock_out')})
    except Exception as e: print(f"Err fetch att status {user_id}: {e}")
    return status

# --- Context Processors ---
@app.context_processor
def inject_global_vars():
    is_admin = False
    if 'user_id' in session: is_admin = session.get('is_admin', False)
    debug_status = app.config.get('DEBUG', False)
    return {'now': datetime.now(), 'is_admin': is_admin, 'debug_status': debug_status}

# --- Routes ---

@app.route('/setup_user') # Development only
def setup_user():
    admin_username = "adminuser"; admin_password = "password123"
    try:
        existing_user = users_collection.find_one({'username': admin_username})
        if not existing_user:
            hashed_password = generate_password_hash(admin_password)
            user_data = {'username':admin_username,'password':hashed_password,'full_name':'Administrator', 'employee_id':'ADM001','is_admin':True,'created_at':datetime.utcnow()}
            users_collection.insert_one(user_data)
            msg = f"Admin user '{admin_username}' created. PW: '{admin_password}'."
        else:
            if not existing_user.get('is_admin'):
                 users_collection.update_one({'_id': existing_user['_id']}, {'$set': {'is_admin': True}})
                 msg = f"User '{admin_username}' exists. Updated to admin."
            else: msg = f"Admin user '{admin_username}' already exists."
        print(f"SETUP: {msg}"); return msg
    except Exception as e: print(f"Err setup_user: {e}"); return f"Error: {e}", 500

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session: return redirect(url_for('admin_dashboard' if session.get('is_admin') else 'dashboard'))
    if request.method == 'POST':
        username = request.form.get('username','').strip(); password = request.form.get('password','')
        if not username or not password: flash("Username and password required.", "warning"); return render_template('login.html'), 400
        try:
            user = users_collection.find_one({'username': username})
            if user and check_password_hash(user['password'], password):
                session.permanent = True
                session['user_id'] = str(user['_id']); session['username'] = user['username']
                session['is_admin'] = user.get('is_admin', False)
                flash(f"Welcome, {user.get('full_name', user['username'])}!", "success")
                next_url = session.pop('next_url', None)
                return redirect(next_url or url_for('admin_dashboard' if session['is_admin'] else 'dashboard'))
            else: flash("Invalid credentials.", "danger")
        except Exception as e: print(f"Err login '{username}': {e}"); flash("Login error.", "danger")
        return render_template('login.html'), 401
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    user_name = session.get('username', 'User'); session.clear()
    flash(f"{user_name} logged out.", "info"); return redirect(url_for('login'))

# --- Standard User Routes ---
@app.route('/')
@app.route('/dashboard')
@login_required
def dashboard():
    if session.get('is_admin'): return redirect(url_for('admin_dashboard'))
    user = get_current_user();
    if not user: flash("Session invalid.", "warning"); return redirect(url_for('login'))
    attendance_status = get_today_attendance_status(user['_id'])
    return render_template('dashboard.html', user=user, attendance_status=attendance_status)

@app.route('/clock_in', methods=['POST'])
@login_required
def clock_in():
    user=get_current_user();
    if not user: return redirect(url_for('login'))
    if user.get('is_admin'): flash("Action NA for admins.", "warning"); return redirect(url_for('admin_dashboard'))
    user_id=user['_id']; attendance_status=get_today_attendance_status(user_id)
    if attendance_status["clocked_in"] and not attendance_status["clocked_out"]: flash("Already clocked in.", "warning")
    elif attendance_status["clocked_in"] and attendance_status["clocked_out"]: flash("Attendance complete.", "info")
    else:
        try: attendance_collection.insert_one({'user_id':user_id,'username':user['username'],'clock_in':datetime.now(),'clock_out':None,'date':date.today().strftime('%Y-%m-%d')}); flash("Clocked in!", "success")
        except Exception as e: print(f"Err clock-in {user_id}: {e}"); flash("Clock-in error.", "danger")
    return redirect(url_for('dashboard'))

@app.route('/clock_out', methods=['POST'])
@login_required
def clock_out():
    user = get_current_user();
    if not user: return redirect(url_for('login'))
    if user.get('is_admin'): flash("Action NA for admins.", "warning"); return redirect(url_for('admin_dashboard'))
    user_id=user['_id']; attendance_status=get_today_attendance_status(user_id)
    if not attendance_status["clocked_in"]: flash("Clock in first.", "warning")
    elif attendance_status["clocked_out"]: flash("Already clocked out.", "warning")
    elif attendance_status["record_id"]:
        try:
            result = attendance_collection.update_one({'_id':attendance_status["record_id"],'clock_out':None},{'$set':{'clock_out':datetime.now()}})
            if result.modified_count > 0: flash("Clocked out!", "success")
            else: flash("Already clocked out?", "warning")
        except Exception as e: print(f"Err clock-out {user_id} rec {attendance_status['record_id']}: {e}"); flash("Clock-out error.", "danger")
    else: flash("Cannot find clock-in record.", "danger")
    return redirect(url_for('dashboard'))

@app.route('/attendance')
@login_required
def view_attendance():
    if session.get('is_admin'): return redirect(url_for('admin_dashboard'))
    user=get_current_user();
    if not user: return redirect(url_for('login'))
    try: user_attendance = list(attendance_collection.find({'user_id':user['_id']}).sort('clock_in',-1))
    except Exception as e: print(f"Err fetch user att {user['_id']}: {e}"); flash("Error fetching attendance.", "danger"); user_attendance=[]
    return render_template('attendance.html', user=user, attendance_records=user_attendance)

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

# =========================
# === ADMIN PORTAL ROUTES ===
# =========================
@app.route('/admin')
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    """ Admin dashboard displaying key statistics. """
    user = get_current_user() # <<< GET THE CURRENT (ADMIN) USER
    if not user: # Should not happen due to decorator, but defensive check
        flash("Admin session invalid. Please log in again.", "warning")
        return redirect(url_for('login'))

    stats = {'user_count':'N/A', 'pending_leaves_count':'N/A', 'attendance_today':'N/A'}
    try:
        stats['user_count'] = users_collection.count_documents({})
        stats['pending_leaves_count'] = leaves_collection.count_documents({'status': 'Pending'})
        today_start=datetime.combine(date.today(),datetime.min.time()); today_end=datetime.combine(date.today(),datetime.max.time())
        stats['attendance_today'] = len(attendance_collection.distinct('user_id', {'clock_in':{'$gte':today_start,'$lt':today_end}}))
    except Exception as e: print(f"Err admin dashboard stats: {e}"); flash("Could not load stats.", "warning")

    # <<< PASS THE 'user' OBJECT TO THE TEMPLATE >>>
    return render_template('admin/dashboard.html', user=user, **stats)

@app.route('/admin/users')
@admin_required
def admin_manage_users():
    user = get_current_user() # Pass user to base template
    if not user: return redirect(url_for('login'))
    try: all_users = list(users_collection.find({}, {'password':0}).sort('username',1))
    except Exception as e: print(f"Err admin fetch users: {e}"); flash("Could not load users.", "danger"); all_users=[]
    return render_template('admin/users.html', user=user, users=all_users)

@app.route('/admin/leaves')
@admin_required
def admin_manage_leaves():
    user = get_current_user() # Pass user to base template
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
            {'_id':ObjectId(leave_id),'status':'Pending'},
            {'$set':{'status':new_status,'action_by':admin_username,'action_date':datetime.now()}},
            return_document=ReturnDocument.AFTER )
        if updated_leave: flash(f"Leave for {updated_leave.get('username','user')} {new_status.lower()}.", "success")
        else:
            existing = leaves_collection.find_one({'_id':ObjectId(leave_id)})
            if existing: flash(f"Leave already actioned (Status: {existing.get('status','?')}).", "warning")
            else: flash("Leave request not found.", "warning")
    except Exception as e: print(f"Err action leave {leave_id} ({action}) by {admin_username}: {e}"); flash("Error actioning leave.", "danger")
    status_filter=request.referrer.split('status=')[-1] if request.referrer and 'status=' in request.referrer else 'All'
    allowed_statuses=['All','Pending','Approved','Rejected']
    if status_filter not in allowed_statuses: status_filter='All'
    return redirect(url_for('admin_manage_leaves', status=status_filter))

@app.route('/admin/settings')
@admin_required
def admin_settings():
    """ Placeholder page for Admin Settings. """
    user = get_current_user() # Pass user to base template
    if not user: return redirect(url_for('login'))
    return render_template('admin/settings.html', user=user)

# --- Error Handling ---
@app.errorhandler(404)
def page_not_found(e): user = get_current_user(); return render_template('errors/404.html', user=user), 404 # Pass user if available
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
    print(f" * Database: mongodb://.../{db.name}") # Mask URI in logs
    print(f" * Listening on http://0.0.0.0:{port}")
    print("--- Press CTRL+C to quit ---")
    app.run(host='0.0.0.0', port=port, threaded=is_debug)