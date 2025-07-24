from flask import Flask, request, jsonify, send_file, send_from_directory
import sqlite3
import random
from datetime import datetime, timedelta
import jwt
import os
from io import BytesIO
import pandas as pd
import config
from auth import auth_service
import bcrypt
from services import dynamic_threshold
from database import db_manager

app = Flask(__name__)
SECRET_KEY = os.environ.get('SECRET_KEY', '777b4636344cab46bc634567d6e97565')

def init_db():
    db_manager.execute_commit("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            full_name TEXT NOT NULL,
            role TEXT DEFAULT 'technician' CHECK(role IN ('admin', 'technician', 'executive')),
            is_active INTEGER DEFAULT 1
        )
    """)
    db_manager.execute_commit("""
        CREATE TABLE IF NOT EXISTS sites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            address TEXT NOT NULL,
            status TEXT DEFAULT 'active' CHECK(status IN ('active', 'inactive'))
        )
    """)
    db_manager.execute_commit("""
        CREATE TABLE IF NOT EXISTS meters (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            site_id INTEGER NOT NULL,
            identifier TEXT NOT NULL,
            meter_type TEXT NOT NULL CHECK(meter_type IN ('electricity', 'water', 'gas')),
            status TEXT DEFAULT 'online' CHECK(status IN ('online', 'offline', 'maintenance', 'faulty'))
        )
    """)
    db_manager.execute_commit("""
        CREATE TABLE IF NOT EXISTS meter_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            meter_id INTEGER NOT NULL,
            timestamp TEXT NOT NULL,
            value REAL NOT NULL,
            FOREIGN KEY(meter_id) REFERENCES meters(id)
        )
    """)
    db_manager.execute_commit("""
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            technician_id INTEGER NOT NULL,
            site_id INTEGER NOT NULL,
            meter_id INTEGER,
            description TEXT NOT NULL,
            status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'completed')),
            assigned_date TEXT NOT NULL,
            due_date TEXT,
            FOREIGN KEY(technician_id) REFERENCES users(id),
            FOREIGN KEY(site_id) REFERENCES sites(id),
            FOREIGN KEY(meter_id) REFERENCES meters(id)
        )
    """)
    db_manager.execute_commit("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            target_type TEXT,
            target_id INTEGER,
            details TEXT,
            timestamp TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)
    db_manager.execute_commit("""
        CREATE TABLE IF NOT EXISTS thresholds (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            meter_id INTEGER NOT NULL UNIQUE,
            threshold_value REAL NOT NULL,
            last_updated TEXT NOT NULL,
            FOREIGN KEY(meter_id) REFERENCES meters(id)
        )
    """)
    # Add initial admin user if not exists
    cursor = db_manager.conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users WHERE role='admin'")
    if cursor.fetchone()[0] == 0:
        hashed_password = bcrypt.hashpw("admin_password".encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        db_manager.execute_commit(
            "INSERT INTO users (email, password, full_name, role) VALUES (?, ?, ?, ?)",
            ("admin@example.com", hashed_password, "Admin User", "admin")
        )
    cursor.close()

init_db()

def verify_token(token):
    if not token:
        return None
    try:
        # Remove 'Bearer ' prefix if present
        if token.startswith('Bearer '):
            token = token.split(' ')[1]
        decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return decoded['user_id']
    except jwt.ExpiredSignatureError:
        return None  # Token is expired
    except jwt.InvalidTokenError:
        return None  # Invalid token

def role_required(required_role):
    def decorator(f):
        def wrapper(*args, **kwargs):
            token = request.headers.get('Authorization')
            user_id = verify_token(token)
            if not user_id:
                return jsonify({'error': 'Unauthorized'}), 401
            
            decoded = jwt.decode(token.split(' ')[1], SECRET_KEY, algorithms=['HS256'])
            user_role = decoded.get('role')

            if user_role != required_role:
                return jsonify({'error': f'Access Denied: {user_role} role not allowed to perform this action.'}), 403
            return f(*args, **kwargs)
        wrapper.__name__ = f.__name__ # Preserve original function name
        return wrapper
    return decorator


# Login route
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if auth_service.login(email, password):
        user_id = auth_service.get_current_user_id()
        user_role = auth_service.get_current_user_role()
        token = jwt.encode({'user_id': user_id, 'role': user_role, 'exp': datetime.utcnow() + timedelta(hours=24)}, SECRET_KEY, algorithm='HS256')
        db_manager.log_audit(user_id, 'login', 'user', user_id, f'User {email} logged in.')
        return jsonify({'message': 'Login successful', 'token': token, 'role': user_role}), 200
    else:
        db_manager.log_audit(None, 'login_failed', 'user', None, f'Attempted login for {email} failed.')
        return jsonify({'error': 'Invalid credentials'}), 401

# --- User Management (Admin Only) ---
@app.route('/api/users', methods=['POST'])
@role_required('admin')
def add_user():
    token = request.headers.get('Authorization')
    acting_user_id = verify_token(token) # Get the ID of the admin performing the action

    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    full_name = data.get('full_name')
    role = data.get('role')

    if not all([email, password, full_name, role]):
        return jsonify({'error': 'Missing required fields'}), 400

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    try:
        user_id = db_manager.execute_commit(
            "INSERT INTO users (email, password, full_name, role) VALUES (?, ?, ?, ?)",
            (email, hashed_password, full_name, role)
        )
        db_manager.log_audit(acting_user_id, 'add_user', 'user', user_id, f'Added new user: {email} ({role}).')
        return jsonify({'message': 'User added successfully', 'id': user_id}), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': 'User with this email already exists'}), 409

@app.route('/api/users', methods=['GET'])
@role_required('admin')
def get_users():
    users = db_manager.query_all("SELECT id, email, full_name, role, is_active FROM users")
    return jsonify({'users': [dict(row) for row in users]})

@app.route('/api/users/<int:user_id>', methods=['PUT'])
@role_required('admin')
def update_user(user_id):
    token = request.headers.get('Authorization')
    acting_user_id = verify_token(token)
    
    data = request.get_json()
    email = data.get('email')
    full_name = data.get('full_name')
    role = data.get('role')
    is_active = data.get('is_active') # This will be boolean or 0/1

    update_fields = []
    params = []
    details_log = []

    if email:
        update_fields.append("email = ?")
        params.append(email)
        details_log.append(f"email changed to {email}")
    if full_name:
        update_fields.append("full_name = ?")
        params.append(full_name)
        details_log.append(f"full_name changed to {full_name}")
    if role:
        update_fields.append("role = ?")
        params.append(role)
        details_log.append(f"role changed to {role}")
    if is_active is not None:
        update_fields.append("is_active = ?")
        params.append(1 if is_active else 0)
        details_log.append(f"is_active changed to {is_active}")

    if not update_fields:
        return jsonify({'error': 'No fields to update'}), 400

    query = f"UPDATE users SET {', '.join(update_fields)} WHERE id = ?"
    params.append(user_id)

    result = db_manager.execute_commit(query, params)
    if result > 0:
        db_manager.log_audit(acting_user_id, 'update_user', 'user', user_id, f'Updated user: {", ".join(details_log)}.')
        return jsonify({'message': 'User updated successfully'}), 200
    return jsonify({'error': 'User not found'}), 404

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@role_required('admin')
def delete_user(user_id):
    token = request.headers.get('Authorization')
    acting_user_id = verify_token(token)

    # Prevent deleting the current admin user if that's the only admin
    if acting_user_id == user_id:
        # Check if there are other admins
        admin_count = db_manager.query_one("SELECT COUNT(*) FROM users WHERE role = 'admin' AND id != ?", (user_id,))[0]
        if admin_count == 0:
            return jsonify({'error': 'Cannot delete the only admin user'}), 400

    result = db_manager.execute_commit("DELETE FROM users WHERE id = ?", (user_id,))
    if result > 0:
        db_manager.log_audit(acting_user_id, 'delete_user', 'user', user_id, f'Deleted user ID: {user_id}.')
        return jsonify({'message': 'User deleted successfully'}), 200
    return jsonify({'error': 'User not found'}), 404

# --- Site Management (Admin Only) ---
@app.route('/api/sites', methods=['POST'])
@role_required('admin')
def add_site():
    token = request.headers.get('Authorization')
    user_id = verify_token(token)

    data = request.get_json()
    name = data.get('name')
    address = data.get('address')
    status = data.get('status', 'active') # Default status

    if not all([name, address]):
        return jsonify({'error': 'Missing required fields: name and address'}), 400

    try:
        site_id = db_manager.execute_commit(
            "INSERT INTO sites (name, address, status) VALUES (?, ?, ?)",
            (name, address, status)
        )
        db_manager.log_audit(user_id, 'add_site', 'site', site_id, f'Added new site: {name}.')
        return jsonify({'message': 'Site added successfully', 'id': site_id}), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Site with this name already exists'}), 409

@app.route('/api/sites', methods=['GET'])
def get_sites():
    token = request.headers.get('Authorization')
    user_id = verify_token(token)
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401
    
    decoded = jwt.decode(token.split(' ')[1], SECRET_KEY, algorithms=['HS256'])
    role = decoded['role']

    if role == 'admin' or role == 'executive':
        sites = db_manager.query_all("SELECT id, name, address, status FROM sites")
    else: # technician
        # Assuming technicians only view sites they have tasks assigned to
        # This might need refinement based on your exact business logic
        query = """
            SELECT DISTINCT s.id, s.name, s.address, s.status
            FROM sites s
            JOIN tasks t ON s.id = t.site_id
            WHERE t.technician_id = ?
        """
        sites = db_manager.query_all(query, (user_id,))

    return jsonify({'sites': [dict(row) for row in sites]})

@app.route('/api/sites/<int:site_id>', methods=['PUT'])
@role_required('admin')
def update_site(site_id):
    token = request.headers.get('Authorization')
    user_id = verify_token(token)

    data = request.get_json()
    name = data.get('name')
    address = data.get('address')
    status = data.get('status')

    update_fields = []
    params = []
    details_log = []

    if name:
        update_fields.append("name = ?")
        params.append(name)
        details_log.append(f"name changed to {name}")
    if address:
        update_fields.append("address = ?")
        params.append(address)
        details_log.append(f"address changed to {address}")
    if status:
        update_fields.append("status = ?")
        params.append(status)
        details_log.append(f"status changed to {status}")

    if not update_fields:
        return jsonify({'error': 'No fields to update'}), 400

    query = f"UPDATE sites SET {', '.join(update_fields)} WHERE id = ?"
    params.append(site_id)

    result = db_manager.execute_commit(query, params)
    if result > 0:
        db_manager.log_audit(user_id, 'update_site', 'site', site_id, f'Updated site ID {site_id}: {", ".join(details_log)}.')
        return jsonify({'message': 'Site updated successfully'}), 200
    return jsonify({'error': 'Site not found'}), 404

@app.route('/api/sites/<int:site_id>', methods=['DELETE'])
@role_required('admin')
def delete_site(site_id):
    token = request.headers.get('Authorization')
    user_id = verify_token(token)

    result = db_manager.execute_commit("DELETE FROM sites WHERE id = ?", (site_id,))
    if result > 0:
        db_manager.log_audit(user_id, 'delete_site', 'site', site_id, f'Deleted site ID: {site_id}.')
        return jsonify({'message': 'Site deleted successfully'}), 200
    return jsonify({'error': 'Site not found'}), 404

# --- Meter Management (Admin Only) ---
@app.route('/api/meters', methods=['POST'])
@role_required('admin')
def add_meter():
    token = request.headers.get('Authorization')
    user_id = verify_token(token)

    data = request.get_json()
    site_id = data.get('site_id')
    identifier = data.get('identifier')
    meter_type = data.get('meter_type')
    status = data.get('status', 'online') # Default status

    if not all([site_id, identifier, meter_type]):
        return jsonify({'error': 'Missing required fields: site_id, identifier, meter_type'}), 400
    
    # Check if site_id exists
    site_exists = db_manager.query_one("SELECT id FROM sites WHERE id = ?", (site_id,))
    if not site_exists:
        return jsonify({'error': 'Site ID does not exist'}), 400

    try:
        meter_id = db_manager.execute_commit(
            "INSERT INTO meters (site_id, identifier, meter_type, status) VALUES (?, ?, ?, ?)",
            (site_id, identifier, meter_type, status)
        )
        db_manager.log_audit(user_id, 'add_meter', 'meter', meter_id, f'Added new meter: {identifier} at site {site_id}.')
        return jsonify({'message': 'Meter added successfully', 'id': meter_id}), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Meter identifier already exists for this site'}), 409 # More specific error if unique constraint is (site_id, identifier)

@app.route('/api/meters', methods=['GET'])
def get_meters():
    token = request.headers.get('Authorization')
    user_id = verify_token(token)
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401

    decoded = jwt.decode(token.split(' ')[1], SECRET_KEY, algorithms=['HS256'])
    role = decoded['role']

    query = """
        SELECT m.id, m.site_id, s.name AS site_name, m.identifier, m.meter_type, m.status
        FROM meters m
        JOIN sites s ON m.site_id = s.id
    """
    params = ()

    if role == 'technician':
        query += """
            JOIN tasks t ON m.id = t.meter_id
            WHERE t.technician_id = ?
            GROUP BY m.id
        """
        params = (user_id,)
    elif role == 'executive':
        # Executives can see all meters
        pass # No WHERE clause needed for executive

    meters = db_manager.query_all(query, params)
    return jsonify({'meters': [dict(row) for row in meters]})


@app.route('/api/meters/<int:meter_id>', methods=['PUT'])
@role_required('admin')
def update_meter(meter_id):
    token = request.headers.get('Authorization')
    user_id = verify_token(token)

    data = request.get_json()
    site_id = data.get('site_id')
    identifier = data.get('identifier')
    meter_type = data.get('meter_type')
    status = data.get('status')

    update_fields = []
    params = []
    details_log = []

    if site_id:
        update_fields.append("site_id = ?")
        params.append(site_id)
        details_log.append(f"site_id changed to {site_id}")
    if identifier:
        update_fields.append("identifier = ?")
        params.append(identifier)
        details_log.append(f"identifier changed to {identifier}")
    if meter_type:
        update_fields.append("meter_type = ?")
        params.append(meter_type)
        details_log.append(f"meter_type changed to {meter_type}")
    if status:
        update_fields.append("status = ?")
        params.append(status)
        details_log.append(f"status changed to {status}")

    if not update_fields:
        return jsonify({'error': 'No fields to update'}), 400

    query = f"UPDATE meters SET {', '.join(update_fields)} WHERE id = ?"
    params.append(meter_id)

    result = db_manager.execute_commit(query, params)
    if result > 0:
        db_manager.log_audit(user_id, 'update_meter', 'meter', meter_id, f'Updated meter ID {meter_id}: {", ".join(details_log)}.')
        return jsonify({'message': 'Meter updated successfully'}), 200
    return jsonify({'error': 'Meter not found'}), 404

@app.route('/api/meters/<int:meter_id>', methods=['DELETE'])
@role_required('admin')
def delete_meter(meter_id):
    token = request.headers.get('Authorization')
    user_id = verify_token(token)

    result = db_manager.execute_commit("DELETE FROM meters WHERE id = ?", (meter_id,))
    if result > 0:
        db_manager.log_audit(user_id, 'delete_meter', 'meter', meter_id, f'Deleted meter ID: {meter_id}.')
        return jsonify({'message': 'Meter deleted successfully'}), 200
    return jsonify({'error': 'Meter not found'}), 404


# --- Meter Data (Admin, Executive, Technician) ---
@app.route('/api/meter_data', methods=['POST'])
@role_required('admin')
def add_meter_data():
    token = request.headers.get('Authorization')
    user_id = verify_token(token)

    data = request.get_json()
    meter_id = data.get('meter_id')
    timestamp_str = data.get('timestamp')
    value = data.get('value')

    if not all([meter_id, timestamp_str, value is not None]):
        return jsonify({'error': 'Missing required fields: meter_id, timestamp, value'}), 400
    
    # Validate timestamp format
    try:
        timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
    except ValueError:
        return jsonify({'error': 'Invalid timestamp format. Use YYYY-MM-DD HH:MM:SS'}), 400

    # Check if meter_id exists
    meter_exists = db_manager.query_one("SELECT id FROM meters WHERE id = ?", (meter_id,))
    if not meter_exists:
        return jsonify({'error': 'Meter ID does not exist'}), 400

    data_id = db_manager.execute_commit(
        "INSERT INTO meter_data (meter_id, timestamp, value) VALUES (?, ?, ?)",
        (meter_id, timestamp.strftime('%Y-%m-%d %H:%M:%S'), value)
    )
    db_manager.log_audit(user_id, 'add_meter_data', 'meter_data', data_id, f'Added data for meter {meter_id}.')

    # Optional: Check for anomalies and update thresholds after new data is added
    meter_type = db_manager.query_one("SELECT meter_type FROM meters WHERE id = ?", (meter_id,))[0]
    historical_data = [row[0] for row in db_manager.query_all(
        "SELECT value FROM meter_data WHERE meter_id = ? ORDER BY timestamp DESC LIMIT 100", (meter_id,)
    )]
    new_threshold = dynamic_threshold(meter_type, historical_data)

    db_manager.execute_commit(
        "INSERT OR REPLACE INTO thresholds (meter_id, threshold_value, last_updated) VALUES (?, ?, ?)",
        (meter_id, new_threshold, datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'))
    )

    return jsonify({'message': 'Meter data added successfully', 'id': data_id}), 201

@app.route('/api/meter_data/<int:meter_id>', methods=['GET'])
def get_meter_data(meter_id):
    token = request.headers.get('Authorization')
    user_id = verify_token(token)
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401
    
    decoded = jwt.decode(token.split(' ')[1], SECRET_KEY, algorithms=['HS256'])
    role = decoded['role']

    # For technicians, ensure they only see data for meters they are assigned tasks for
    if role == 'technician':
        is_assigned = db_manager.query_one("""
            SELECT COUNT(*) FROM tasks WHERE technician_id = ? AND meter_id = ?
        """, (user_id, meter_id,))[0]
        if not is_assigned:
            return jsonify({'error': 'Access Denied: Not assigned to this meter'}), 403

    meter_data = db_manager.query_all(
        "SELECT timestamp, value FROM meter_data WHERE meter_id = ? ORDER BY timestamp ASC",
        (meter_id,)
    )
    return jsonify({'meter_data': [dict(row) for row in meter_data]})

# Endpoint to get the current threshold for a meter
@app.route('/api/thresholds/<int:meter_id>', methods=['GET'])
def get_threshold(meter_id):
    token = request.headers.get('Authorization')
    user_id = verify_token(token)
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401

    decoded = jwt.decode(token.split(' ')[1], SECRET_KEY, algorithms=['HS256'])
    role = decoded['role']

    # Technician access check
    if role == 'technician':
        is_assigned = db_manager.query_one("""
            SELECT COUNT(*) FROM tasks WHERE technician_id = ? AND meter_id = ?
        """, (user_id, meter_id,))[0]
        if not is_assigned:
            return jsonify({'error': 'Access Denied: Not assigned to this meter'}), 403

    threshold = db_manager.query_one(
        "SELECT threshold_value, last_updated FROM thresholds WHERE meter_id = ?", (meter_id,)
    )
    if threshold:
        return jsonify({'threshold': dict(threshold)}), 200
    return jsonify({'error': 'Threshold not found for this meter'}), 404

# --- Task Management (Admin and Technician) ---
@app.route('/api/tasks', methods=['POST'])
@role_required('admin')
def add_task():
    token = request.headers.get('Authorization')
    user_id = verify_token(token)

    data = request.get_json()
    technician_id = data.get('technician_id')
    site_id = data.get('site_id')
    meter_id = data.get('meter_id')
    description = data.get('description')
    assigned_date_str = data.get('assigned_date', datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'))
    due_date_str = data.get('due_date')

    if not all([technician_id, site_id, description]):
        return jsonify({'error': 'Missing required fields: technician_id, site_id, description'}), 400
    
    # Validate technician_id, site_id, meter_id
    technician_exists = db_manager.query_one("SELECT id FROM users WHERE id = ? AND role = 'technician'", (technician_id,))
    if not technician_exists:
        return jsonify({'error': 'Invalid Technician ID'}), 400
    site_exists = db_manager.query_one("SELECT id FROM sites WHERE id = ?", (site_id,))
    if not site_exists:
        return jsonify({'error': 'Invalid Site ID'}), 400
    if meter_id:
        meter_exists = db_manager.query_one("SELECT id FROM meters WHERE id = ? AND site_id = ?", (meter_id, site_id))
        if not meter_exists:
            return jsonify({'error': 'Invalid Meter ID or Meter not at specified Site'}), 400

    # Convert dates
    try:
        assigned_date = datetime.strptime(assigned_date_str, '%Y-%m-%d %H:%M:%S')
        due_date = datetime.strptime(due_date_str, '%Y-%m-%d %H:%M:%S') if due_date_str else None
    except ValueError:
        return jsonify({'error': 'Invalid date format. Use YYYY-MM-DD HH:MM:SS'}), 400

    task_id = db_manager.execute_commit(
        "INSERT INTO tasks (technician_id, site_id, meter_id, description, assigned_date, due_date) VALUES (?, ?, ?, ?, ?, ?)",
        (technician_id, site_id, meter_id, description, assigned_date.strftime('%Y-%m-%d %H:%M:%S'), due_date.strftime('%Y-%m-%d %H:%M:%S') if due_date else None)
    )
    db_manager.log_audit(user_id, 'add_task', 'task', task_id, f'Assigned task {task_id} to technician {technician_id}.')
    return jsonify({'message': 'Task added successfully', 'id': task_id}), 201

@app.route('/api/tasks', methods=['GET'])
def get_tasks():
    token = request.headers.get('Authorization')
    user_id = verify_token(token)
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401

    decoded = jwt.decode(token.split(' ')[1], SECRET_KEY, algorithms=['HS256'])
    role = decoded['role']

    query = """
        SELECT
            t.id,
            t.description,
            t.status,
            t.assigned_date,
            t.due_date,
            u.full_name AS technician_name,
            s.name AS site_name,
            m.identifier AS meter_identifier
        FROM tasks t
        JOIN users u ON t.technician_id = u.id
        JOIN sites s ON t.site_id = s.id
        LEFT JOIN meters m ON t.meter_id = m.id
    """
    params = ()
    
    if role == 'technician':
        query += " WHERE t.technician_id = ?"
        params = (user_id,)

    query += " ORDER BY t.due_date DESC"

    tasks = [dict(row) for row in db_manager.query_all(query, params)]
    
    return jsonify({'tasks': tasks})

@app.route('/api/tasks/<int:task_id>', methods=['PUT'])
def update_task(task_id):
    token = request.headers.get('Authorization')
    user_id = verify_token(token)
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401
        
    data = request.get_json()
    status = data.get('status')
    
    decoded = jwt.decode(token.split(' ')[1], SECRET_KEY, algorithms=['HS256'])
    role = decoded['role']

    if role == 'admin':
        # Admin can update any task
        result = db_manager.execute_commit(
            "UPDATE tasks SET status=? WHERE id=?", 
            (status, task_id)
        )
    else: # technician
        # Technician can only update their own tasks' status
        if status and status not in ['pending', 'completed']: # Technicians typically only change status to these
             return jsonify({'error': 'Invalid status for technician'}), 400
        
        result = db_manager.execute_commit(
            " The user wants an updated backend.py, but from the conversation, they've already been given the full updated version in the previous response.

The tools are for code execution, browsing, searching, etc., but since the request is for the updated file, and I have it from the documents, I can just provide it briefly.

The instruction is to respond briefly.

No need for tools here, as the content is already available.from flask import Flask, request, jsonify, send_file, send_from_directory
import sqlite3
import random
from datetime import datetime, timedelta
import jwt
import os
from io import BytesIO
import pandas as pd
import config
from auth import auth_service
import bcrypt
from services import dynamic_threshold
from database import db_manager

app = Flask(__name__)
SECRET_KEY = os.environ.get('SECRET_KEY', '777b4636344cab46bc634567d6e97565')

def init_db():
    db_manager.execute_commit("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            full_name TEXT NOT NULL,
            role TEXT DEFAULT 'technician' CHECK(role IN ('admin', 'technician', 'executive')),
            is_active INTEGER DEFAULT 1
        )
    """)
    db_manager.execute_commit("""
        CREATE TABLE IF NOT EXISTS sites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            address TEXT NOT NULL,
            status TEXT DEFAULT 'active' CHECK(status IN ('active', 'inactive'))
        )
    """)
    db_manager.execute_commit("""
        CREATE TABLE IF NOT EXISTS meters (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            site_id INTEGER NOT NULL,
            identifier TEXT NOT NULL,
            meter_type TEXT NOT NULL CHECK(meter_type IN ('electricity', 'water', 'gas')),
            status TEXT DEFAULT 'online' CHECK(status IN ('online', 'offline', 'maintenance', 'faulty'))
        )
    """)
    db_manager.execute_commit("""
        CREATE TABLE IF NOT EXISTS meter_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            meter_id INTEGER NOT NULL,
            timestamp TEXT NOT NULL,
            value REAL NOT NULL,
            FOREIGN KEY(meter_id) REFERENCES meters(id)
        )
    """)
    db_manager.execute_commit("""
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            technician_id INTEGER NOT NULL,
            site_id INTEGER NOT NULL,
            meter_id INTEGER,
            description TEXT NOT NULL,
            status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'completed')),
            assigned_date TEXT NOT NULL,
            due_date TEXT,
            FOREIGN KEY(technician_id) REFERENCES users(id),
            FOREIGN KEY(site_id) REFERENCES sites(id),
            FOREIGN KEY(meter_id) REFERENCES meters(id)
        )
    """)
    db_manager.execute_commit("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            target_type TEXT,
            target_id INTEGER,
            details TEXT,
            timestamp TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)
    db_manager.execute_commit("""
        CREATE TABLE IF NOT EXISTS thresholds (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            meter_id INTEGER NOT NULL UNIQUE,
            threshold_value REAL NOT NULL,
            last_updated TEXT NOT NULL,
            FOREIGN KEY(meter_id) REFERENCES meters(id)
        )
    """)
    # Add initial admin user if not exists
    cursor = db_manager.conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users WHERE role='admin'")
    if cursor.fetchone()[0] == 0:
        hashed_password = bcrypt.hashpw("admin_password".encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        db_manager.execute_commit(
            "INSERT INTO users (email, password, full_name, role) VALUES (?, ?, ?, ?)",
            ("admin@example.com", hashed_password, "Admin User", "admin")
        )
    cursor.close()

init_db()

def verify_token(token):
    if not token:
        return None
    try:
        # Remove 'Bearer ' prefix if present
        if token.startswith('Bearer '):
            token = token.split(' ')[1]
        decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return decoded['user_id']
    except jwt.ExpiredSignatureError:
        return None  # Token is expired
    except jwt.InvalidTokenError:
        return None  # Invalid token

def role_required(required_role):
    def decorator(f):
        def wrapper(*args, **kwargs):
            token = request.headers.get('Authorization')
            user_id = verify_token(token)
            if not user_id:
                return jsonify({'error': 'Unauthorized'}), 401
            
            decoded = jwt.decode(token.split(' ')[1], SECRET_KEY, algorithms=['HS256'])
            user_role = decoded.get('role')

            if user_role != required_role:
                return jsonify({'error': f'Access Denied: {user_role} role not allowed to perform this action.'}), 403
            return f(*args, **kwargs)
        wrapper.__name__ = f.__name__ # Preserve original function name
        return wrapper
    return decorator


# Login route
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if auth_service.login(email, password):
        user_id = auth_service.get_current_user_id()
        user_role = auth_service.get_current_user_role()
        token = jwt.encode({'user_id': user_id, 'role': user_role, 'exp': datetime.utcnow() + timedelta(hours=24)}, SECRET_KEY, algorithm='HS256')
        db_manager.log_audit(user_id, 'login', 'user', user_id, f'User {email} logged in.')
        return jsonify({'message': 'Login successful', 'token': token, 'role': user_role}), 200
    else:
        db_manager.log_audit(None, 'login_failed', 'user', None, f'Attempted login for {email} failed.')
        return jsonify({'error': 'Invalid credentials'}), 401

# --- User Management (Admin Only) ---
@app.route('/api/users', methods=['POST'])
@role_required('admin')
def add_user():
    token = request.headers.get('Authorization')
    acting_user_id = verify_token(token) # Get the ID of the admin performing the action

    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    full_name = data.get('full_name')
    role = data.get('role')

    if not all([email, password, full_name, role]):
        return jsonify({'error': 'Missing required fields'}), 400

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    try:
        user_id = db_manager.execute_commit(
            "INSERT INTO users (email, password, full_name, role) VALUES (?, ?, ?, ?)",
            (email, hashed_password, full_name, role)
        )
        db_manager.log_audit(acting_user_id, 'add_user', 'user', user_id, f'Added new user: {email} ({role}).')
        return jsonify({'message': 'User added successfully', 'id': user_id}), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': 'User with this email already exists'}), 409

@app.route('/api/users', methods=['GET'])
@role_required('admin')
def get_users():
    users = db_manager.query_all("SELECT id, email, full_name, role, is_active FROM users")
    return jsonify({'users': [dict(row) for row in users]})

@app.route('/api/users/<int:user_id>', methods=['PUT'])
@role_required('admin')
def update_user(user_id):
    token = request.headers.get('Authorization')
    acting_user_id = verify_token(token)
    
    data = request.get_json()
    email = data.get('email')
    full_name = data.get('full_name')
    role = data.get('role')
    is_active = data.get('is_active') # This will be boolean or 0/1

    update_fields = []
    params = []
    details_log = []

    if email:
        update_fields.append("email = ?")
        params.append(email)
        details_log.append(f"email changed to {email}")
    if full_name:
        update_fields.append("full_name = ?")
        params.append(full_name)
        details_log.append(f"full_name changed to {full_name}")
    if role:
        update_fields.append("role = ?")
        params.append(role)
        details_log.append(f"role changed to {role}")
    if is_active is not None:
        update_fields.append("is_active = ?")
        params.append(1 if is_active else 0)
        details_log.append(f"is_active changed to {is_active}")

    if not update_fields:
        return jsonify({'error': 'No fields to update'}), 400

    query = f"UPDATE users SET {', '.join(update_fields)} WHERE id = ?"
    params.append(user_id)

    result = db_manager.execute_commit(query, params)
    if result > 0:
        db_manager.log_audit(acting_user_id, 'update_user', 'user', user_id, f'Updated user: {", ".join(details_log)}.')
        return jsonify({'message': 'User updated successfully'}), 200
    return jsonify({'error': 'User not found'}), 404

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@role_required('admin')
def delete_user(user_id):
    token = request.headers.get('Authorization')
    acting_user_id = verify_token(token)

    # Prevent deleting the current admin user if that's the only admin
    if acting_user_id == user_id:
        # Check if there are other admins
        admin_count = db_manager.query_one("SELECT COUNT(*) FROM users WHERE role = 'admin' AND id != ?", (user_id,))[0]
        if admin_count == 0:
            return jsonify({'error': 'Cannot delete the only admin user'}), 400

    result = db_manager.execute_commit("DELETE FROM users WHERE id = ?", (user_id,))
    if result > 0:
        db_manager.log_audit(acting_user_id, 'delete_user', 'user', user_id, f'Deleted user ID: {user_id}.')
        return jsonify({'message': 'User deleted successfully'}), 200
    return jsonify({'error': 'User not found'}), 404

# --- Site Management (Admin Only) ---
@app.route('/api/sites', methods=['POST'])
@role_required('admin')
def add_site():
    token = request.headers.get('Authorization')
    user_id = verify_token(token)

    data = request.get_json()
    name = data.get('name')
    address = data.get('address')
    status = data.get('status', 'active') # Default status

    if not all([name, address]):
        return jsonify({'error': 'Missing required fields: name and address'}), 400

    try:
        site_id = db_manager.execute_commit(
            "INSERT INTO sites (name, address, status) VALUES (?, ?, ?)",
            (name, address, status)
        )
        db_manager.log_audit(user_id, 'add_site', 'site', site_id, f'Added new site: {name}.')
        return jsonify({'message': 'Site added successfully', 'id': site_id}), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Site with this name already exists'}), 409

@app.route('/api/sites', methods=['GET'])
def get_sites():
    token = request.headers.get('Authorization')
    user_id = verify_token(token)
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401
    
    decoded = jwt.decode(token.split(' ')[1], SECRET_KEY, algorithms=['HS256'])
    role = decoded['role']

    if role == 'admin' or role == 'executive':
        sites = db_manager.query_all("SELECT id, name, address, status FROM sites")
    else: # technician
        # Assuming technicians only view sites they have tasks assigned to
        # This might need refinement based on your exact business logic
        query = """
            SELECT DISTINCT s.id, s.name, s.address, s.status
            FROM sites s
            JOIN tasks t ON s.id = t.site_id
            WHERE t.technician_id = ?
        """
        sites = db_manager.query_all(query, (user_id,))

    return jsonify({'sites': [dict(row) for row in sites]})

@app.route('/api/sites/<int:site_id>', methods=['PUT'])
@role_required('admin')
def update_site(site_id):
    token = request.headers.get('Authorization')
    user_id = verify_token(token)

    data = request.get_json()
    name = data.get('name')
    address = data.get('address')
    status = data.get('status')

    update_fields = []
    params = []
    details_log = []

    if name:
        update_fields.append("name = ?")
        params.append(name)
        details_log.append(f"name changed to {name}")
    if address:
        update_fields.append("address = ?")
        params.append(address)
        details_log.append(f"address changed to {address}")
    if status:
        update_fields.append("status = ?")
        params.append(status)
        details_log.append(f"status changed to {status}")

    if not update_fields:
        return jsonify({'error': 'No fields to update'}), 400

    query = f"UPDATE sites SET {', '.join(update_fields)} WHERE id = ?"
    params.append(site_id)

    result = db_manager.execute_commit(query, params)
    if result > 0:
        db_manager.log_audit(user_id, 'update_site', 'site', site_id, f'Updated site ID {site_id}: {", ".join(details_log)}.')
        return jsonify({'message': 'Site updated successfully'}), 200
    return jsonify({'error': 'Site not found'}), 404

@app.route('/api/sites/<int:site_id>', methods=['DELETE'])
@role_required('admin')
def delete_site(site_id):
    token = request.headers.get('Authorization')
    user_id = verify_token(token)

    result = db_manager.execute_commit("DELETE FROM sites WHERE id = ?", (site_id,))
    if result > 0:
        db_manager.log_audit(user_id, 'delete_site', 'site', site_id, f'Deleted site ID: {site_id}.')
        return jsonify({'message': 'Site deleted successfully'}), 200
    return jsonify({'error': 'Site not found'}), 404

# --- Meter Management (Admin Only) ---
@app.route('/api/meters', methods=['POST'])
@role_required('admin')
def add_meter():
    token = request.headers.get('Authorization')
    user_id = verify_token(token)

    data = request.get_json()
    site_id = data.get('site_id')
    identifier = data.get('identifier')
    meter_type = data.get('meter_type')
    status = data.get('status', 'online') # Default status

    if not all([site_id, identifier, meter_type]):
        return jsonify({'error': 'Missing required fields: site_id, identifier, meter_type'}), 400
    
    # Check if site_id exists
    site_exists = db_manager.query_one("SELECT id FROM sites WHERE id = ?", (site_id,))
    if not site_exists:
        return jsonify({'error': 'Site ID does not exist'}), 400

    try:
        meter_id = db_manager.execute_commit(
            "INSERT INTO meters (site_id, identifier, meter_type, status) VALUES (?, ?, ?, ?)",
            (site_id, identifier, meter_type, status)
        )
        db_manager.log_audit(user_id, 'add_meter', 'meter', meter_id, f'Added new meter: {identifier} at site {site_id}.')
        return jsonify({'message': 'Meter added successfully', 'id': meter_id}), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Meter identifier already exists for this site'}), 409 # More specific error if unique constraint is (site_id, identifier)

@app.route('/api/meters', methods=['GET'])
def get_meters():
    token = request.headers.get('Authorization')
    user_id = verify_token(token)
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401

    decoded = jwt.decode(token.split(' ')[1], SECRET_KEY, algorithms=['HS256'])
    role = decoded['role']

    query = """
        SELECT m.id, m.site_id, s.name AS site_name, m.identifier, m.meter_type, m.status
        FROM meters m
        JOIN sites s ON m.site_id = s.id
    """
    params = ()

    if role == 'technician':
        query += """
            JOIN tasks t ON m.id = t.meter_id
            WHERE t.technician_id = ?
            GROUP BY m.id
        """
        params = (user_id,)
    elif role == 'executive':
        # Executives can see all meters
        pass # No WHERE clause needed for executive

    meters = db_manager.query_all(query, params)
    return jsonify({'meters': [dict(row) for row in meters]})


@app.route('/api/meters/<int:meter_id>', methods=['PUT'])
@role_required('admin')
def update_meter(meter_id):
    token = request.headers.get('Authorization')
    user_id = verify_token(token)

    data = request.get_json()
    site_id = data.get('site_id')
    identifier = data.get('identifier')
    meter_type = data.get('meter_type')
    status = data.get('status')

    update_fields = []
    params = []
    details_log = []

    if site_id:
        update_fields.append("site_id = ?")
        params.append(site_id)
        details_log.append(f"site_id changed to {site_id}")
    if identifier:
        update_fields.append("identifier = ?")
        params.append(identifier)
        details_log.append(f"identifier changed to {identifier}")
    if meter_type:
        update_fields.append("meter_type = ?")
        params.append(meter_type)
        details_log.append(f"meter_type changed to {meter_type}")
    if status:
        update_fields.append("status = ?")
        params.append(status)
        details_log.append(f"status changed to {status}")

    if not update_fields:
        return jsonify({'error': 'No fields to update'}), 400

    query = f"UPDATE meters SET {', '.join(update_fields)} WHERE id = ?"
    params.append(meter_id)

    result = db_manager.execute_commit(query, params)
    if result > 0:
        db_manager.log_audit(user_id, 'update_meter', 'meter', meter_id, f'Updated meter ID {meter_id}: {", ".join(details_log)}.')
        return jsonify({'message': 'Meter updated successfully'}), 200
    return jsonify({'error': 'Meter not found'}), 404

@app.route('/api/meters/<int:meter_id>', methods=['DELETE'])
@role_required('admin')
def delete_meter(meter_id):
    token = request.headers.get('Authorization')
    user_id = verify_token(token)

    result = db_manager.execute_commit("DELETE FROM meters WHERE id = ?", (meter_id,))
    if result > 0:
        db_manager.log_audit(user_id, 'delete_meter', 'meter', meter_id, f'Deleted meter ID: {meter_id}.')
        return jsonify({'message': 'Meter deleted successfully'}), 200
    return jsonify({'error': 'Meter not found'}), 404


# --- Meter Data (Admin, Executive, Technician) ---
@app.route('/api/meter_data', methods=['POST'])
@role_required('admin')
def add_meter_data():
    token = request.headers.get('Authorization')
    user_id = verify_token(token)

    data = request.get_json()
    meter_id = data.get('meter_id')
    timestamp_str = data.get('timestamp')
    value = data.get('value')

    if not all([meter_id, timestamp_str, value is not None]):
        return jsonify({'error': 'Missing required fields: meter_id, timestamp, value'}), 400
    
    # Validate timestamp format
    try:
        timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
    except ValueError:
        return jsonify({'error': 'Invalid timestamp format. Use YYYY-MM-DD HH:MM:SS'}), 400

    # Check if meter_id exists
    meter_exists = db_manager.query_one("SELECT id FROM meters WHERE id = ?", (meter_id,))
    if not meter_exists:
        return jsonify({'error': 'Meter ID does not exist'}), 400

    data_id = db_manager.execute_commit(
        "INSERT INTO meter_data (meter_id, timestamp, value) VALUES (?, ?, ?)",
        (meter_id, timestamp.strftime('%Y-%m-%d %H:%M:%S'), value)
    )
    db_manager.log_audit(user_id, 'add_meter_data', 'meter_data', data_id, f'Added data for meter {meter_id}.')

    # Optional: Check for anomalies and update thresholds after new data is added
    meter_type = db_manager.query_one("SELECT meter_type FROM meters WHERE id = ?", (meter_id,))[0]
    historical_data = [row[0] for row in db_manager.query_all(
        "SELECT value FROM meter_data WHERE meter_id = ? ORDER BY timestamp DESC LIMIT 100", (meter_id,)
    )]
    new_threshold = dynamic_threshold(meter_type, historical_data)

    db_manager.execute_commit(
        "INSERT OR REPLACE INTO thresholds (meter_id, threshold_value, last_updated) VALUES (?, ?, ?)",
        (meter_id, new_threshold, datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'))
    )

    return jsonify({'message': 'Meter data added successfully', 'id': data_id}), 201

@app.route('/api/meter_data/<int:meter_id>', methods=['GET'])
def get_meter_data(meter_id):
    token = request.headers.get('Authorization')
    user_id = verify_token(token)
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401
    
    decoded = jwt.decode(token.split(' ')[1], SECRET_KEY, algorithms=['HS256'])
    role = decoded['role']

    # For technicians, ensure they only see data for meters they are assigned tasks for
    if role == 'technician':
        is_assigned = db_manager.query_one("""
            SELECT COUNT(*) FROM tasks WHERE technician_id = ? AND meter_id = ?
        """, (user_id, meter_id,))[0]
        if not is_assigned:
            return jsonify({'error': 'Access Denied: Not assigned to this meter'}), 403

    meter_data = db_manager.query_all(
        "SELECT timestamp, value FROM meter_data WHERE meter_id = ? ORDER BY timestamp ASC",
        (meter_id,)
    )
    return jsonify({'meter_data': [dict(row) for row in meter_data]})

# Endpoint to get the current threshold for a meter
@app.route('/api/thresholds/<int:meter_id>', methods=['GET'])
def get_threshold(meter_id):
    token = request.headers.get('Authorization')
    user_id = verify_token(token)
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401

    decoded = jwt.decode(token.split(' ')[1], SECRET_KEY, algorithms=['HS256'])
    role = decoded['role']

    # Technician access check
    if role == 'technician':
        is_assigned = db_manager.query_one("""
            SELECT COUNT(*) FROM tasks WHERE technician_id = ? AND meter_id = ?
        """, (user_id, meter_id,))[0]
        if not is_assigned:
            return jsonify({'error': 'Access Denied: Not assigned to this meter'}), 403

    threshold = db_manager.query_one(
        "SELECT threshold_value, last_updated FROM thresholds WHERE meter_id = ?", (meter_id,)
    )
    if threshold:
        return jsonify({'threshold': dict(threshold)}), 200
    return jsonify({'error': 'Threshold not found for this meter'}), 404

# --- Task Management (Admin and Technician) ---
@app.route('/api/tasks', methods=['POST'])
@role_required('admin')
def add_task():
    token = request.headers.get('Authorization')
    user_id = verify_token(token)

    data = request.get_json()
    technician_id = data.get('technician_id')
    site_id = data.get('site_id')
    meter_id = data.get('meter_id')
    description = data.get('description')
    assigned_date_str = data.get('assigned_date', datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'))
    due_date_str = data.get('due_date')

    if not all([technician_id, site_id, description]):
        return jsonify({'error': 'Missing required fields: technician_id, site_id, description'}), 400
    
    # Validate technician_id, site_id, meter_id
    technician_exists = db_manager.query_one("SELECT id FROM users WHERE id = ? AND role = 'technician'", (technician_id,))
    if not technician_exists:
        return jsonify({'error': 'Invalid Technician ID'}), 400
    site_exists = db_manager.query_one("SELECT id FROM sites WHERE id = ?", (site_id,))
    if not site_exists:
        return jsonify({'error': 'Invalid Site ID'}), 400
    if meter_id:
        meter_exists = db_manager.query_one("SELECT id FROM meters WHERE id = ? AND site_id = ?", (meter_id, site_id))
        if not meter_exists:
            return jsonify({'error': 'Invalid Meter ID or Meter not at specified Site'}), 400

    # Convert dates
    try:
        assigned_date = datetime.strptime(assigned_date_str, '%Y-%m-%d %H:%M:%S')
        due_date = datetime.strptime(due_date_str, '%Y-%m-%d %H:%M:%S') if due_date_str else None
    except ValueError:
        return jsonify({'error': 'Invalid date format. Use YYYY-MM-DD HH:MM:SS'}), 400

    task_id = db_manager.execute_commit(
        "INSERT INTO tasks (technician_id, site_id, meter_id, description, assigned_date, due_date) VALUES (?, ?, ?, ?, ?, ?)",
        (technician_id, site_id, meter_id, description, assigned_date.strftime('%Y-%m-%d %H:%M:%S'), due_date.strftime('%Y-%m-%d %H:%M:%S') if due_date else None)
    )
    db_manager.log_audit(user_id, 'add_task', 'task', task_id, f'Assigned task {task_id} to technician {technician_id}.')
    return jsonify({'message': 'Task added successfully', 'id': task_id}), 201

@app.route('/api/tasks', methods=['GET'])
def get_tasks():
    token = request.headers.get('Authorization')
    user_id = verify_token(token)
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401

    decoded = jwt.decode(token.split(' ')[1], SECRET_KEY, algorithms=['HS256'])
    role = decoded['role']

    query = """
        SELECT
            t.id,
            t.description,
            t.status,
            t.assigned_date,
            t.due_date,
            u.full_name AS technician_name,
            s.name AS site_name,
            m.identifier AS meter_identifier
        FROM tasks t
        JOIN users u ON t.technician_id = u.id
        JOIN sites s ON t.site_id = s.id
        LEFT JOIN meters m ON t.meter_id = m.id
    """
    params = ()
    
    if role == 'technician':
        query += " WHERE t.technician_id = ?"
        params = (user_id,)

    query += " ORDER BY t.due_date DESC"

    tasks = [dict(row) for row in db_manager.query_all(query, params)]
    
    return jsonify({'tasks': tasks})

@app.route('/api/tasks/<int:task_id>', methods=['PUT'])
def update_task(task_id):
    token = request.headers.get('Authorization')
    user_id = verify_token(token)
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401
        
    data = request.get_json()
    status = data.get('status')
    
    decoded = jwt.decode(token.split(' ')[1], SECRET_KEY, algorithms=['HS256'])
    role = decoded['role']

    if role == 'admin':
        # Admin can update any task
        result = db_manager.execute_commit(
            "UPDATE tasks SET status=? WHERE id=?", 
            (status, task_id)
        )
    else: # technician
        # Technician can only update their own tasks' status
        if status and status not in ['pending', 'completed']: # Technicians typically only change status to these
             return jsonify({'error': 'Invalid status for technician'}), 400
        
        result = db_manager.execute_commit(
            "UPDATE tasks SET status=? WHERE id=? AND technician_id=?", 
            (status, task_id, user_id)
        )
    
    if result <= 0:
        return jsonify({'error': 'Task not found or permission denied'}), 404
        
    db_manager.log_audit(
        user_id, 'update_task', 'task', task_id, 
        f'Task {task_id} status updated to {status}.'
    )
    return jsonify({'message': 'Task updated successfully'}), 200

@app.route('/api/tasks/<int:task_id>', methods=['DELETE'])
@role_required('admin')
def delete_task(task_id):
    token = request.headers.get('Authorization')
    user_id = verify_token(token)

    result = db_manager.execute_commit("DELETE FROM tasks WHERE id = ?", (task_id,))
    if result > 0:
        db_manager.log_audit(user_id, 'delete_task', 'task', task_id, f'Deleted task ID: {task_id}.')
        return jsonify({'message': 'Task deleted successfully'}), 200
    return jsonify({'error': 'Task not found'}), 404

# --- Audit Log (Admin Only) ---
@app.route('/api/audit_log', methods=['GET'])
@role_required('admin')
def get_audit_log():
    log_entries = db_manager.query_all("""
        SELECT 
            al.id, 
            al.timestamp, 
            u.full_name AS user_full_name, 
            al.action, 
            al.target_type, 
            al.target_id, 
            al.details
        FROM audit_log al
        LEFT JOIN users u ON al.user_id = u.id
        ORDER BY al.timestamp DESC
    """)
    return jsonify({'audit_log': [dict(row) for row in log_entries]})

# --- Data Import (Admin Only) ---
@app.route('/api/upload_excel', methods=['POST'])
@role_required('admin')
def upload_excel():
    token = request.headers.get('Authorization')
    user_id = verify_token(token)

    if 'file' not in request.files:
        return jsonify({'error': 'No file part in the request'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    if file:
        try:
            df = pd.read_excel(file.stream)
            # Process dataframe and insert into DB
            for index, row in df.iterrows():
                # Assuming Excel columns map directly to meter_data table:
                # meter_id, timestamp, value
                meter_id = row.get('meter_id')
                timestamp = row.get('timestamp')
                value = row.get('value')

                if meter_id is None or timestamp is None or value is None:
                    continue # Skip rows with missing essential data

                # Check if meter exists
                meter_exists = db_manager.query_one("SELECT id FROM meters WHERE id = ?", (meter_id,))
                if not meter_exists:
                    # Log or handle case where meter_id from excel doesn't exist in DB
                    db_manager.log_audit(user_id, 'excel_import_warning', 'meter_data', None, f'Skipped data for non-existent meter_id: {meter_id} from Excel import.')
                    continue
                
                # Format timestamp
                if isinstance(timestamp, pd.Timestamp):
                    timestamp_str = timestamp.strftime('%Y-%m-%d %H:%M:%S')
                else: # Assuming it's already a string in correct format or can be parsed
                    timestamp_str = str(timestamp) # Add error handling if format is incorrect

                db_manager.execute_commit(
                    "INSERT INTO meter_data (meter_id, timestamp, value) VALUES (?, ?, ?)",
                    (meter_id, timestamp_str, value)
                )
            
            db_manager.log_audit(user_id, 'upload_excel', 'meter_data', None, 'Successfully imported data from Excel file.')
            return jsonify({'message': 'Excel file processed successfully'}), 200
        except Exception as e:
            db_manager.log_audit(user_id, 'upload_excel_failed', 'meter_data', None, f'Failed to import Excel: {str(e)}.')
            return jsonify({'error': f'Error processing file: {str(e)}'}), 500

# This is typically typically only for local development
# When deploying with Gunicorn, this block is usually not executed.
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    # --- COMMENT OUT OR REMOVE THIS LINE FOR PRODUCTION WITH GUNICORN ---
    app.run(host='0.0.0.0', port=port, debug=false) # Set debug=False for production deployment