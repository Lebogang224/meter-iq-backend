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
from flask_caching import Cache
import hashlib

app = Flask(__name__)
SECRET_KEY = os.getenv('SECRET_KEY', 'your-secret-key')

# Configure caching
cache = Cache(app, config={'CACHE_TYPE': 'SimpleCache'})

# Check if database exists
def database_exists():
    return os.path.exists(config.DB_PATH)

# Seed initial data only if needed
def seed_initial_data():
    # Seed users
    if not db_manager.query_one("SELECT 1 FROM users"):
        users = [
            ("admin@meteriq.com", bcrypt.hashpw("admin123".encode('utf-8'), bcrypt.gensalt()).decode('utf-8'), "Admin User", config.ROLE_ADMIN),
            ("tech@meteriq.com", bcrypt.hashpw("tech123".encode('utf-8'), bcrypt.gensalt()).decode('utf-8'), "Field Technician", config.ROLE_TECHNICIAN),
            ("exec@meteriq.com", bcrypt.hashpw("exec123".encode('utf-8'), bcrypt.gensalt()).decode('utf-8'), "Jane Doe (CEO)", config.ROLE_EXECUTIVE)
        ]
        for user in users:
            db_manager.execute_commit("INSERT INTO users (email, password, full_name, role) VALUES (?, ?, ?, ?)", user)

    # Insert sites
    sites_data = [
        ("Vermont", "Unknown Address", "active"),
        ("Sesfikile", "Unknown Address", "active"),
        ("Petersfield", "Unknown Address", "active"),
        ("Majuteni", "Unknown Address", "active"),
        ("Lakefield", "Unknown Address", "active"),
        ("Albert court", "Unknown Address", "active"),
        ("North rand road", "Unknown Address", "active"),
        ("Constance place", "Unknown Address", "active"),
        ("Welcome centre", "Unknown Address", "active"),
        ("Kalan hira", "Unknown Address", "active"),
        ("Safeway centre", "Unknown Address", "active"),
        ("Siyadumisa", "Unknown Address", "active")
    ]
    for site in sites_data:
        try:
            db_manager.execute_commit("INSERT INTO sites (name, address, status) VALUES (?, ?, ?)", site)
        except sqlite3.IntegrityError:
            pass

    # Insert meters and readings
    sites = db_manager.query_all("SELECT id, name FROM sites")
    site_map = {site['name']: site['id'] for site in sites}
    meter_readings = [
        ("1", "Lear", "electricity", "online", site_map["Vermont"], 6425, 6731, 7038, 7356),
        ("Water bulk", "5808", "water", "online", site_map["Vermont"], 57192, 57953, 58762, 59507),
        ("Bulk 6024", "6024", "electricity", "online", site_map["Sesfikile"], 50613, 51269, 52317, 53188),
        ("5757", "5757", "electricity", "faulty", site_map["Sesfikile"], 105, 105, 105, 105),
        ("1", "163", "electricity", "online", site_map["Petersfield"], 4048, 4489, 0, 0),
        ("Bulk W", "7103", "water", "online", site_map["Petersfield"], 22911, 23573, 0, 0),
        ("2379", "2379", "electricity", "online", site_map["Majuteni"], 7213790, 7252109, 7287437, 7320080),
        ("3974", "3974", "water", "online", site_map["Majuteni"], 595, 696, 780, 895),
        ("5672", "5672", "electricity", "online", site_map["Lakefield"], 159604, 159851, 160116, 160338),
        ("9579", "9579", "water", "online", site_map["Lakefield"], 6254, 6399, 6573, 6753),
        ("5546", "5546", "electricity", "online", site_map["Albert court"], 1118, 1125, 1133, 1139),
        ("Bulk water", "Bulk water", "water", "online", site_map["Albert court"], 0, 1696, 2581, 3523),
        ("991", "991", "electricity", "online", site_map["North rand road"], 6659, 6823, 6975, 7152),
        ("Bulk water 7142", "7142", "water", "online", site_map["North rand road"], 27104, 27535, 27967, 28464),
        ("Edge Digital Print", "9382", "electricity", "online", site_map["Constance place"], 212761, 214316, 216016, 0),
        ("Bulk", "8756w", "water", "online", site_map["Constance place"], 2268, 2397, 2544, 0),
        ("9306", "9306", "electricity", "online", site_map["Welcome centre"], 23, 0, 0, 0),
        ("4998(Check E)", "4998", "electricity", "online", site_map["Kalan hira"], 44944, 54512, 62840, 72593),
        ("6843(W Bulk)", "6843(W Bulk)", "water", "online", site_map["Kalan hira"], 6410, 6545, 6649, 6775),
        ("Public lights", "8185", "electricity", "online", site_map["Safeway centre"], 9941, 10007, 10082, 0),
        ("Bulk water", "Bulk water", "water", "online", site_map["Safeway centre"], 34344, 34755, 35139, 35570),
        ("Main 1", "4749", "electricity", "online", site_map["Siyadumisa"], 699345, 700558, 702406, 0),
        ("Bulk", "5535", "water", "online", site_map["Siyadumisa"], 9215, 9574, 9952, 0),
    ]
    for identifier, meter_num, meter_type, status, site_id, r1, r2, r3, r4 in meter_readings:
        try:
            meter_id = db_manager.execute_commit(
                """INSERT INTO meters (site_id, identifier, meter_type, status, base_threshold, last_reading)
                VALUES (?, ?, ?, ?, 1800, ?)""",
                (site_id, meter_num, meter_type, status, r4 if r4 != 0 else r3 if r3 != 0 else r2 if r2 != 0 else r1)
            )
            dates = ['2025-04-07 00:00:00', '2025-05-07 00:00:00', '2025-06-06 00:00:00', '2025-07-06 00:00:00']
            readings = [r1, r2, r3, r4]
            for date, value in zip(dates, readings):
                if value != 0 and value is not None:
                    status = 'normal'
                    prev_index = readings.index(value) - 1
                    if prev_index >= 0 and value > (readings[prev_index] * 1.2):
                        status = 'critical'
                    elif prev_index >= 0 and value > (readings[prev_index] * 1.1):
                        status = 'warning'
                    db_manager.execute_commit(
                        """INSERT INTO readings (meter_id, reading_value, reading_date, status, comments)
                        VALUES (?, ?, ?, ?, ?)""",
                        (meter_id, value, date, status, 'Imported from Excel')
                    )
        except sqlite3.IntegrityError:
            pass

def init_db():
    # Create tables
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
            status TEXT DEFAULT 'online' CHECK(status IN ('online', 'offline', 'maintenance', 'faulty', 'prepaid')),
            base_threshold REAL DEFAULT 1800,
            last_reading REAL DEFAULT 0,
            FOREIGN KEY(site_id) REFERENCES sites(id),
            UNIQUE(site_id, identifier)
        )
    """)
    db_manager.execute_commit("""
        CREATE TABLE IF NOT EXISTS readings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            meter_id INTEGER NOT NULL,
            reading_value REAL NOT NULL,
            reading_date TEXT NOT NULL,
            status TEXT DEFAULT 'normal' CHECK(status IN ('normal', 'warning', 'critical')),
            photo_url TEXT,
            comments TEXT,
            approved INTEGER DEFAULT 0,
            FOREIGN KEY(meter_id) REFERENCES meters(id)
        )
    """)
    db_manager.execute_commit("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            meter_id INTEGER NOT NULL,
            site_id INTEGER NOT NULL,
            message TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('open', 'resolved', 'acknowledged')),
            level INTEGER DEFAULT 1,
            timestamp TEXT NOT NULL,
            FOREIGN KEY(meter_id) REFERENCES meters(id),
            FOREIGN KEY(site_id) REFERENCES sites(id)
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
    # Add indexes for performance
    db_manager.execute_commit("CREATE INDEX IF NOT EXISTS idx_meters_site_id ON meters(site_id)")
    db_manager.execute_commit("CREATE INDEX IF NOT EXISTS idx_readings_meter_id ON readings(meter_id)")
    db_manager.execute_commit("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)")
    # Seed data only if database is new or empty
    if not db_manager.query_one("SELECT 1 FROM sites"):
        seed_initial_data()

# Initialize database only if it doesn't exist
if not database_exists():
    init_db()
else:
    # Ensure tables exist
    init_db()

otp_storage = {}

def verify_token(token):
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return str(decoded['user_id'])
    except jwt.InvalidTokenError:
        return None

@app.errorhandler(401)
def unauthorized(error):
    return jsonify({'error': 'Unauthorized'}), 401

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500



@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        if not email or not password:
            return jsonify({'error': 'Missing email or password'}), 400
        if auth_service.login(email, password):
            user_id = str(auth_service.get_current_user_id())
            otp = str(random.randint(100000, 999999))
            otp_storage[user_id] = otp
            print(f"OTP for user {email}: {otp} (user_id: {user_id})")
            return jsonify({'user_id': user_id})
        else:
            return jsonify({'error': 'Invalid credentials'}), 401
    except Exception as e:
        print(f"Login error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/verify-otp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    user_id = str(data.get('user_id'))
    otp = data.get('otp')
    print(f"Verifying OTP: user_id={user_id}, otp={otp}, stored={otp_storage.get(user_id)}")
    if user_id in otp_storage and otp_storage[user_id] == otp:
        token = jwt.encode({
            'user_id': user_id, 
            'role': auth_service.get_current_user_role()
        }, SECRET_KEY, algorithm='HS256')
        user = {
            'full_name': auth_service.current_user['full_name'], 
            'role': auth_service.current_user['role']
        }
        del otp_storage[user_id]
        return jsonify({'token': token, 'user': user})
    return jsonify({'error': 'Invalid OTP'}), 401

@app.route('/api/logout', methods=['POST'])
def logout():
    token = request.headers.get('Authorization')
    user_id = verify_token(token)
    if user_id:
        auth_service.logout()
    return jsonify({'message': 'Logged out'})

@app.route('/api/dashboard', methods=['GET'])
@cache.cached(timeout=60, key_prefix=lambda: f"dashboard_{hashlib.md5(str(request.headers.get('Authorization')).encode()).hexdigest()}")
def dashboard():
    token = request.headers.get('Authorization')
    if not verify_token(token):
        return jsonify({'error': 'Unauthorized'}), 401
    kpis = db_manager.query_one("""
        SELECT 
            (SELECT COUNT(*) FROM readings) AS total_readings,
            (SELECT COUNT(*) FROM alerts WHERE status='open') AS critical_alerts,
            (SELECT COUNT(*) FROM readings WHERE status='normal') AS normal_readings,
            (SELECT COUNT(*) FROM sites WHERE status='active') AS active_sites,
            (SELECT COUNT(*) FROM meters WHERE status='online') AS total_meters,
            (SELECT COUNT(*) FROM users WHERE role='technician' AND is_active=1) AS total_techs
    """)
    if not kpis:
        return jsonify({'error': 'Could not fetch dashboard data'}), 500
    co2_reduction = (kpis['total_readings'] / 1000) * random.uniform(0.4, 0.5)
    return jsonify({
        'total_readings': kpis['total_readings'],
        'critical_alerts': kpis['critical_alerts'],
        'normal_readings': kpis['normal_readings'],
        'active_sites': kpis['active_sites'],
        'total_meters': kpis['total_meters'],
        'total_techs': kpis['total_techs'],
        'co2_reduction': f"{co2_reduction:,.2f} tons"
    })

@app.route('/api/readings', methods=['GET'])
@cache.cached(timeout=60, query_string=True)
def get_readings():
    token = request.headers.get('Authorization')
    if not verify_token(token):
        return jsonify({'error': 'Unauthorized'}), 401
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 10))
    offset = (page - 1) * per_page
    readings = [dict(row) for row in db_manager.query_all("""
        SELECT r.id, r.reading_value, r.reading_date, r.status, r.photo_url, r.comments, r.approved,
               m.identifier as meter_identifier, s.name as site_name
        FROM readings r
        JOIN meters m ON r.meter_id = m.id
        JOIN sites s ON m.site_id = s.id
        ORDER BY r.reading_date DESC
        LIMIT ? OFFSET ?
    """, (per_page, offset))]
    return jsonify({'readings': readings})

@app.route('/api/readings', methods=['POST'])
def submit_reading():
    token = request.headers.get('Authorization')
    user_id = verify_token(token)
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401
    site_id = request.form.get('site_id')
    meter_id = request.form.get('meter_id')
    reading_value = float(request.form.get('reading_value'))
    comments = request.form.get('comments', '')
    meter = db_manager.query_one(
        "SELECT last_reading, meter_type, base_threshold FROM meters WHERE id=?", 
        (meter_id,)
    )
    if not meter:
        return jsonify({'error': 'Invalid meter'}), 400
    last_reading = meter['last_reading']
    if reading_value < last_reading:
        return jsonify({'error': 'Current reading must be >= previous reading'}), 400
    consumption = reading_value - last_reading
    if meter['meter_type'] == 'electricity':
        historical_data = [
            row['reading_value'] for row in db_manager.query_all(
                "SELECT reading_value FROM readings WHERE meter_id=? ORDER BY reading_date DESC LIMIT 10",
                (meter_id,)
            )
        ]
        threshold = dynamic_threshold(meter['meter_type'], tuple(historical_data))  # Convert to tuple for caching
    else:
        threshold = meter['base_threshold']
    status = 'normal'
    alert_level = 0
    if consumption > threshold * 1.2:
        status = 'critical'
        alert_level = 2
    elif consumption > threshold or consumption < threshold * 0.8:
        status = 'warning'
        alert_level = 1
    photo_url = None
    if 'photo' in request.files:
        photo = request.files['photo']
        filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{photo.filename}"
        photo_path = f"Uploads/{filename}"
        os.makedirs('Uploads', exist_ok=True)
        photo.save(photo_path)
        photo_url = f"/Uploads/{filename}"
    reading_id = db_manager.execute_commit(
        """INSERT INTO readings (meter_id, reading_value, reading_date, status, photo_url, comments)
        VALUES (?, ?, ?, ?, ?, ?)""",
        (meter_id, reading_value, datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'), status, photo_url, comments)
    )
    if not reading_id:
        return jsonify({'error': 'Failed to save reading'}), 500
    db_manager.execute_commit(
        "UPDATE meters SET last_reading=? WHERE id=?", 
        (reading_value, meter_id)
    )
    if alert_level > 0:
        meter_info = db_manager.query_one(
            "SELECT site_id FROM meters WHERE id=?", 
            (meter_id,)
        )
        if meter_info:
            message = f"{status.capitalize()} Consumption: {consumption:.2f} (threshold: {threshold:.2f})"
            db_manager.execute_commit(
                """INSERT INTO alerts (meter_id, site_id, message, status, level, timestamp) 
                VALUES (?, ?, ?, 'open', ?, ?)""",
                (meter_id, meter_info['site_id'], message, alert_level, 
                 datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'))
            )
    db_manager.log_audit(
        user_id, 
        'CREATE_READING', 
        'READING', 
        reading_id, 
        f"Value: {reading_value}, Status: {status}"
    )
    cache.delete_memoized(get_readings)
    return jsonify({'message': 'Reading submitted'})

@app.route('/api/readings/<int:reading_id>/approve', methods=['PUT'])
def approve_reading(reading_id):
    token = request.headers.get('Authorization')
    user_id = verify_token(token)
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401
    decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
    role = decoded['role']
    if role != 'admin':
        return jsonify({'error': 'Permission denied'}), 403
    result = db_manager.execute_commit("UPDATE readings SET approved=1 WHERE id=?", (reading_id,))
    if result <= 0:
        return jsonify({'error': 'Reading not found'}), 404
    db_manager.log_audit(
        user_id, 
        'APPROVE_READING', 
        'READING', 
        reading_id
    )
    cache.delete_memoized(get_readings)
    return jsonify({'message': 'Reading approved'})

@app.route('/api/alerts', methods=['GET'])
@cache.cached(timeout=60, query_string=True)
def get_alerts():
    token = request.headers.get('Authorization')
    if not verify_token(token):
        return jsonify({'error': 'Unauthorized'}), 401
    status = request.args.get('status', 'open')
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 10))
    offset = (page - 1) * per_page
    alerts = [dict(row) for row in db_manager.query_all("""
        SELECT a.id, a.message, a.status, a.level, a.timestamp,
               m.identifier as meter_identifier, s.name as site_name
        FROM alerts a
        JOIN meters m ON a.meter_id = m.id
        JOIN sites s ON a.site_id = s.id
        WHERE a.status = ?
        ORDER BY a.timestamp DESC
        LIMIT ? OFFSET ?
    """, (status, per_page, offset))]
    return jsonify({'alerts': alerts})

@app.route('/api/alerts/<int:alert_id>/resolve', methods=['PUT'])
def resolve_alert(alert_id):
    token = request.headers.get('Authorization')
    user_id = verify_token(token)
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401
    result = db_manager.execute_commit(
        "UPDATE alerts SET status='resolved', message=message || ' (Resolved)' WHERE id=?", 
        (alert_id,)
    )
    if result <= 0:
        return jsonify({'error': 'Alert not found'}), 404
    db_manager.log_audit(
        user_id, 
        'RESOLVE_ALERT', 
        'ALERT', 
        alert_id, 
        "Alert resolved"
    )
    cache.delete_memoized(get_alerts)
    return jsonify({'message': 'Alert resolved'})

@app.route('/api/sites', methods=['GET'])
@cache.cached(timeout=60)
def get_sites():
    token = request.headers.get('Authorization')
    user_id = verify_token(token)
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401
    sites = [dict(row) for row in db_manager.query_all("SELECT id, name, address, status FROM sites")]
    return jsonify(sites)

@app.route('/api/sites', methods=['POST'])
def create_site():
    token = request.headers.get('Authorization')
    user_id = verify_token(token)
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json()
    name = data.get('name')
    address = data.get('address')
    status = data.get('status', 'active')
    try:
        site_id = db_manager.execute_commit(
            "INSERT INTO sites (name, address, status) VALUES (?, ?, ?)", 
            (name, address, status)
        )
        cache.delete_memoized(get_sites)
        if not site_id:
            return jsonify({'error': 'Failed to create site'}), 500
        db_manager.log_audit(
            user_id, 
            'CREATE_SITE', 
            'SITE', 
            site_id
        )
        return jsonify({'message': 'Site created', 'id': site_id})
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Site name already exists'}), 400

@app.route('/api/sites/<int:site_id>', methods=['PUT'])
def update_site(site_id):
    token = request.headers.get('Authorization')
    user_id = verify_token(token)
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json()
    name = data.get('name')
    address = data.get('address')
    status = data.get('status')
    params = []
    query_parts = []
    if name:
        query_parts.append("name=?")
        params.append(name)
    if address:
        query_parts.append("address=?")
        params.append(address)
    if status:
        query_parts.append("status=?")
        params.append(status)
    if not query_parts:
        return jsonify({'error': 'No fields to update'}), 400
    query = f"UPDATE sites SET {', '.join(query_parts)} WHERE id=?"
    params.append(site_id)
    result = db_manager.execute_commit(query, tuple(params))
    if result <= 0:
        return jsonify({'error': 'Site not found'}), 404
    cache.delete_memoized(get_sites)
    db_manager.log_audit(
        user_id, 
        'UPDATE_SITE', 
        'SITE', 
        site_id
    )
    return jsonify({'message': 'Site updated'})

@app.route('/api/sites/<int:site_id>', methods=['DELETE'])
def delete_site(site_id):
    token = request.headers.get('Authorization')
    user_id = verify_token(token)
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401
    result = db_manager.execute_commit(
        "DELETE FROM sites WHERE id=?", 
        (site_id,)
    )
    if result <= 0:
        return jsonify({'error': 'Site not found'}), 404
    cache.delete_memoized(get_sites)
    db_manager.log_audit(
        user_id, 
        'DELETE_SITE', 
        'SITE', 
        site_id
    )
    return jsonify({'message': 'Site deleted'})

@app.route('/api/users', methods=['GET'])
@cache.cached(timeout=60)
def get_users():
    token = request.headers.get('Authorization')
    user_id = verify_token(token)
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401
    users = [dict(row) for row in db_manager.query_all("SELECT id, email, full_name, role FROM users WHERE is_active=1")]
    return jsonify(users)

@app.route('/api/users', methods=['POST'])
def create_user():
    token = request.headers.get('Authorization')
    user_id = verify_token(token)
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401
    if not db_manager.has_permission(user_id, ['admin']):
        return jsonify({'error': 'Permission denied'}), 403
    data = request.get_json()
    email = data.get('email')
    password = bcrypt.hashpw(data.get('password').encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    full_name = data.get('full_name')
    role = data.get('role')
    try:
        new_user_id = db_manager.execute_commit(
            "INSERT INTO users (email, password, full_name, role) VALUES (?, ?, ?, ?)",
            (email, password, full_name, role)
        )
        cache.delete_memoized(get_users)
        if not new_user_id:
            return jsonify({'error': 'Failed to create user'}), 500
        db_manager.log_audit(
            user_id, 
            'CREATE_USER', 
            'USER', 
            new_user_id
        )
        return jsonify({'message': 'User created', 'id': new_user_id})
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Email already exists'}), 400

@app.route('/api/users/<int:user_id>', methods=['PUT'])
def update_user(user_id):
    token = request.headers.get('Authorization')
    requester_id = verify_token(token)
    if not requester_id:
        return jsonify({'error': 'Unauthorized'}), 401
    if not db_manager.has_permission(requester_id, ['admin']):
        return jsonify({'error': 'Permission denied'}), 403
    data = request.get_json()
    role = data.get('role')
    result = db_manager.execute_commit(
        "UPDATE users SET role=? WHERE id=?", 
        (role, user_id)
    )
    if result <= 0:
        return jsonify({'error': 'User not found'}), 404
    cache.delete_memoized(get_users)
    db_manager.log_audit(
        requester_id, 
        'UPDATE_USER', 
        'USER', 
        user_id
    )
    return jsonify({'message': 'User updated'})

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
def delete_user(user_id):
    token = request.headers.get('Authorization')
    requester_id = verify_token(token)
    if not requester_id:
        return jsonify({'error': 'Unauthorized'}), 401
    if not db_manager.has_permission(requester_id, ['admin']):
        return jsonify({'error': 'Permission denied'}), 403
    result = db_manager.execute_commit(
        "UPDATE users SET is_active=0 WHERE id=?", 
        (user_id,)
    )
    if result <= 0:
        return jsonify({'error': 'User not found'}), 404
    cache.delete_memoized(get_users)
    db_manager.log_audit(
        requester_id, 
        'DELETE_USER', 
        'USER', 
        user_id
    )
    return jsonify({'message': 'User deleted'})

@app.route('/api/meters', methods=['GET'])
@cache.cached(timeout=60, query_string=True)
def get_meters():
    token = request.headers.get('Authorization')
    if not verify_token(token):
        return jsonify({'error': 'Unauthorized'}), 401
    site_id = request.args.get('site_id')
    query = "SELECT id, identifier, last_reading FROM meters WHERE status='online'"
    params = []
    if site_id:
        query += " AND site_id=?"
        params = [site_id]
    meters = [dict(row) for row in db_manager.query_all(query, tuple(params))]
    return jsonify(meters)

@app.route('/api/analytics/readings', methods=['GET'])
@cache.cached(timeout=60, query_string=True)
def analytics_readings():
    token = request.headers.get('Authorization')
    if not verify_token(token):
        return jsonify({'error': 'Unauthorized'}), 401
    start_date = request.args.get('from')
    end_date = request.args.get('to')
    start_datetime = f"{start_date} 00:00:00"
    end_datetime = f"{end_date} 23:59:59"
    data = db_manager.query_all("""
        SELECT date(r.reading_date) as day, m.meter_type, SUM(r.reading_value) as total
        FROM readings r
        JOIN meters m ON r.meter_id = m.id
        WHERE r.reading_date BETWEEN ? AND ?
        GROUP BY date(r.reading_date), m.meter_type
        ORDER BY day
    """, (start_datetime, end_datetime))
    electric = []
    water = []
    gas = []
    dates = sorted(set(row['day'] for row in data))
    for date in dates:
        electric_val = next((row['total'] for row in data if row['day'] == date and row['meter_type'] == 'electricity'), 0)
        water_val = next((row['total'] for row in data if row['day'] == date and row['meter_type'] == 'water'), 0)
        gas_val = next((row['total'] for row in data if row['day'] == date and row['meter_type'] == 'gas'), 0)
        electric.append(electric_val)
        water.append(water_val)
        gas.append(gas_val)
    return jsonify({'dates': dates, 'electric': electric, 'water': water, 'gas': gas})

@app.route('/api/reports', methods=['GET'])
def generate_report():
    token = request.headers.get('Authorization')
    if not verify_token(token):
        return jsonify({'error': 'Unauthorized'}), 401
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    format = request.args.get('format', 'csv')
    start_datetime = f"{start_date} 00:00:00"
    end_datetime = f"{end_date} 23:59:59"
    readings = [dict(row) for row in db_manager.query_all("""
        SELECT r.reading_value, r.reading_date, r.status, r.comments,
               m.identifier as meter_identifier, s.name as site_name
        FROM readings r
        JOIN meters m ON r.meter_id = m.id
        JOIN sites s ON m.site_id = s.id
        WHERE r.reading_date BETWEEN ? AND ?
        ORDER BY r.reading_date DESC
    """, (start_datetime, end_datetime))]
    df = pd.DataFrame(readings)
    output = BytesIO()
    if format == 'excel':
        df.to_excel(output, index=False)
        content_type = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        filename = 'report.xlsx'
    else:
        df.to_csv(output, index=False)
        content_type = 'text/csv'
        filename = 'report.csv'
    output.seek(0)
    return send_file(output, mimetype=content_type, download_name=filename, as_attachment=True)

@app.route('/api/audit_log', methods=['GET'])
@cache.cached(timeout=60)
def get_audit_log():
    token = request.headers.get('Authorization')
    user_id = verify_token(token)
    if not user_id or not db_manager.has_permission(user_id, ['admin']):
        return jsonify({'error': 'Unauthorized'}), 401
    logs = [dict(row) for row in db_manager.query_all("SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT 100")]
    return jsonify(logs)

@app.route('/Uploads/<path:filename>')
def serve_upload(filename):
    return send_from_directory('Uploads', filename)

@app.route('/api/tasks', methods=['POST'])
def assign_task():
    token = request.headers.get('Authorization')
    user_id = verify_token(token)
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401
    decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
    role = decoded['role']
    if role != 'admin':
        return jsonify({'error': 'Permission denied'}), 403
    data = request.get_json()
    technician_id = data.get('technician_id')
    site_id = data.get('site_id')
    meter_id = data.get('meter_id')
    description = data.get('description')
    due_date = data.get('due_date')
    task_id = db_manager.execute_commit(
        """INSERT INTO tasks (technician_id, site_id, meter_id, description, assigned_date, due_date)
        VALUES (?, ?, ?, ?, ?, ?)""",
        (technician_id, site_id, meter_id, description, datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'), due_date)
    )
    db_manager.log_audit(
        user_id, 
        'ASSIGN_TASK', 
        'TASK', 
        task_id
    )
    cache.delete_memoized(get_tasks)
    return jsonify({'message': 'Task assigned', 'id': task_id})

@app.route('/api/tasks', methods=['GET'])
@cache.cached(timeout=60, query_string=True)
def get_tasks():
    token = request.headers.get('Authorization')
    user_id = verify_token(token)
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401
    decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
    role = decoded['role']
    if role == 'admin':
        tasks = [dict(row) for row in db_manager.query_all("""
            SELECT t.*, s.name as site_name, m.identifier as meter_identifier
            FROM tasks t
            JOIN sites s ON t.site_id = s.id
            LEFT JOIN meters m ON t.meter_id = m.id
        """)]
    else:
        tasks = [dict(row) for row in db_manager.query_all("""
            SELECT t.*, s.name as site_name, m.identifier as meter_identifier
            FROM tasks t
            JOIN sites s ON t.site_id = s.id
            LEFT JOIN meters m ON t.meter_id = m.id
            WHERE technician_id=?
        """, (user_id,))]
    return jsonify({'tasks': tasks})

@app.route('/api/tasks/<int:task_id>', methods=['PUT'])
def update_task(task_id):
    token = request.headers.get('Authorization')
    user_id = verify_token(token)
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json()
    status = data.get('status')
    result = db_manager.execute_commit(
        "UPDATE tasks SET status=? WHERE id=? AND technician_id=?", 
        (status, task_id, user_id)
    )
    if result <= 0:
        return jsonify({'error': 'Task not found or permission denied'}), 404
    db_manager.log_audit(
        user_id, 
        'UPDATE_TASK', 
        'TASK', 
        task_id, 
        f"Status changed to {status}"
    )
    cache.delete_memoized(get_tasks)
    return jsonify({'message': 'Task updated'})

if __name__ == '__main__':
    app.run(debug=True)

