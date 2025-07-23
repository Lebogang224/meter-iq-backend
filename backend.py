
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
SECRET_KEY = 'your-secret-key'

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

    # Seed initial users if not present
    if not db_manager.query_one("SELECT 1 FROM users"):
        users = [
            ("admin@meteriq.com", bcrypt.hashpw("admin123".encode('utf-8'), bcrypt.gensalt()).decode('utf-8'), "Admin User", config.ROLE_ADMIN),
            ("tech@meteriq.com", bcrypt.hashpw("tech123".encode('utf-8'), bcrypt.gensalt()).decode('utf-8'), "Field Technician", config.ROLE_TECHNICIAN),
            ("exec@meteriq.com", bcrypt.hashpw("exec123".encode('utf-8'), bcrypt.gensalt()).decode('utf-8'), "Jane Doe (CEO)", config.ROLE_EXECUTIVE)
        ]
        db_manager.conn.executemany(
            "INSERT INTO users (email, password, full_name, role) VALUES (?, ?, ?, ?)", 
            users
        )
        db_manager.conn.commit()

    # Seed sites, meters, and readings only if sites table is empty
    if not db_manager.query_one("SELECT 1 FROM sites"):
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
        db_manager.conn.executemany(
            "INSERT OR IGNORE INTO sites (name, address, status) VALUES (?, ?, ?)",
            sites_data
        )
        db_manager.conn.commit()

        # Get site map
        sites = db_manager.query_all("SELECT id, name FROM sites")
        site_map = {site['name']: site['id'] for site in sites}

        # Prepare meter data
        meter_data = []
        reading_data = []
        dates = ['2025-04-07 00:00:00', '2025-05-07 00:00:00', '2025-06-06 00:00:00', '2025-07-06 00:00:00']

        meter_readings = [
            # Vermont
            ("1", "Lear", "electricity", "online", site_map["Vermont"], 6425, 6731, 7038, 7356),
            ("2", "4409", "electricity", "online", site_map["Vermont"], 10325, 104514, 104729, 104953),
            ("3", "4900", "electricity", "online", site_map["Vermont"], 76277, 76411, 76472, 76602),
            ("4", "9247", "electricity", "online", site_map["Vermont"], 97489, 97935, 98389, 99673),
            ("5", "8876", "electricity", "online", site_map["Vermont"], 120129, 120366, 120595, 120861),
            ("6", "Lear", "electricity", "online", site_map["Vermont"], 66091, 66508, 66929, 67387),
            ("7", "8272", "electricity", "online", site_map["Vermont"], 50913, 51395, 51871, 52417),
            ("8", "Dzt", "electricity", "online", site_map["Vermont"], 10753, 11308, 11899, 12642),
            ("9", "5298", "electricity", "online", site_map["Vermont"], 124278, 124634, 124894, 125523),
            ("10", "5107", "electricity", "online", site_map["Vermont"], 25023, 25317, 25704, 26153),
            ("11", "6490", "electricity", "online", site_map["Vermont"], 73801, 74102, 74390, 74677),
            ("12", "9312", "electricity", "online", site_map["Vermont"], 81390, 81423, 81456, 81491),
            ("13", "9064", "electricity", "online", site_map["Vermont"], 67565, 67820, 68140, 68581),
            ("14", "8397", "electricity", "online", site_map["Vermont"], 88965, 89264, 89572, 89928),
            ("15", "8868", "electricity", "online", site_map["Vermont"], 97244, 97562, 97909, 98302),
            ("16", "70", "electricity", "online", site_map["Vermont"], 109984, 110356, 110816, 111330),
            ("17", "Lear", "electricity", "online", site_map["Vermont"], 20616, 20852, 21123, 21448),
            ("18", "6565", "electricity", "online", site_map["Vermont"], 108791, 109210, 109572, 110039),
            ("19", "8884", "electricity", "online", site_map["Vermont"], 114232, 115056, 115960, 117041),
            ("20", "9726", "electricity", "online", site_map["Vermont"], 107809, 108153, 108547, 108991),
            ("21", "2253", "electricity", "online", site_map["Vermont"], 81271, 81576, 81996, 82360),
            ("22", "8835", "electricity", "online", site_map["Vermont"], 103584, 104056, 104589, 105539),
            ("23", "8959", "electricity", "online", site_map["Vermont"], 97606, 98224, 98972, 99635),
            ("24", "8598", "electricity", "online", site_map["Vermont"], 109540, 109784, 110061, 110390),
            ("25", "9239", "electricity", "online", site_map["Vermont"], 126966, 127335, 127689, 128055),
            ("26", "2758", "electricity", "online", site_map["Vermont"], 92785, 93112, 93608, 94197),
            ("27", "9221", "electricity", "online", site_map["Vermont"], 103426, 103796, 104215, 104670),
            ("28", "8090", "electricity", "online", site_map["Vermont"], 99999, 100374, 100794, 101182),
            ("29", "877", "electricity", "online", site_map["Vermont"], 82583, 82706, 82822, 82968),
            ("30", "5331", "electricity", "online", site_map["Vermont"], 91352, 91852, 92333, 92865),
            ("31", "6540", "electricity", "online", site_map["Vermont"], 107861, 108521, 109229, 109993),
            ("32", "6409", "electricity", "online", site_map["Vermont"], 146487, 147264, 147932, 148793),
            ("33", "62", "electricity", "online", site_map["Vermont"], 140362, 141191, 142029, 142809),
            ("34", "5949", "electricity", "online", site_map["Vermont"], 105561, 106075, 106580, 107597),
            ("35", "6557", "electricity", "online", site_map["Vermont"], 106708, 107401, 108144, 108956),
            ("36", "4006", "electricity", "online", site_map["Vermont"], 107979, 108546, 109176, 109882),
            ("37", "Lear", "electricity", "online", site_map["Vermont"], 41308, 41316, 41317, 41317),
            ("38", "9643", "electricity", "online", site_map["Vermont"], 75949, 76530, 77006, 77020),
            ("39", "Lear", "electricity", "online", site_map["Vermont"], 46580, 46920, 47283, 47709),
            ("40", "6607", "electricity", "online", site_map["Vermont"], 75076, 75370, 75644, 75945),
            ("41", "8454", "electricity", "online", site_map["Vermont"], 87458, 88079, 88733, 89483),
            ("42", "42", "electricity", "online", site_map["Vermont"], 119461, 119922, 120399, 120942),
            ("43", "Lear", "electricity", "online", site_map["Vermont"], 32090, 32509, 32934, 33417),
            ("44", "138", "electricity", "online", site_map["Vermont"], 115289, 115760, 116352, 117059),
            ("45", "9650", "electricity", "online", site_map["Vermont"], 104418, 104485, 104905, 105613),
            ("46", "54", "electricity", "online", site_map["Vermont"], 87014, 87045, 87068, 87083),
            ("47", "104", "electricity", "online", site_map["Vermont"], 78517, 78728, 78988, 79303),
            ("48", "6441", "electricity", "online", site_map["Vermont"], 81634, 82004, 82354, 82726),
            ("49", "8892", "electricity", "online", site_map["Vermont"], 107784, 108276, 108827, 109367),
            ("50", "782", "electricity", "online", site_map["Vermont"], 127268, 128279, 129429, 130726),
            ("51", "3956", "electricity", "online", site_map["Vermont"], 97623, 98210, 98810, 99408),
            ("Guard", "6375", "electricity", "online", site_map["Vermont"], 349654, 351019, 352395, 353807),
            ("Water bulk", "5808", "water", "online", site_map["Vermont"], 57192, 57953, 58762, 59507),
            ("Water 13", "9802", "water", "online", site_map["Vermont"], 467, 474, 0, 0),
            ("Water 14", "9807", "water", "online", site_map["Vermont"], 567, 578, 0, 0),
            ("Water 15", "9809", "water", "online", site_map["Vermont"], 645, 653, 0, 0),
            ("Water 16", "9300", "water", "online", site_map["Vermont"], 867, 877, 0, 0),
            ("Water 17", "9820", "water", "online", site_map["Vermont"], 575, 581, 0, 0),
            ("Water 18", "8208", "water", "online", site_map["Vermont"], 855, 865, 0, 0),
            ("Water 19", "9290", "water", "online", site_map["Vermont"], 2143, 2175, 0, 0),
            ("Water 20", "9283", "water", "online", site_map["Vermont"], 859, 870, 0, 0),
            ("Water 21", "9819", "water", "online", site_map["Vermont"], 531, 540, 0, 0),
            ("Water 22", "8845", "water", "online", site_map["Vermont"], 136, 168, 0, 0),
            ("Water 23", "1355", "water", "online", site_map["Vermont"], 313, 327, 0, 0),
            ("Water 24", "9292", "water", "online", site_map["Vermont"], 684, 692, 0, 0),
            ("Water 33", "-", "water", "prepaid", site_map["Vermont"], 0, 0, 0, 0),
            ("Water 34", "9895", "water", "online", site_map["Vermont"], 2102, 2120, 0, 0),
            ("Water 35", "9285", "water", "online", site_map["Vermont"], 1276, 1295, 0, 0),
            ("Water 36", "6650", "water", "online", site_map["Vermont"], 1345, 1373, 0, 0),
            ("Water 37", "9900", "water", "online", site_map["Vermont"], 569, 576, 0, 0),
            ("Water 38", "9896", "water", "online", site_map["Vermont"], 683, 683, 0, 0),
            ("Water 39", "9899", "water", "online", site_map["Vermont"], 1071, 1081, 0, 0),
            ("Water 40", "9296", "water", "online", site_map["Vermont"], 642, 648, 0, 0),
            ("Water 41", "9881", "water", "online", site_map["Vermont"], 803, 881, 0, 0),
            ("Water 42", "9295", "water", "online", site_map["Vermont"], 983, 996, 0, 0),
            ("Water 43", "9889", "water", "online", site_map["Vermont"], 686, 701, 0, 0),
            ("Water 44", "9891", "water", "online", site_map["Vermont"], 2040, 2067, 0, 0),
            ("Water 45", "9298", "water", "online", site_map["Vermont"], 671, 701, 0, 0),
            ("Water 46", "9281", "water", "online", site_map["Vermont"], 736, 742, 0, 0),
            ("Water 47", "6419", "water", "online", site_map["Vermont"], 193, 198, 0, 0),
            ("Water 48", "9297", "water", "online", site_map["Vermont"], 362, 369, 0, 0),
            ("Water 49", "9287", "water", "online", site_map["Vermont"], 1125, 1140, 0, 0),
            ("Water 50", "9299", "water", "online", site_map["Vermont"], 2070, 2119, 0, 0),
            ("Water 51", "9286", "water", "online", site_map["Vermont"], 1346, 1362, 0, 0),
            ("Water Guard house", "9808", "water", "online", site_map["Vermont"], 987, 989, 0, 0),
            ("Water common property 1", "9812", "water", "online", site_map["Vermont"], 124, 130, 0, 0),
            ("Water common property 2", "9810", "water", "online", site_map["Vermont"], 80, 83, 0, 0),
            ("Water common property 3", "9817", "water", "online", site_map["Vermont"], 80, 84, 0, 0),
            ("Water Park", "5326", "water", "online", site_map["Vermont"], 120, 122, 0, 0),
            # Sesfikile
            ("4623", "4623", "electricity", "online", site_map["Sesfikile"], 4513, 4513, 4764, 4897),
            ("5757", "5757", "electricity", "faulty", site_map["Sesfikile"], 105, 105, 105, 105),
            ("5752", "5752", "electricity", "online", site_map["Sesfikile"], 5628, 5652, 5673, 5708),
            ("5751", "5751", "electricity", "online", site_map["Sesfikile"], 142, 143, 144, 144),
            ("5748", "5748", "electricity", "online", site_map["Sesfikile"], 66, 67, 68, 69),
            ("5755", "5755", "electricity", "online", site_map["Sesfikile"], 2138, 2140, 2142, 2144),
            ("5753", "5753", "electricity", "online", site_map["Sesfikile"], 557, 560, 563, 565),
            ("5754", "5754", "electricity", "online", site_map["Sesfikile"], 676, 680, 684, 688),
            ("5756", "5756", "electricity", "online", site_map["Sesfikile"], 119, 121, 123, 124),
            ("1242", "1242", "electricity", "online", site_map["Sesfikile"], 11495, 11495, 11495, 11495),
            ("5590", "5590", "electricity", "online", site_map["Sesfikile"], 541, 544, 548, 551),
            ("1946", "1946", "electricity", "online", site_map["Sesfikile"], 28546, 28662, 28761, 28865),
            ("5750", "5750", "electricity", "online", site_map["Sesfikile"], 2585, 2607, 2631, 2662),
            ("5749", "5749", "electricity", "online", site_map["Sesfikile"], 626, 626, 626, 626),
            ("8238", "8238", "electricity", "online", site_map["Sesfikile"], 25555, 25678, 25783, 25914),
            ("Bulk 6024", "6024", "electricity", "online", site_map["Sesfikile"], 50613, 51269, 52317, 53188),
            ("KFC", "4781", "electricity", "online", site_map["Sesfikile"], 4540219, 4561450, 4585838, 0),
            ("Shop 13", "7710", "electricity", "online", site_map["Sesfikile"], 533165, 533926, 5347635, 0),
            ("Shop 20", "8015", "electricity", "online", site_map["Sesfikile"], 378709, 421928, 45910, 0),
            ("Common area", "8819", "electricity", "online", site_map["Sesfikile"], 73522, 74060, 74502, 0),
            ("Shop 19", "8827", "electricity", "online", site_map["Sesfikile"], 48289, 48646, 49057, 0),
            ("Shop 17-18", "741", "electricity", "online", site_map["Sesfikile"], 616553, 621127, 626454, 0),
            ("Shop 14", "774", "electricity", "online", site_map["Sesfikile"], 838336, 40069, 40279, 0),
            ("Common area", "7463", "electricity", "online", site_map["Sesfikile"], 41480, 42950, 44326, 0),
            ("Shop 21", "5135", "electricity", "online", site_map["Sesfikile"], 61783, 61783, 61783, 0),
            ("Shop 16", "790", "electricity", "online", site_map["Sesfikile"], 125870, 126473, 127033, 0),
            ("Common area", "8769", "electricity", "online", site_map["Sesfikile"], 126121, 126128, 126129, 0),
            ("Shop 12", "394", "electricity", "online", site_map["Sesfikile"], 57061, 57392, 57710, 0),
            ("FNB", "Lear", "electricity", "online", site_map["Sesfikile"], 12974, 13168, 0, 0),
            ("Shop 11A", "402", "electricity", "online", site_map["Sesfikile"], 38250, 38456, 38863, 0),
            ("Shop 2", "758", "electricity", "online", site_map["Sesfikile"], 321313, 322018, 322665, 0),
            ("Shop 3", "5143", "electricity", "online", site_map["Sesfikile"], 40141, 40376, 40639, 0),
            ("Shop 5-10", "717", "electricity", "online", site_map["Sesfikile"], 244728, 251794, 259741, 0),
            ("Shop 4", "725", "electricity", "online", site_map["Sesfikile"], 84866, 84866, 84866, 0),
            ("Shop 11", "410", "electricity", "online", site_map["Sesfikile"], 108229, 108740, 109412, 0),
            ("Check meter", "8436", "electricity", "online", site_map["Sesfikile"], 58399, 73443, 51251, 0),
            ("Checkers", "9628", "electricity", "online", site_map["Sesfikile"], 474159, 582684, 699639, 0),
            # Petersfield
            ("1", "163", "electricity", "online", site_map["Petersfield"], 4048, 4489, 0, 0),
            ("2", "3435", "electricity", "online", site_map["Petersfield"], 49188, 46847, 0, 0),
            ("3", "4071", "electricity", "online", site_map["Petersfield"], 15928, 16649, 0, 0),
            ("4", "2313", "electricity", "online", site_map["Petersfield"], 25313, 25508, 0, 0),
            ("5", "3404", "electricity", "online", site_map["Petersfield"], 66415, 66754, 0, 0),
            ("6", "4927", "electricity", "online", site_map["Petersfield"], 42254, 43413, 0, 0),
            ("7", "9731", "electricity", "online", site_map["Petersfield"], 48429, 48502, 0, 0),
            ("8", "556", "electricity", "online", site_map["Petersfield"], 0, 90954, 0, 0),
            ("9", "8708", "electricity", "online", site_map["Petersfield"], 0, 75144, 0, 0),
            ("10", "2631", "electricity", "online", site_map["Petersfield"], 16882, 16882, 0, 0),
            ("11", "978", "electricity", "online", site_map["Petersfield"], 0, 20312, 0, 0),
            ("12", "4300", "electricity", "online", site_map["Petersfield"], 0, 24520, 0, 0),
            ("13", "5272", "electricity", "online", site_map["Petersfield"], 26971, 27438, 0, 0),
            ("14", "5272", "electricity", "online", site_map["Petersfield"], 32973, 33217, 0, 0),
            ("15", "5664", "electricity", "online", site_map["Petersfield"], 45175, 46395, 0, 0),
            ("16", "1158", "electricity", "online", site_map["Petersfield"], 0, 76162, 0, 0),
            ("17", "-", "electricity", "online", site_map["Petersfield"], 1679, 1712, 0, 0),
            ("17", "8402", "electricity", "online", site_map["Petersfield"], 37574, 37938, 0, 0),
            ("18", "-", "electricity", "online", site_map["Petersfield"], 2190, 2197, 0, 0),
            ("18", "758", "electricity", "online", site_map["Petersfield"], 55482, 55851, 0, 0),
            ("19", "879", "electricity", "online", site_map["Petersfield"], 1550, 1569, 0, 0),
            ("19", "517", "electricity", "online", site_map["Petersfield"], 48466, 48948, 0, 0),
            ("20", "-", "electricity", "online", site_map["Petersfield"], 1328, 1356, 0, 0),
            ("20", "261", "electricity", "online", site_map["Petersfield"], 55956, 57380, 0, 0),
            ("21", "-", "electricity", "online", site_map["Petersfield"], 1458, 1487, 0, 0),
            ("21", "7461", "electricity", "online", site_map["Petersfield"], 50415, 51428, 0, 0),
            ("22", "27", "electricity", "online", site_map["Petersfield"], 92837, 93506, 0, 0),
            ("23", "-", "electricity", "online", site_map["Petersfield"], 894, 0, 0, 0),
            ("23", "7187", "electricity", "online", site_map["Petersfield"], 0, 54190, 0, 0),
            ("24", "4481", "electricity", "online", site_map["Petersfield"], 0, 51178, 0, 0),
            ("25", "4846", "electricity", "online", site_map["Petersfield"], 0, 76552, 0, 0),
            ("25", "-", "electricity", "online", site_map["Petersfield"], 1422, 1437, 0, 0),
            ("26", "380", "electricity", "online", site_map["Petersfield"], 3037, 3065, 0, 0),
            ("26", "6463", "electricity", "online", site_map["Petersfield"], 39455, 40604, 0, 0),
            ("27", "798", "electricity", "online", site_map["Petersfield"], 4000, 4028, 0, 0),
            ("27", "7112", "electricity", "online", site_map["Petersfield"], 95630, 96880, 0, 0),
            ("28", "3610", "electricity", "online", site_map["Petersfield"], 34570, 34982, 0, 0),
            ("28", "994", "electricity", "online", site_map["Petersfield"], 0, 903, 0, 0),
            ("29", "1039", "electricity", "online", site_map["Petersfield"], 694, 701, 0, 0),
            ("29", "3407", "electricity", "online", site_map["Petersfield"], 28103, 28445, 0, 0),
            ("30", "1295", "electricity", "online", site_map["Petersfield"], 1023, 1044, 0, 0),
            ("30", "9744", "electricity", "online", site_map["Petersfield"], 27701, 28167, 0, 0),
            ("31", "8632", "electricity", "online", site_map["Petersfield"], 623, 637, 0, 0),
            ("31", "3077", "electricity", "online", site_map["Petersfield"], 15118, 15509, 0, 0),
            ("32", "9706", "electricity", "online", site_map["Petersfield"], 731, 751, 0, 0),
            ("32", "1853", "electricity", "online", site_map["Petersfield"], 30221, 31348, 0, 0),
            ("33", "6165", "electricity", "online", site_map["Petersfield"], 941, 958, 0, 0),
            ("33", "7840", "electricity", "online", site_map["Petersfield"], 32741, 33576, 0, 0),
            ("34", "7484", "electricity", "online", site_map["Petersfield"], 1797, 1834, 0, 0),
            ("34", "4392", "electricity", "online", site_map["Petersfield"], 48571, 49905, 0, 0),
            ("35", "6169", "electricity", "online", site_map["Petersfield"], 248, 251, 0, 0),
            ("35", "Lear", "electricity", "online", site_map["Petersfield"], 0, 3598, 0, 0),
            ("36", "6158", "electricity", "online", site_map["Petersfield"], 817, 832, 0, 0),
            ("36", "6742", "electricity", "online", site_map["Petersfield"], 33023, 33661, 0, 0),
            ("Bulk W", "7103", "water", "online", site_map["Petersfield"], 22911, 23573, 0, 0),
            ("-", "6913", "water", "online", site_map["Petersfield"], 2366, 2380, 0, 0),
            ("-", "6952", "water", "online", site_map["Petersfield"], 3061, 3096, 0, 0),
            ("-", "7316", "water", "online", site_map["Petersfield"], 1458, 1461, 0, 0),
            ("-", "442", "water", "online", site_map["Petersfield"], 1143, 1152, 0, 0),
            ("-", "336", "water", "online", site_map["Petersfield"], 2502, 2510, 0, 0),
            ("-", "7491", "water", "online", site_map["Petersfield"], 2164, 2180, 0, 0),
            ("-", "1330", "water", "online", site_map["Petersfield"], 0, 2779, 0, 0),
            ("-", "3560", "water", "online", site_map["Petersfield"], 315, 341, 0, 0),
            ("-", "2332", "water", "online", site_map["Petersfield"], 1768, 1772, 0, 0),
            ("-", "596", "water", "online", site_map["Petersfield"], 1830, 145, 0, 0),
            ("-", "6", "water", "online", "online", site_map["Petersfield"], 2965, 3001, 0, 0),
            ("-", "5402", "water", "online", site_map["Petersfield"], 630, 634, 0, 0),
            ("-", "6656", "water", "online", site_map["Petersfield"], 142, 0, 0, 0),
            ("-", "6916", "water", "online", site_map["Petersfield"], 2036, 2052, 0, 0),
            ("-", "2332", "water", "online", site_map["Petersfield"], 1768, 0, 0, 0),
            ("-", "-", "water", "online", site_map["Petersfield"], 0, 2988, 3012, 0),
            ("Common property E", "3728", "water", "online", site_map["Petersfield"], 9820, 9967, 0, 0),
            # Majuteni
            ("2976", "2976", "electricity", "online", site_map["Majuteni"], 32415, 32415, 32416, 32416),
            ("2379", "2379", "electricity", "online", site_map["Majuteni"], 7213790, 7252109, 7287437, 7320080),
            ("2358", "2358", "electricity", "online", site_map["Majuteni"], 9860099, 9892923, 9922678, 9953079),
            ("5477", "5477", "electricity", "offline", site_map["Majuteni"], 0, 0, 0, 0),
            ("2363", "2363", "electricity", "offline", site_map["Majuteni"], 0, 0, 0, 0),
            ("5321", "5321", "electricity", "online", site_map["Majuteni"], 29010, 29015, 29067, 29146),
            ("1000", "1000", "electricity", "online", site_map["Majuteni"], 21928, 21928, 21928, 21928),
            ("Lear", "2979", "electricity", "online", site_map["Majuteni"], 2979, 2979, 2979, 2979),
            ("Lear", "6695", "electricity", "online", site_map["Majuteni"], 6695, 6695, 6695, 6695),
            ("Lear", "37939", "electricity", "online", site_map["Majuteni"], 37939, 37930, 37940, 37941),
            ("Lear(outside lights)", "8364", "electricity", "online", site_map["Majuteni"], 0, 8741, 9007, 0),
            ("6188", "6188", "electricity", "online", site_map["Majuteni"], 62792, 62820, 62880, 62939),
            ("4377", "4377", "electricity", "online", site_map["Majuteni"], 19707, 19791, 20123, 20802),
            ("3976", "3976", "water", "online", site_map["Majuteni"], 1037, 1037, 1037, 1037),
            ("3971", "3971", "water", "online", site_map["Majuteni"], 252, 255, 258, 262),
            ("3974", "3974", "water", "online", site_map["Majuteni"], 595, 696, 780, 895),
            ("3975", "3975", "water", "online", site_map["Majuteni"], 2600, 2604, 2612, 2615),
            ("3982", "3982", "water", "online", site_map["Majuteni"], 4184, 4187, 4191, 4194),
            ("3977", "3977", "water", "online", site_map["Majuteni"], 3093, 3094, 3095, 3095),
            ("3969", "3969", "water", "online", site_map["Majuteni"], 64, 64, 64, 64),
            ("142", "142", "water", "online", site_map["Majuteni"], 72, 84, 92, 93),
            ("3978", "3978", "water", "online", site_map["Majuteni"], 63, 63, 63, 63),
            ("3968", "3968", "water", "online", site_map["Majuteni"], 926, 928, 939, 941),
            ("3972", "3972", "water", "online", site_map["Majuteni"], 321, 322, 323, 326),
            ("3970", "3970", "water", "online", site_map["Majuteni"], 1645, 1650, 1654, 1658),
            ("3973", "3973", "water", "online", site_map["Majuteni"], 488, 488, 488, 488),
            ("6879", "6879", "electricity", "online", site_map["Majuteni"], 759156, 760004, 760869, 76174),
            ("5334", "5334", "electricity", "online", site_map["Majuteni"], 147961, 153768, 159992, 165847),
            ("6159", "6159", "electricity", "online", site_map["Majuteni"], 486753, 487681, 488796, 490255),
            ("909", "909", "electricity", "online", site_map["Majuteni"], 62004, 62004, 62004, 62004),
            ("1577", "1577", "electricity", "online", site_map["Majuteni"], 418147, 418147, 418147, 418147),
            ("2002", "2002", "electricity", "online", site_map["Majuteni"], 8849, 8849, 8849, 8849),
            ("2359", "2359", "electricity", "online", site_map["Majuteni"], 4252997, 4270173, 4286440, 4301029),
            # Lakefield
            ("5672", "5672", "electricity", "online", site_map["Lakefield"], 159604, 159851, 160116, 160338),
            ("2472", "2472", "electricity", "online", site_map["Lakefield"], 90, 145, 210, 267),
            ("6039", "6039", "electricity", "online", site_map["Lakefield"], 48642, 48678, 48757, 48758),
            ("5673", "5673", "electricity", "online", site_map["Lakefield"], 41398, 41430, 41466, 41516),
            ("5671", "5671", "electricity", "online", site_map["Lakefield"], 11910, 11910, 11910, 11912),
            ("Lear", "1875", "electricity", "online", site_map["Lakefield"], 1875, 2056, 2280, 2479),
            ("2398", "2398", "electricity", "online", site_map["Lakefield"], 2, 8, 38, 75),
            ("6037", "6037", "electricity", "online", site_map["Lakefield"], 77630, 77732, 77823, 77963),
            ("6039", "6039", "electricity", "online", site_map["Lakefield"], 70509, 70638, 70771, 70891),
            ("6040", "6040", "electricity", "online", site_map["Lakefield"], 41271, 41437, 41605, 41799),
            ("7020", "7020", "electricity", "online", site_map["Lakefield"], 56649, 57240, 57886, 58493),
            ("2432", "2432", "electricity", "online", site_map["Lakefield"], 88, 177, 268, 334),
            ("7022", "7022", "electricity", "online", site_map["Lakefield"], 70605, 70700, 70740, 70766),
            ("7019", "7019", "electricity", "online", site_map["Lakefield"], 92000, 92614, 93342, 94085),
            ("7023", "7023", "electricity", "online", site_map["Lakefield"], 79620, 79904, 80088, 80671),
            ("2502", "2502", "electricity", "online", site_map["Lakefield"], 0, 0, 363, 478),
            ("4393", "4393", "electricity", "online", site_map["Lakefield"], 2543, 2632, 2736, 2866),
            ("7021", "7021", "electricity", "online", site_map["Lakefield"], 39971, 40013, 40314, 40700),
            ("1485", "1485", "electricity", "online", site_map["Lakefield"], 189978, 190899, 192190, 194027),
            ("4552", "4552", "electricity", "online", site_map["Lakefield"], 209707, 210977, 212136, 215778),
            ("2784", "2784", "electricity", "offline", site_map["Lakefield"], 171750, 171750, 0, 0),
            ("9980", "9980", "electricity", "online", site_map["Lakefield"], 50370, 51540, 52759, 54111),
            ("2461", "2461", "electricity", "online", site_map["Lakefield"], 159441, 159441, 159441, 159441),
            ("2479", "2479", "electricity", "online", site_map["Lakefield"], 487720, 482903, 485274, 488085),
            ("2446", "2446", "electricity", "online", site_map["Lakefield"], 258738, 261360, 265234, 270286),
            ("2487", "2487", "electricity", "online", site_map["Lakefield"], 262443, 263913, 265875, 270308),
            ("9579", "9579", "water", "online", site_map["Lakefield"], 6254, 6399, 6573, 6753),
            ("8955", "8955", "water", "online", site_map["Lakefield"], 3827, 3926, 4066, 4194),
            ("-", "6537", "water", "online", site_map["Lakefield"], 0, 6539, 6601, 6669),
            ("-", "12095", "water", "online", site_map["Lakefield"], 0, 12759, 12887, 12911),
            # Albert court
            ("5546", "5546", "electricity", "online", site_map["Albert court"], 1118, 1125, 1133, 1139),
            ("5553", "5553", "electricity", "online", site_map["Albert court"], 827, 830, 834, 839),
            ("5787", "5787", "electricity", "online", site_map["Albert court"], 1391, 1400, 1408, 1421),
            ("5761", "5761", "electricity", "online", site_map["Albert court"], 911, 919, 927, 938),
            ("5815", "5815", "electricity", "online", site_map["Albert court"], 650, 655, 659, 663),
            ("5798", "5798", "electricity", "online", site_map["Albert court"], 1649, 1663, 1673, 1684),
            ("5482", "5482", "electricity", "online", site_map["Albert court"], 4362, 4374, 4386, 4398),
            ("5494", "5494", "electricity", "online", site_map["Albert court"], 742, 748, 753, 756),
            ("5386", "5386", "electricity", "online", site_map["Albert court"], 1005, 1012, 1013, 1013),
            ("5385", "5385", "electricity", "online", site_map["Albert court"], 1211, 1224, 1239, 1256),
            ("6141", "6141", "electricity", "online", site_map["Albert court"], 1499, 1505, 1512, 1519),
            ("Bulk water", "Bulk water", "water", "online", site_map["Albert court"], 0, 1696, 2581, 3523),
            # North rand road
            ("5691", "5691", "electricity", "offline", site_map["North rand road"], 0, 0, 0, 0),
            ("7505", "7505", "electricity", "online", site_map["North rand road"], 1, 1, 1, 1),
            ("3782", "3782", "electricity", "online", site_map["North rand road"], 10, 10, 10, 10),
            ("7456", "7456", "electricity", "online", site_map["North rand road"], 165, 168, 171, 175),
            ("991", "991", "electricity", "online", site_map["North rand road"], 6659, 6823, 6975, 7152),
            ("927", "927", "electricity", "online", site_map["North rand road"], 2149, 2165, 2183, 2204),
            ("7450", "7450", "electricity", "online", site_map["North rand road"], 878, 879, 883, 893),
            ("3213", "3213", "electricity", "online", site_map["North rand road"], 739, 754, 763, 775),
            ("7458", "7458", "electricity", "online", site_map["North rand road"], 17, 15, 18, 18),
            ("1915", "1915", "electricity", "online", site_map["North rand road"], 96, 96, 96, 96),
            ("7448", "7448", "electricity", "online", site_map["North rand road"], 80, 82, 84, 85),
            ("7444", "7444", "electricity", "online", site_map["North rand road"], 63, 69, 75, 82),
            ("1440", "1440", "electricity", "online", site_map["North rand road"], 43, 44, 44, 44),
            ("7442", "7442", "electricity", "online", site_map["North rand road"], 3877, 3938, 3993, 4061),
            ("933", "933", "electricity", "online", "online", site_map["North rand road"], 6946, 7074, 7215, 7472),
            ("Bulk water 7142", "7142", "water", "online", site_map["North rand road"], 27104, 27535, 27967, 28464),
            ("Kota joe", "4311", "electricity", "online", site_map["North rand road"], 111431, 112213, 113240, 0),
            ("Kwik fit", "4223", "electricity", "online", site_map["North rand road"], 246968, 249575, 252779, 0),
            ("-", "9886", "electricity", "online", site_map["North rand road"], 392592, 397992, 3902728, 0),
            ("Restaurant", "4249", "electricity", "online", site_map["North rand road"], 697689, 701293, 705282, 0),
            ("Kota joe", "4256", "electricity", "online", site_map["North rand road"], 2315996, 2344336, 2376461, 0),
            ("Bulk", "9221", "electricity", "online", site_map["North rand road"], 68252, 68672, 69172, 0),
            ("Bulk", "9225", "electricity", "online", site_map["North rand road"], 8649, 8769, 9075, 0),
            # Constance place
            ("Bulk water", "8756w", "water", "online", site_map["Constance place"], 2098, 2268, 0, 0),
            ("2706w", "2706w", "water", "online", site_map["Constance place"], 289, 295, 0, 0),
            ("7666w", "7666w", "water", "online", site_map["Constance place"], 745, 768, 0, 0),
            ("3257w", "3257w", "water", "offline", site_map["Constance place"], 0, 0, 0, 0),
            ("0458w", "0458w", "water", "online", site_map["Constance place"], 7391, 7423, 0, 0),
            ("3256w", "3256w", "water", "online", site_map["Constance place"], 183, 183, 0, 0),
            ("530w", "530w", "water", "online", site_map["Constance place"], 4829, 4838, 0, 0),
            ("3514w", "3514w", "water", "online", site_map["Constance place"], 1346, 1350, 0, 0),
            ("206w", "206w", "water", "online", site_map["Constance place"], 4947, 0, 0, 0),
            ("4682w", "4682w", "water", "online", site_map["Constance place"], 34, 36, 0, 0),
            ("Edge Digital Print", "9382", "electricity", "online", site_map["Constance place"], 212761, 214316, 216016, 0),
            ("CBD Health & Suppliments", "4431", "electricity", "online", site_map["Constance place"], 48158, 48327, 48502, 0),
            ("DJ M Projects", "4942", "electricity", "online", site_map["Constance place"], 57355, 57740, 58109, 0),
            ("Constance corner fish & chips", "3383", "electricity", "online", site_map["Constance place"], 27955, 28685, 29433, 0),
            ("Printing Shop", "3114", "electricity", "online", site_map["Constance place"], 0, 0, 0, 0),
            ("Garage", "4743", "electricity", "online", site_map["Constance place"], 0, 31920, 43667, 0),
            ("Hairdresser", "4431", "electricity", "online", site_map["Constance place"], 539546, 539549, 539572, 0),
            ("Office 6", "4386", "electricity", "online", site_map["Constance place"], 11225, 11230, 11238, 0),
            ("Office 1", "4427", "electricity", "online", site_map["Constance place"], 3137, 3137, 3145, 0),
            ("Office 2", "4934", "electricity", "online", site_map["Constance place"], 15658, 15698, 15725, 0),
            ("Office 3", "4678", "electricity", "online", site_map["Constance place"], 7673, 7673, 7673, 0),
            ("Office 4", "4626", "electricity", "online", site_map["Constance place"], 4537, 4538, 4543, 0),
            ("Office 5", "4930", "electricity", "online", site_map["Constance place"], 13163, 13163, 13163, 0),
            ("Office 6", "4635", "electricity", "online", site_map["Constance place"], 24367, 30352, 30355, 0),
            ("Office 7", "4625", "electricity", "online", site_map["Constance place"], 24291, 24439, 24517, 0),
            ("Kingdom church", "4934", "electricity", "online", site_map["Constance place"], 20670, 15698, 0, 0),
            ("Kingdom church (Office15)", "5232", "electricity", "online", site_map["Constance place"], 2082, 2094, 2109, 0),
            ("Kingdom church (Office16)", "4519", "electricity", "online", site_map["Constance place"], 1464, 1464, 1464, 0),
            ("Kingdom church", "3136", "electricity", "online", site_map["Constance place"], 14908, 14913, 14918, 0),
            ("Office 7", "4338", "electricity", "online", site_map["Constance place"], 2612, 2612, 2613, 0),
            ("Office 8", "4384", "electricity", "online", site_map["Constance place"], 18122, 18122, 18122, 0),
            ("Office 8", "4460", "electricity", "online", site_map["Constance place"], 5850, 5850, 5850, 0),
            ("Office 9", "4371", "electricity", "online", site_map["Constance place"], 1186, 1186, 1186, 0),
            ("Office 10", "4543", "electricity", "online", site_map["Constance place"], 524, 524, 524, 0),
            ("Office 11", "4328", "electricity", "online", site_map["Constance place"], 3868, 3836, 3868, 0),
            ("Office 12", "4408", "electricity", "online", site_map["Constance place"], 98790, 98790, 98790, 0),
            ("Office 1 Vacant", "4298", "electricity", "online", site_map["Constance place"], 23853, 23853, 23858, 0),
            ("Office 2", "4899", "electricity", "online", site_map["Constance place"], 1552, 1552, 1552, 0),
            ("Office 13", "4825", "electricity", "online", site_map["Constance place"], 20690, 20704, 20718, 0),
            ("Office 14", "4871", "electricity", "online", site_map["Constance place"], 4005, 4005, 4005, 0),
            ("Shop 13 Philandria 6", "2174", "electricity", "online", site_map["Constance place"], 77958, 78325, 78446, 0),
            ("Philandria", "2503", "electricity", "online", site_map["Constance place"], 8505, 8587, 8994, 0),
            ("PVT Vacant", "4392", "electricity", "online", site_map["Constance place"], 24048, 24048, 24048, 0),
            ("PVT Unit 8 Vacant", "4605", "electricity", "online", site_map["Constance place"], 25230, 44554, 25417, 0),
            ("PVT Vacant", "4534", "electricity", "online", site_map["Constance place"], 14251, 14251, 14251, 0),
            ("Office 3 Vacant", "4856", "electricity", "online", site_map["Constance place"], 22205, 22205, 22205, 0),
            ("Unit 12 Vacant", "4602", "electricity", "online", site_map["Constance place"], 51132, 51132, 51132, 0),
            ("Unit 13 Vacant", "4486", "electricity", "online", site_map["Constance place"], 67845, 67914, 67929, 0),
            ("office net 14 +13", "4374", "electricity", "online", site_map["Constance place"], 54198, 54289, 54404, 0),
            ("Dr MUKENDI NGALAMULUME", "2340", "electricity", "online", site_map["Constance place"], 539549, 539562, 0, 0),
            ("Unit 14 Vacant", "7535", "electricity", "online", site_map["Constance place"], 3589, 3589, 3589, 0),
            ("SALVAGE DUCKS(empty)", "3373", "electricity", "online", site_map["Constance place"], 15301, 13076, 13077, 0),
            ("Office 14", "4909", "electricity", "online", site_map["Constance place"], 17964, 17964, 17964, 0),
            ("Vacant", "4865", "electricity", "online", site_map["Constance place"], 8155, 8155, 8155, 0),
            ("Car Wash 999", "4852", "electricity", "online", site_map["Constance place"], 30914, 31191, 31405, 0),
            ("Unit 9 Maktub", "4608", "electricity", "online", site_map["Constance place"], 44554, 44554, 44554, 0),
            ("Unit 11 Maktub", "4380", "electricity", "online", site_map["Constance place"], 23731, 23801, 23802, 0),
            ("Public Lights", "2160", "electricity", "online", site_map["Constance place"], 33693, 33713, 33736, 0),
            ("Public Lights", "974", "electricity", "online", site_map["Constance place"], 12530, 12764, 13022, 0),
            ("Public Lights", "4550", "electricity", "online", site_map["Constance place"], 69138, 69270, 69466, 0),
            ("Public Lights", "4929", "electricity", "online", site_map["Constance place"], 55335, 55545, 55762, 0),
            ("Bulk E", "0", "electricity", "online", site_map["Constance place"], 0, 56457, 0, 0),
            ("Bulk", "8756w", "water", "online", site_map["Constance place"], 2268, 2397, 2544, 0),
            ("Elashadda, Kyk & Leer Shop 5", "2706w", "water", "online", site_map["Constance place"], 295, 300, 304, 0),
            ("DJ M Projects", "7666w", "water", "online", site_map["Constance place"], 768, 787, 807, 0),
            ("Harvest Shop 101", "0458w", "water", "online", site_map["Constance place"], 7423, 7467, 7510, 0),
            ("Edge digital", "3256w", "water", "online", site_map["Constance place"], 183, 183, 183, 0),
            ("Public Toilets", "530w", "water", "online", site_map["Constance place"], 4838, 4848, 4861, 0),
            ("Edge digital", "3514w", "water", "online", site_map["Constance place"], 1350, 1356, 1361, 0),
            ("Car Wash", "206w", "water", "online", site_map["Constance place"], 36, 5005, 5034, 0),
            # Welcome centre
            ("9306", "9306", "electricity", "online", site_map["Welcome centre"], 23, 0, 0, 0),
            ("1707", "1707", "electricity", "online", site_map["Welcome centre"], 45, 0, 0, 0),
            ("1837", "1837", "electricity", "online", site_map["Welcome centre"], 12, 0, 0, 0),
            ("9318", "9318", "electricity", "online", site_map["Welcome centre"], 130, 0, 0, 0),
            ("9314", "9314", "electricity", "online", site_map["Welcome centre"], 95, 0, 0, 0),
            ("1820", "1820", "electricity", "online", site_map["Welcome centre"], 77, 0, 0, 0),
            ("1832", "1832", "electricity", "online", site_map["Welcome centre"], 115, 0, 0, 0),
            ("1804", "1804", "electricity", "online", site_map["Welcome centre"], 86, 0, 0, 0),
            ("780", "780", "electricity", "online", site_map["Welcome centre"], 15122, 0, 0, 0),
            ("8737", "8737", "electricity", "online", site_map["Welcome centre"], 6105, 0, 0, 0),
            ("6311", "6311", "electricity", "online", site_map["Welcome centre"], 234, 0, 0, 0),
            ("1657", "1657", "electricity", "online", site_map["Welcome centre"], 6212, 0, 0, 0),
            ("1665", "1665", "electricity", "online", site_map["Welcome centre"], 1728, 0, 0, 0),
            ("4199", "4199", "electricity", "online", site_map["Welcome centre"], 1943, 0, 0, 0),
            ("919", "919", "electricity", "online", site_map["Welcome centre"], 23740, 0, 0, 0),
            # Kalan hira
            ("0251(W)", "0251(W)", "water", "online", site_map["Kalan hira"], 2156, 2200, 2236, 2278),
            ("6843(W Bulk)", "6843(W Bulk)", "water", "online", site_map["Kalan hira"], 6410, 6545, 6649, 6775),
            ("4998(Check E)", "4998(Check E)", "electricity", "online", site_map["Kalan hira"], 44944, 54512, 62840, 72593),
            ("3944", "3944", "electricity", "online", site_map["Kalan hira"], 28606, 29308, 30174, 30752),
            ("378", "378", "electricity", "online", site_map["Kalan hira"], 44897, 45602, 46473, 46888),
            ("8439", "8439", "electricity", "online", site_map["Kalan hira"], 60295, 60295, 60295, 60295),
            ("6547", "6547", "electricity", "online", site_map["Kalan hira"], 43702, 43772, 43852, 43883),
            ("1136", "1136", "electricity", "online", site_map["Kalan hira"], 77011, 77030, 77045, 77062),
            ("1136", "1136", "electricity", "online", site_map["Kalan hira"], 22129, 22148, 22161, 22178),
            ("1136", "1136", "electricity", "online", site_map["Kalan hira"], 40477, 40492, 40502, 40514),
            ("9973", "9973", "electricity", "online", site_map["Kalan hira"], 2285, 2285, 2285, 2287),
            ("9973", "9973", "electricity", "online", site_map["Kalan hira"], 168821, 168823, 168851, 168946),
            ("9973", "9973", "electricity", "online", site_map["Kalan hira"], 27791, 27791, 27791, 27791),
            ("88", "88", "electricity", "online", site_map["Kalan hira"], 49256, 49264, 49273, 49294),
            ("88", "88", "electricity", "online", site_map["Kalan hira"], 50121, 50121, 50121, 50121),
            ("88", "88", "electricity", "online", site_map["Kalan hira"], 35449, 35449, 35449, 35449),
            ("4248", "4248", "electricity", "online", site_map["Kalan hira"], 26429, 26717, 26960, 27322),
            ("3611", "3611", "electricity", "online", site_map["Kalan hira"], 63300, 63385, 63466, 63529),
            ("62", "62", "electricity", "online", site_map["Kalan hira"], 166279, 166279, 166279, 166279),
            ("62", "62", "electricity", "online", site_map["Kalan hira"], 74482, 74482, 74482, 74483),
            ("62", "62", "electricity", "online", site_map["Kalan hira"], 74080, 74080, 74132, 74146),
            ("honeywell", "841", "electricity", "online", site_map["Kalan hira"], 1115, 1300, 1673, 0),
            ("2480", "2480", "electricity", "online", site_map["Kalan hira"], 405217, 405929, 406532, 406894),
            ("2779", "2779", "electricity", "online", site_map["Kalan hira"], 38409, 38412, 38428, 38470),
            ("70", "70", "electricity", "online", site_map["Kalan hira"], 190568, 190587, 190601, 190634),
            ("70", "70", "electricity", "online", site_map["Kalan hira"], 117261, 117328, 117376, 117446),
            ("70", "70", "electricity", "online", site_map["Kalan hira"], 172988, 173033, 173065, 173159),
            ("54", "54", "electricity", "online", site_map["Kalan hira"], 299592, 299695, 299759, 299930),
            ("54", "54", "electricity", "online", site_map["Kalan hira"], 21354, 21354, 21354, 21354),
            ("54", "54", "electricity", "online", site_map["Kalan hira"], 40566, 40566, 40566, 40566),
            ("2291", "2291", "electricity", "online", site_map["Kalan hira"], 21232, 220501, 226424, 233013),
            ("6699", "6699", "electricity", "online", site_map["Kalan hira"], 683155, 685629, 688574, 692573),
            # Safeway centre
            ("2405", "2405", "water", "online", site_map["Safeway centre"], 6056, 6116, 6176, 6244),
            ("2402", "2402", "water", "online", site_map["Safeway centre"], 1085, 1099, 1112, 1127),
            ("2409", "2409", "water", "online", site_map["Safeway centre"], 3157, 3188, 3205, 3230),
            ("2401", "2401", "water", "online", site_map["Safeway centre"], 1847, 1874, 1901, 1928),
            ("2404", "2404", "water", "online", site_map["Safeway centre"], 136, 136, 136, 144),
            ("2406", "2406", "water", "online", site_map["Safeway centre"], 256, 259, 262, 264),
            ("795", "795", "water", "online", site_map["Safeway centre"], 1161, 1174, 1188, 1201),
            ("796", "796", "water", "online", site_map["Safeway centre"], 1359, 1359, 1360, 1365),
            ("799", "799", "water", "online", site_map["Safeway centre"], 677, 690, 701, 716),
            ("2411", "2411", "water", "online", site_map["Safeway centre"], 0, 470, 479, 487),
            ("2412", "2412", "water", "online", site_map["Safeway centre"], 405, 412, 417, 427),
            ("2418", "2418", "water", "online", site_map["Safeway centre"], 429, 438, 446, 456),
            ("2408", "2408", "water", "online", site_map["Safeway centre"], 702, 709, 717, 725),
            ("2407", "2407", "water", "online", site_map["Safeway centre"], 952, 965, 977, 989),
            ("Bulk water", "Bulk water", "water", "online", site_map["Safeway centre"], 34344, 34755, 35139, 35570),
            ("Public lights", "8185", "electricity", "online", site_map["Safeway centre"], 9941, 10007, 10082, 0),
            ("Plus express", "6462", "electricity", "online", site_map["Safeway centre"], 13837, 14055, 14283, 0),
            ("Black pearl", "Black pearl", "electricity", "offline", site_map["Safeway centre"], 0, 0, 0, 0),
            ("Hair salon", "3737", "electricity", "faulty", site_map["Safeway centre"], 0, 178, 369, 0),
            ("Liquor store", "9532", "electricity", "online", site_map["Safeway centre"], 125307, 128448, 131639, 0),
            ("Asian shop", "9662", "electricity", "online", site_map["Safeway centre"], 48495, 49497, 505606, 0),
            ("Shop 2", "Lear", "electricity", "online", site_map["Safeway centre"], 0, 0, 0, 0),
            ("-", "Lear", "electricity", "online", site_map["Safeway centre"], 0, 0, 0, 0),
            ("-", "Lear", "electricity", "online", site_map["Safeway centre"], 0, 8, 319, 0),
            # Siyadumisa
            ("Workshop", "9602", "water", "online", site_map["Siyadumisa"], 2455, 2413, 2477, 0),
            ("-", "9610", "water", "online", site_map["Siyadumisa"], 365, 383, 398, 0),
            ("Ebenezer", "9605", "water", "online", site_map["Siyadumisa"], 919, 933, 945, 0),
            ("-", "1981", "water", "online", site_map["Siyadumisa"], 3162, 3222, 3242, 0),
            ("Tyre factory", "9608", "water", "online", site_map["Siyadumisa"], 1741, 1874, 2046, 0),
            ("Bulk", "5535", "water", "online", site_map["Siyadumisa"], 9215, 9574, 9952, 0),
            ("Main 1", "4749", "electricity", "online", site_map["Siyadumisa"], 699345, 700558, 702406, 0),
            ("Workshop", "3248", "electricity", "online", site_map["Siyadumisa"], 229945, 232957, 236968, 0),
            ("Spare", "9599", "electricity", "offline", site_map["Siyadumisa"], 0, 0, 0, 0),
            ("Fitment centre", "9565", "electricity", "online", site_map["Siyadumisa"], 287252, 288388, 289713, 0),
            ("Factory Ronnie", "6116", "electricity", "online", site_map["Siyadumisa"], 24570, 25439, 26024, 0),
            ("Ebenezer", "9664", "electricity", "online", site_map["Siyadumisa"], 410128, 411962, 413670, 0),
            ("Storeroom", "6306", "electricity", "online", site_map["Siyadumisa"], 2409, 2425, 2438, 0),
            ("Main 2", "4731", "electricity", "online", site_map["Siyadumisa"], 1467650, 1472434, 1481212, 0),
            ("DTS", "9654", "electricity", "online", site_map["Siyadumisa"], 100818, 103105, 106247, 0),
            ("Bus", "9557", "electricity", "online", site_map["Siyadumisa"], 23729, 29009, 34281, 0)
        ]

        for entry in meter_readings:
            identifier, meter_num, meter_type, status, site_id = entry[:5]
            readings_vals = entry[5:]
            last_reading = next((r for r in reversed(readings_vals) if r != 0), 0)
            meter_data.append((site_id, meter_num, meter_type, status, 1800, last_reading))

        # Batch insert meters
        db_manager.conn.executemany(
            "INSERT OR IGNORE INTO meters (site_id, identifier, meter_type, status, base_threshold, last_reading) VALUES (?, ?, ?, ?, ?, ?)",
            meter_data
        )
        db_manager.conn.commit()

        # Get meter ids
        site_meter_map = {}
        for row in db_manager.query_all("SELECT id, site_id, identifier FROM meters"):
            site_meter_map[(row['site_id'], row['identifier'])] = row['id']

        # Prepare readings
        for entry in meter_readings:
            identifier, meter_num, meter_type, status, site_id = entry[:5]
            readings_vals = entry[5:]
            meter_id = site_meter_map.get((site_id, meter_num))
            if meter_id:
                readings_list = list(readings_vals)
                for i, value in enumerate(readings_list):
                    if value != 0 and value is not None:
                        reading_status = 'normal'
                        if i > 0 and readings_list[i-1] != 0:
                            prev = readings_list[i-1]
                            if value > prev * 1.2:
                                reading_status = 'critical'
                            elif value > prev * 1.1:
                                reading_status = 'warning'
                        reading_data.append((meter_id, value, dates[i], reading_status, None, 'Imported from Excel'))

        # Batch insert readings
        if reading_data:
            db_manager.conn.executemany(
                "INSERT INTO readings (meter_id, reading_value, reading_date, status, photo_url, comments) VALUES (?, ?, ?, ?, ?, ?)",
                reading_data
            )
            db_manager.conn.commit()

init_db()

# Simulated OTP storage
otp_storage = {}

def verify_token(token):
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return str(decoded['user_id'])  # Ensure user_id is string
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

@app.route('/')
def serve_index():
    return send_from_directory('.', 'index.html')

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        email = data.get('email')
        password = data.get('password')
        if not email or not password:
            return jsonify({'error': 'Missing email or password'}), 400
        
        if auth_service.login(email, password):
            user_id = str(auth_service.get_current_user_id())  # Convert to string
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
    user_id = str(data.get('user_id'))  # Convert to string
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
    
@app.route('/api/readings/<int:reading_id>', methods=['GET'])
def get_reading_details(reading_id):
    token = request.headers.get('Authorization')
    if not verify_token(token):
        return jsonify({'error': 'Unauthorized'}), 401
    
    # Query for the specific reading, joining with meters and sites to get names
    reading = db_manager.query_one("""
        SELECT r.id, r.reading_value, r.reading_date, r.status, r.photo_url, r.comments, r.approved,
               m.identifier as meter_identifier, s.name as site_name
        FROM readings r
        JOIN meters m ON r.meter_id = m.id
        JOIN sites s ON m.site_id = s.id
        WHERE r.id = ?
    """, (reading_id,))
    
    if not reading:
        return jsonify({'error': 'Reading not found'}), 404
        
    return jsonify(dict(reading))

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
    
    # Threshold calculation
    if meter['meter_type'] == 'electricity':
        historical_data = [
            row['reading_value'] for row in db_manager.query_all(
                "SELECT reading_value FROM readings WHERE meter_id=? ORDER BY reading_date DESC LIMIT 10",
                (meter_id,)
            )
        ]
        threshold = dynamic_threshold(meter['meter_type'], historical_data)
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
    
    # Photo handling
    photo_url = None
    if 'photo' in request.files:
        photo = request.files['photo']
        filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{photo.filename}"
        photo_path = f"uploads/{filename}"
        os.makedirs('uploads', exist_ok=True)
        photo.save(photo_path)
        photo_url = f"/uploads/{filename}"
    
    # Create reading
    reading_id = db_manager.execute_commit(
        """INSERT INTO readings (meter_id, reading_value, reading_date, status, photo_url, comments)
        VALUES (?, ?, ?, ?, ?, ?)""",
        (meter_id, reading_value, datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'), status, photo_url, comments)
    )
    
    if not reading_id:
        return jsonify({'error': 'Failed to save reading'}), 500
        
    # Update meter
    db_manager.execute_commit(
        "UPDATE meters SET last_reading=? WHERE id=?", 
        (reading_value, meter_id)
    )
    
    # Create alert if warning or critical
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
    
    # Audit log
    db_manager.log_audit(
        user_id, 
        'CREATE_READING', 
        'READING', 
        reading_id, 
        f"Value: {reading_value}, Status: {status}"
    )
    
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
    
    return jsonify({'message': 'Reading approved'})

@app.route('/api/alerts', methods=['GET'])
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
    
    return jsonify({'message': 'Alert resolved'})

@app.route('/api/sites', methods=['GET'])
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
        
    db_manager.log_audit(
        user_id, 
        'DELETE_SITE', 
        'SITE', 
        site_id
    )
    return jsonify({'message': 'Site deleted'})

@app.route('/api/users', methods=['GET'])
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
        
    db_manager.log_audit(
        requester_id, 
        'DELETE_USER', 
        'USER', 
        user_id
    )
    return jsonify({'message': 'User deleted'})

@app.route('/api/meters', methods=['GET'])
def get_meters():
    token = request.headers.get('Authorization')
    if not verify_token(token):
        return jsonify({'error': 'Unauthorized'}), 401
        
    site_id = request.args.get('site_id')
    query = "SELECT id, identifier, last_reading FROM meters WHERE status='online'"
    params = ()
    if site_id:
        query += " AND site_id=?"
        params = (site_id,)
    meters = [dict(row) for row in db_manager.query_all(query, params)]
    return jsonify(meters)

@app.route('/api/analytics/readings', methods=['GET'])
def analytics_readings():
    token = request.headers.get('Authorization')
    if not verify_token(token):
        return jsonify({'error': 'Unauthorized'}), 401
        
    start_date = request.args.get('from')
    end_date = request.args.get('to')
    
    # Convert dates to datetime ranges
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
    
    # Convert dates to datetime ranges
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
def get_audit_log():
    token = request.headers.get('Authorization')
    user_id = verify_token(token)
    if not user_id or not db_manager.has_permission(user_id, ['admin']):
        return jsonify({'error': 'Unauthorized'}), 401
        
    logs = [dict(row) for row in db_manager.query_all("SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT 100")]
    return jsonify(logs)

@app.route('/uploads/<path:filename>')
def serve_upload(filename):
    return send_from_directory('uploads', filename)

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
    
    return jsonify({'message': 'Task assigned', 'id': task_id})

@app.route('/api/tasks', methods=['GET'])
def get_tasks():
    token = request.headers.get('Authorization')
    user_id = verify_token(token)
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401
        
    decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
    role = decoded['role']
    
    query = """
        SELECT t.*, s.name as site_name, m.identifier as meter_identifier, u.full_name as technician_name
        FROM tasks t
        JOIN sites s ON t.site_id = s.id
        LEFT JOIN meters m ON t.meter_id = m.id
        JOIN users u ON t.technician_id = u.id
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
    
    decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
    role = decoded['role']

    if role == 'admin':
        # Admin can update any task
        result = db_manager.execute_commit(
            "UPDATE tasks SET status=? WHERE id=?", 
            (status, task_id)
        )
    else:
        # Technician can only update their own tasks
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
    
    return jsonify({'message': 'Task updated'})

if __name__ == '__main__':
    app.run(debug=True)
