import sqlite3
import uuid
import re
import functools
import smtplib
from email.mime.text import MIMEText
from flask import Flask, request, jsonify, render_template, g

app = Flask(__name__)
DB_NAME = "gateway.db"

# --- EMAIL CONFIGURATION ---
# ⚠️ IMPORTANT: Generate a NEW App Password since you leaked the old one.
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 465 # Changed to 465 (SSL) for better network compatibility
SMTP_EMAIL = "neeleshatom3.0@gmail.com" 
SMTP_PASSWORD = "mqsy bcvo nofz hvdp" 
ADMIN_EMAIL = "23z350@psgtech.ac.in"

def send_approval_email(username, command, request_id):
    subject = f"ACTION REQUIRED: Command Approval for {username}"
    body = f"""
    User '{username}' wants to execute:
    
    {command}
    
    This command triggered a REQUIRE_APPROVAL rule.
    Login to the gateway to approve or reject Request ID #{request_id}.
    """
    
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = SMTP_EMAIL
    msg['To'] = ADMIN_EMAIL

    print(f"🔄 Attempting to send email to {ADMIN_EMAIL}...")

    try:
        # Using SMTP_SSL for Port 465 (Better for restricted networks)
        with smtplib.SMTP_SSL(SMTP_SERVER, SMTP_PORT) as server:
            server.login(SMTP_EMAIL, SMTP_PASSWORD)
            server.sendmail(SMTP_EMAIL, ADMIN_EMAIL, msg.as_string())
        print(f"✅ Email successfully sent to {ADMIN_EMAIL}")
    except Exception as e:
        print(f"❌ EMAIL FAILED: {str(e)}")
        print("Check: 1. App Password is correct. 2. Internet connection. 3. Firewall settings.")

# --- Database Helpers ---

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DB_NAME)
        db.row_factory = sqlite3.Row 
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            api_key TEXT UNIQUE NOT NULL,
            role TEXT NOT NULL,
            credits INTEGER DEFAULT 100
        )''')
        
        cursor.execute('''CREATE TABLE IF NOT EXISTS rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pattern TEXT NOT NULL,
            action TEXT NOT NULL,
            message TEXT
        )''')
        
        cursor.execute('''CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            command_text TEXT,
            status TEXT,
            rule_matched TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS approval_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            command_text TEXT,
            status TEXT DEFAULT 'pending',
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )''')
        
        cursor.execute("SELECT count(*) FROM users")
        if cursor.fetchone()[0] == 0:
            print("Seeding DB...")
            cursor.execute("INSERT INTO users (username, api_key, role, credits) VALUES (?, ?, ?, ?)",
                           ('admin', 'admin-secret', 'admin', 9999))
            
            seed_rules = [
                (r':\(\){ :\|:& };:', 'AUTO_REJECT', 'Fork bombs are not allowed.'),
                (r'rm\s+-rf\s+/', 'AUTO_REJECT', 'Recursive root deletion is forbidden.'),
                (r'^sudo\s+.*', 'REQUIRE_APPROVAL', 'Root access requires admin approval.'), 
                (r'^(ls|cat|pwd|echo)(\s+|$)', 'AUTO_ACCEPT', 'Standard filesystem utilities.') 
            ]
            cursor.executemany("INSERT INTO rules (pattern, action, message) VALUES (?, ?, ?)", seed_rules)
            
        db.commit()

# --- Auth ---

def require_api_key(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key: return jsonify({'error': 'Missing API Key'}), 401
        
        db = get_db()
        cur = db.cursor()
        cur.execute("SELECT * FROM users WHERE api_key = ?", (api_key,))
        user = cur.fetchone()
        
        if not user: return jsonify({'error': 'Invalid API Key'}), 403
        g.user = user
        return f(*args, **kwargs)
    return decorated_function

# --- Routes ---

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/me', methods=['GET'])
@require_api_key
def get_me():
    return jsonify({'username': g.user['username'], 'role': g.user['role'], 'credits': g.user['credits']})

@app.route('/api/commands', methods=['POST'])
@require_api_key
def submit_command():
    data = request.json
    command = data.get('command_text', '').strip()
    if not command: return jsonify({'error': 'Command cannot be empty'}), 400

    db = get_db()
    cursor = db.cursor()

    # 1. Check Credits
    current_credits = g.user['credits']
    if current_credits <= 0:
        return jsonify({'status': 'rejected', 'message': 'Insufficient credits', 'new_balance': 0}), 402

    # 2. Match Rules
    cursor.execute("SELECT * FROM rules ORDER BY id ASC")
    rules = cursor.fetchall()
    
    action = "AUTO_REJECT" 
    matched_pattern = "DEFAULT_DENY"
    response_msg = "Command blocked: No matching rule found." 

    for rule in rules:
        try:
            if re.search(rule['pattern'], command):
                action = rule['action']
                matched_pattern = rule['pattern']
                response_msg = rule['message'] 
                break 
        except re.error: continue 

    # --- 3. APPROVAL LOGIC ---
    if action == 'REQUIRE_APPROVAL':
        # Check if already approved
        cursor.execute("SELECT id FROM approval_requests WHERE user_id = ? AND command_text = ? AND status = 'approved'", 
                      (g.user['id'], command))
        
        if cursor.fetchone():
            action = 'AUTO_ACCEPT' # Proceed to execute below
            response_msg = "Command executed (Approved via previous request)"
        else:
            # Check if pending
            cursor.execute("SELECT id FROM approval_requests WHERE user_id = ? AND command_text = ? AND status = 'pending'", 
                          (g.user['id'], command))
            
            if not cursor.fetchone():
                # Create Request
                cursor.execute('INSERT INTO approval_requests (user_id, command_text) VALUES (?, ?)', 
                              (g.user['id'], command))
                req_id = cursor.lastrowid
                
                # LOGGING: Record the request in audit_logs
                cursor.execute('''
                    INSERT INTO audit_logs (user_id, command_text, status, rule_matched)
                    VALUES (?, ?, 'pending_approval', ?)
                ''', (g.user['id'], command, matched_pattern))
                
                db.commit()
                send_approval_email(g.user['username'], command, req_id)
            
            return jsonify({
                'status': 'pending_approval',
                'message': 'Command paused. Admin approval requested.',
                'new_balance': current_credits
            }), 202

    # --- 4. EXECUTION LOGIC ---
    try:
        if action == 'AUTO_ACCEPT':
            new_balance = current_credits - 1
            cursor.execute("UPDATE users SET credits = ? WHERE id = ?", (new_balance, g.user['id']))
            status = 'executed'
        else:
            new_balance = current_credits
            status = 'rejected'
        
        # LOGGING: Standard logs
        cursor.execute('''
            INSERT INTO audit_logs (user_id, command_text, status, rule_matched)
            VALUES (?, ?, ?, ?)
        ''', (g.user['id'], command, status, matched_pattern))

        db.commit()

        return jsonify({
            'status': status,
            'message': response_msg,
            'new_balance': new_balance,
            'rule_matched': matched_pattern
        })

    except Exception as e:
        db.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/approvals', methods=['GET', 'POST'])
@require_api_key
def manage_approvals():
    db = get_db()
    
    # --- GET: View Requests ---
    if request.method == 'GET':
        if g.user['role'] == 'admin':
            # Admin: See ALL PENDING requests from EVERYONE (to act on them)
            # We also include the 'status' column in the select
            cur = db.execute('''
                SELECT r.id, u.username, r.command_text, r.timestamp, r.status
                FROM approval_requests r
                JOIN users u ON r.user_id = u.id
                WHERE r.status = 'pending'
                ORDER BY r.timestamp DESC
            ''')
        else:
            # Member: See ALL THEIR OWN requests (Pending, Approved, Rejected)
            cur = db.execute('''
                SELECT r.id, u.username, r.command_text, r.timestamp, r.status
                FROM approval_requests r
                JOIN users u ON r.user_id = u.id
                WHERE r.user_id = ?
                ORDER BY r.timestamp DESC
            ''', (g.user['id'],))
            
        return jsonify([dict(row) for row in cur.fetchall()])

    # --- POST: Make Decision (ADMIN ONLY) ---
    if request.method == 'POST':
        if g.user['role'] != 'admin': 
            return jsonify({'error': 'Unauthorized'}), 403

        data = request.json
        req_id = data.get('request_id')
        decision = data.get('decision') # 'approved' or 'rejected'
        
        if decision not in ['approved', 'rejected']:
            return jsonify({'error': 'Invalid decision'}), 400

        # Get request details for logging
        cur = db.execute("SELECT user_id, command_text FROM approval_requests WHERE id = ?", (req_id,))
        req_data = cur.fetchone()

        # Update Status
        db.execute("UPDATE approval_requests SET status = ? WHERE id = ?", (decision, req_id))
        
        # LOGGING: 
        if req_data:
            # 1. Log for the Admin (Action taken)
            log_msg = f"Admin {decision} request #{req_id}"
            db.execute('''
                INSERT INTO audit_logs (user_id, command_text, status, rule_matched)
                VALUES (?, ?, ?, 'ADMIN_ACTION')
            ''', (g.user['id'], f"{log_msg}: {req_data['command_text']}", decision))

            # 2. Log for the Member (So they see it in their Audit Log too)
            # This fixes "approval or rejection is not recorded on member login"
            db.execute('''
                INSERT INTO audit_logs (user_id, command_text, status, rule_matched)
                VALUES (?, ?, ?, 'ADMIN_DECISION')
            ''', (req_data['user_id'], req_data['command_text'], f"Request {decision}",))

        db.commit()
        return jsonify({'status': 'updated'})

@app.route('/api/history', methods=['GET'])
@require_api_key
def get_history():
    db = get_db()
    cur = db.cursor()
    if g.user['role'] == 'admin':
        # Admin sees everything
        query = '''
            SELECT l.id, l.command_text, l.status, l.timestamp, l.rule_matched, u.username 
            FROM audit_logs l
            JOIN users u ON l.user_id = u.id
            ORDER BY l.timestamp DESC LIMIT 50
        '''
        cur.execute(query)
    else:
        # User sees their own
        query = '''
            SELECT id, command_text, status, timestamp, rule_matched 
            FROM audit_logs 
            WHERE user_id = ? 
            ORDER BY timestamp DESC LIMIT 50
        '''
        cur.execute(query, (g.user['id'],))
    return jsonify([dict(row) for row in cur.fetchall()])

# --- Standard Management Routes (Rules/Users) ---
@app.route('/api/rules', methods=['GET', 'POST', 'DELETE'])
@require_api_key
def manage_rules():
    if g.user['role'] != 'admin': return jsonify({'error': 'Unauthorized'}), 403
    db = get_db()
    if request.method == 'GET':
        # FIX: Capture the cursor returned by execute
        cur = db.execute("SELECT * FROM rules ORDER BY id ASC")
        return jsonify([dict(row) for row in cur.fetchall()])
    if request.method == 'POST':
        d = request.json
        try: re.compile(d.get('pattern'))
        except: return jsonify({'error': 'Invalid Regex'}), 400
        db.execute("INSERT INTO rules (pattern, action, message) VALUES (?, ?, ?)", 
                   (d.get('pattern'), d.get('action'), d.get('message', '')))
        db.commit()
        return jsonify({'status': 'added'})
    if request.method == 'DELETE':
        db.execute("DELETE FROM rules WHERE id = ?", (request.args.get('id'),))
        db.commit()
        return jsonify({'status': 'deleted'})

@app.route('/api/users', methods=['GET', 'POST'])
@require_api_key
def manage_users():
    if g.user['role'] != 'admin': return jsonify({'error': 'Unauthorized'}), 403
    db = get_db()
    if request.method == 'GET':
        cur = db.execute("SELECT id, username, role, credits FROM users")
        return jsonify([dict(row) for row in cur.fetchall()])
    if request.method == 'POST':
        d = request.json
        try:
            k = str(uuid.uuid4())
            db.execute("INSERT INTO users (username, api_key, role, credits) VALUES (?, ?, ?, ?)",
                        (d.get('username'), k, d.get('role', 'member'), 100))
            db.commit()
            return jsonify({'api_key': k})
        except: return jsonify({'error': 'User exists'}), 400

if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000)