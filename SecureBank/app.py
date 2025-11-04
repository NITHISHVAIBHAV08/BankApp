from flask import Flask, render_template_string, request, redirect, session
import oracledb
import bcrypt, hmac, hashlib, os, decimal

# ---------------- Config ---------------- #
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "supersecretkey")  # override in production

# Oracle connection details — change as needed
ORACLE_USER = os.environ.get("ORACLE_USER", "securebank")
ORACLE_PWD  = os.environ.get("ORACLE_PWD", "sbpass")
ORACLE_DSN  = os.environ.get("ORACLE_DSN", "localhost/XEPDB1")

# HMAC secret for signing transactions (store securely in env in production)
HMAC_SECRET = os.environ.get("HMAC_SECRET", "sharedsecretkey").encode("utf-8")

# ---------------- Helpers ---------------- #
def get_db_conn():
    """Return a new Oracle connection."""
    return oracledb.connect(user=ORACLE_USER, password=ORACLE_PWD, dsn=ORACLE_DSN)

# ---------------- Routes ---------------- #
@app.route('/')
def home():
    return render_template_string('''
    <html><body style="font-family:Arial;text-align:center;margin-top:80px;">
    <h2>🏦 Secure Bank Login</h2>
    <form method="POST" action="/login">
        <input type="text" name="username" placeholder="Username" required><br><br>
        <input type="password" name="password" placeholder="Password" required><br><br>
        <button type="submit">Login</button>
    </form>
    <p>New user? <a href="/register">Register here</a></p>
    </body></html>
    ''')

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].encode('utf-8')
        hashed_pw = bcrypt.hashpw(password, bcrypt.gensalt()).decode('utf-8')

        conn = get_db_conn()
        cur = conn.cursor()

        # Check if username already exists
        cur.execute("SELECT 1 FROM users WHERE username = :u", [username])
        if cur.fetchone():
            cur.close(); conn.close()
            return "<h3>❌ Username already exists! Try another. <a href='/register'>Back</a></h3>"

        cur.execute("INSERT INTO users (username, password) VALUES (:u, :p)", [username, hashed_pw])
        conn.commit()
        cur.close(); conn.close()
        return "<h3>✅ Registration successful! You can now <a href='/'>login</a>.</h3>"
    else:
        return render_template_string('''
        <html><body style="font-family:Arial;text-align:center;margin-top:80px;">
        <h2>📝 User Registration</h2>
        <form method="POST">
            <input type="text" name="username" placeholder="Create Username" required><br><br>
            <input type="password" name="password" placeholder="Create Password" required><br><br>
            <button type="submit">Register</button>
        </form>
        <p><a href="/">Back to Login</a></p>
        </body></html>
        ''')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username'].strip()
    password = request.form['password'].encode('utf-8')

    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute("SELECT password FROM users WHERE username = :u", [username])
    row = cur.fetchone()
    cur.close(); conn.close()

    if row:
        stored_hash = row[0]
        if bcrypt.checkpw(password, stored_hash.encode('utf-8')):
            session['username'] = username
            return redirect('/dashboard')

    return "<h3>❌ Invalid credentials! <a href='/'>Try again</a>.</h3>"

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect('/')

    username = session['username']

    conn = get_db_conn()
    cur = conn.cursor()

    # Fetch last 10 transactions where user is sender
    cur.execute("""
        SELECT txn_id, sender_username, receiver_username, amount, txn_signature, txn_time, txn_status
        FROM transactions
        WHERE sender_username = :u
        ORDER BY txn_time DESC
        FETCH FIRST 10 ROWS ONLY
    """, [username])
    sent = cur.fetchall()

    # Fetch last 10 transactions where user is receiver
    cur.execute("""
        SELECT txn_id, sender_username, receiver_username, amount, txn_signature, txn_time, txn_status
        FROM transactions
        WHERE receiver_username = :u
        ORDER BY txn_time DESC
        FETCH FIRST 10 ROWS ONLY
    """, [username])
    received = cur.fetchall()

    cur.close(); conn.close()

    def rows_to_html(rows):
        html = ""
        for t in rows:
            txn_id, sender, receiver, amount, sig, ttime, status = t
            html += f"""
            <tr>
              <td>{txn_id}</td>
              <td>{sender}</td>
              <td>{receiver}</td>
              <td>₹{amount}</td>
              <td><textarea cols="50" rows="2" readonly>{sig}</textarea></td>
              <td>{ttime}</td>
              <td>{status}</td>
            </tr>
            """
        return html

    sent_html = rows_to_html(sent)
    recv_html = rows_to_html(received)

    return render_template_string(f'''
    <html>
    <head>
      <style>
        body{{font-family:Arial; margin:30px;}}
        .container{{display:flex; gap:40px; align-items:flex-start;}}
        .box{{border:1px solid #ddd; padding:18px; border-radius:8px; width:48%;}}
        table{{width:100%; border-collapse:collapse; margin-top:12px;}}
        th, td{{border:1px solid #ddd; padding:8px; font-size:14px;}}
        th{{background:#f2f2f2;}}
        textarea{{width:100%;}}
        label{{font-weight:600;}}
      </style>
    </head>
    <body>
    <h2>Welcome, {username} 👋</h2>

    <div class="container">
      <div class="box">
        <h3>Make a secure transaction</h3>
        <form method="POST" action="/transaction">
            <label>Receiver Username:</label><br>
            <input type="text" name="receiver" placeholder="Receiver username" required><br><br>
            <label>Amount (INR):</label><br>
            <input type="number" step="0.01" name="amount" placeholder="Enter Amount" required><br><br>
            <button type="submit">Send Money</button>
        </form>
        <p style="margin-top:12px;"><a href="/logout">Logout</a></p>
      </div>

      <div class="box">
        <h3>Your recent activity</h3>
        <p><b>Sent (last 10)</b></p>
        <table>
          <tr><th>Txn ID</th><th>Sender</th><th>Receiver</th><th>Amount</th><th>Signature</th><th>Time</th><th>Status</th></tr>
          {sent_html if sent_html else '<tr><td colspan="7">No sent transactions yet.</td></tr>'}
        </table>

        <p style="margin-top:16px;"><b>Received (last 10)</b></p>
        <table>
          <tr><th>Txn ID</th><th>Sender</th><th>Receiver</th><th>Amount</th><th>Signature</th><th>Time</th><th>Status</th></tr>
          {recv_html if recv_html else '<tr><td colspan="7">No received transactions yet.</td></tr>'}
        </table>
      </div>
    </div>

    </body></html>
    ''')

@app.route('/transaction', methods=['POST'])
def transaction():
    if 'username' not in session:
        return redirect('/')

    username = session['username']
    receiver = request.form.get('receiver', '').strip()
    amount_raw = request.form.get('amount', '').strip()

    # Basic validation
    if not receiver:
        return "<h3>❌ Receiver is required. <a href='/dashboard'>Back</a></h3>"
    if receiver == username:
        return "<h3>❌ You cannot send money to yourself. <a href='/dashboard'>Back</a></h3>"

    try:
        amount = decimal.Decimal(amount_raw)
        if amount <= 0:
            raise ValueError("Amount must be positive")
    except Exception:
        return "<h3>❌ Invalid amount. <a href='/dashboard'>Back</a></h3>"

    conn = None
    try:
        conn = get_db_conn()
        cur = conn.cursor()

        # --- Receiver existence check ---
        cur.execute("SELECT 1 FROM users WHERE username = :r", {"r": receiver})
        if not cur.fetchone():
            cur.close(); conn.close()
            return f"<h3>❌ Receiver '{receiver}' does not exist. <a href='/dashboard'>Back</a></h3>"

        # --- Generate HMAC signature for transaction integrity ---
        message = f"{username}:{receiver}:{amount}".encode('utf-8')
        signature = hmac.new(HMAC_SECRET, message, hashlib.sha256).hexdigest()

        # --- Insert transaction into DB ---
        insert_sql = """
            INSERT INTO transactions (
                sender_username,
                receiver_username,
                amount,
                txn_signature,
                txn_status
            ) VALUES (:sender, :receiver, :amount, :sig, :status)
        """
        cur.execute(insert_sql, {
            "sender": username,
            "receiver": receiver,
            # convert Decimal to float for Oracle NUMBER bind; adjust if you prefer a different approach
            "amount": float(amount),
            "sig": signature,
            "status": "COMPLETED"
        })
        conn.commit()

        # Retrieve the inserted transaction id/time for confirmation
        cur.execute("""
            SELECT txn_id, txn_time FROM transactions
            WHERE sender_username = :s AND txn_signature = :sig
            ORDER BY txn_time DESC
            FETCH FIRST 1 ROWS ONLY
        """, {"s": username, "sig": signature})
        inserted = cur.fetchone()
        txn_id, txn_time = inserted if inserted else ("N/A", "N/A")

        cur.close()
    except Exception as e:
        if conn:
            conn.rollback()
        # In production: log error instead of returning raw exception
        return f"<h3>❌ Transaction failed: {str(e)}. <a href='/dashboard'>Back</a></h3>"
    finally:
        if conn:
            conn.close()

    return render_template_string(f'''
    <html><body style="font-family:Arial;text-align:center;margin-top:80px;">
    <h2>💸 Transaction Recorded</h2>
    <p><b>Txn ID:</b> {txn_id}</p>
    <p><b>Sender:</b> {username}</p>
    <p><b>Receiver:</b> {receiver}</p>
    <p><b>Amount:</b> ₹{amount}</p>
    <p><b>Signature (HMAC):</b></p>
    <textarea cols="80" rows="3" readonly>{signature}</textarea><br><br>
    <p><b>Status:</b> COMPLETED</p>
    <p><b>Time:</b> {txn_time}</p>
    <a href="/dashboard">Back to Dashboard</a>
    </body></html>
    ''')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

# ---------------- Main ---------------- #
if __name__ == '__main__':
    # SSL cert check (optional)
    if not (os.path.exists("server_cert.pem") and os.path.exists("server_key.pem")):
        print("⚠️ Missing SSL certificate. Generate with: py generate_cert.py (or run without ssl_context for testing)")
    print("🚀 Starting SecureBank Flask Server with Oracle Integration...")
    # For production use a proper WSGI server (gunicorn/uvicorn) and real certs
    app.run(ssl_context=('server_cert.pem', 'server_key.pem'))
