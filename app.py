import os
import sqlite3
from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO

app = Flask(__name__)
app.config['SECRET_KEY'] = 'spyshield_secure_key'

socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')
DB_NAME = "spyshield_audit.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            device TEXT NOT NULL,
            process TEXT NOT NULL,
            status TEXT NOT NULL,
            risk_tier TEXT DEFAULT 'LOW',
            duration TEXT DEFAULT '0s'
        )
    """)
    # Automatically add missing column to existing database
    try:
        cursor.execute("ALTER TABLE audit_logs ADD COLUMN risk_tier TEXT DEFAULT 'LOW'")
    except sqlite3.OperationalError:
        pass  # Column already exists
    conn.commit()
    conn.close()

init_db()

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/api/telemetry', methods=['POST'])
def receive_telemetry():
    data = request.json
    timestamp = data.get('timestamp')
    device = data.get('device')
    process = data.get('process')
    status = data.get('status')
    risk_tier = data.get('risk_tier', 'LOW')
    duration = data.get('duration', 'Active')

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO audit_logs (timestamp, device, process, status, risk_tier, duration) VALUES (?, ?, ?, ?, ?, ?)",
        (timestamp, device, process, status, risk_tier, duration)
    )
    conn.commit()
    conn.close()

    socketio.emit('telemetry_update', data)
    return jsonify({"status": "logged"}), 200

@app.route('/api/terminate', methods=['POST'])
def terminate_request():
    """Receives kill command from dashboard and broadcasts it to the agent."""
    process_name = request.json.get('process')
    if not process_name or process_name == "None":
        return jsonify({"error": "No active process"}), 400
    
    # Broadcast kill command to agent
    socketio.emit('kill_process_command', {"process": process_name})
    return jsonify({"status": f"Kill signal dispatched for {process_name}"}), 200

@app.route('/api/history', methods=['GET'])
def get_history():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT timestamp, device, process, status, risk_tier, duration FROM audit_logs ORDER BY id DESC LIMIT 50")
    rows = cursor.fetchall()
    conn.close()

    history = [
        {"timestamp": r[0], "device": r[1], "process": r[2], "status": r[3], "risk_tier": r[4], "duration": r[5]}
        for r in rows
    ]
    return jsonify(history), 200

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    socketio.run(app, host='0.0.0.0', port=port)