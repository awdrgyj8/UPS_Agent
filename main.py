from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature
import time, json, subprocess, base64, binascii, socket
from pathlib import Path
import sqlite3

BASE_DIR = Path(__file__).resolve().parent
PUBLIC_KEY_PATH = BASE_DIR / "Key" / "public_key.pem"
NONCE_DB_PATH = BASE_DIR / "seen_nonces.db"

# load public key
with open(PUBLIC_KEY_PATH, "rb") as f:
    pubkey = load_pem_public_key(f.read())

# 寫入防止重放攻擊記錄
conn = sqlite3.connect(NONCE_DB_PATH, check_same_thread=False)
conn.execute("CREATE TABLE IF NOT EXISTS nonces (nonce TEXT PRIMARY KEY, ts INTEGER)")
conn.commit()

app = Flask(__name__)
start_time = time.time()

def nonce_seen(nonce):
    cur = conn.execute("SELECT 1 FROM nonces WHERE nonce = ?", (nonce,))
    row = cur.fetchone()
    return row is not None

def mark_nonce(nonce):
    conn.execute("INSERT OR IGNORE INTO nonces (nonce, ts) VALUES (?, ?)", (nonce, int(time.time())))
    conn.commit()

@app.route("/status", methods=["GET"])
def status():
    return jsonify({
        "ok": True,
        "hostname": socket.gethostname(),
        "uptime_seconds": int(time.time() - start_time),
        "timestamp": int(time.time()),
    }), 200

@app.route("/shutdown", methods=["POST"])
def shutdown():
    data = request.get_json()
    try:
        payload = data["payload"]      # 字典
        signature_b64 = data["signature"]
    except Exception:
        return jsonify({"ok": False, "reason": "bad format"}), 400

    payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()

    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except (binascii.Error, ValueError, TypeError):
        return jsonify({"ok": False, "reason": "bad signature encoding"}), 400

    # 驗證簽名
    try:
        pubkey.verify(signature, payload_bytes) # type: ignore
    except InvalidSignature:
        return jsonify({"ok": False, "reason": "invalid signature"}), 403

    # check timestamp and nonce
    try:
        ts = int(payload.get("timestamp", 0))
    except (TypeError, ValueError):
        return jsonify({"ok": False, "reason": "bad timestamp"}), 400
    nonce = payload.get("nonce")
    action = payload.get("action")

    if abs(int(time.time()) - ts) > 30:
        return jsonify({"ok": False, "reason": "timestamp skew"}), 403

    if nonce is None or nonce_seen(nonce):
        return jsonify({"ok": False, "reason": "nonce invalid or replay"}), 403

    if action != "shutdown":
        return jsonify({"ok": False, "reason": "unknown action"}), 400

    # mark nonce and then perform action
    mark_nonce(nonce)

    print('已接收到關機命令')
    try:
        subprocess.run(["sudo", "-n", "shutdown", "-h", "now"], check=True, timeout=10)
    except subprocess.TimeoutExpired:
        return jsonify({"ok": False, "reason": "shutdown command timeout"}), 500
    except subprocess.CalledProcessError as e:
        return jsonify({"ok": False, "reason": f"shutdown command failed: {e}"}), 500
    
    return jsonify({"ok": True, "message": "shutdown accepted"}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5858)
