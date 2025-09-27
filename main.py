from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature
import time, json, os
import sqlite3

# load public key
with open("Key/public_key.pem", "rb") as f:
    pubkey = load_pem_public_key(f.read())

# 寫入防止重放攻擊記錄
conn = sqlite3.connect("seen_nonces.db", check_same_thread=False)
conn.execute("CREATE TABLE IF NOT EXISTS nonces (nonce TEXT PRIMARY KEY, ts INTEGER)")
conn.commit()

app = Flask(__name__)

def nonce_seen(nonce):
    cur = conn.execute("SELECT 1 FROM nonces WHERE nonce = ?", (nonce,))
    row = cur.fetchone()
    return row is not None

def mark_nonce(nonce):
    conn.execute("INSERT OR IGNORE INTO nonces (nonce, ts) VALUES (?, ?)", (nonce, int(time.time())))
    conn.commit()

@app.route("/shutdown", methods=["POST"])
def shutdown():
    data = request.get_json()
    try:
        payload = data["payload"]      # 字典
        signature_b64 = data["signature"]
    except Exception:
        return jsonify({"ok": False, "reason": "bad format"}), 400

    payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()

    import base64
    signature = base64.b64decode(signature_b64)

    # 驗證簽名
    try:
        pubkey.verify(signature, payload_bytes) # type: ignore
    except InvalidSignature:
        return jsonify({"ok": False, "reason": "invalid signature"}), 403

    # check timestamp and nonce
    ts = int(payload.get("timestamp", 0))
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
    os.system("sudo shutdown -h now")
    
    return jsonify({"ok": True, "message": "shutdown accepted"}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5858)
