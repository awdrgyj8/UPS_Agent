from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature
import time, json, subprocess, base64, binascii, socket, os, platform, shutil
from pathlib import Path
from dotenv import load_dotenv
import sqlite3

BASE_DIR = Path(__file__).resolve().parent
PUBLIC_KEY_PATH = BASE_DIR / "Key" / "public_key.pem"
NONCE_DB_PATH = BASE_DIR / "seen_nonces.db"
load_dotenv(BASE_DIR / ".env")

# 提供給 Controller 判斷此 Agent 支援哪些端點
CAPABILITIES = ["status", "shutdown", "verify"]

def get_agent_port():
    port = os.getenv("AGENT_PORT")
    if port is None or port == "":
        return 5858
    try:
        return int(port)
    except ValueError:
        raise ValueError("AGENT_PORT 必須是數字")

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

# ---- 系統資訊（皆為盡力讀取，失敗時回傳 None）----
def _read_system_uptime():
    try:
        with open("/proc/uptime", "r") as f:
            return int(float(f.read().split()[0]))
    except (OSError, ValueError, IndexError):
        return None

def _read_load_avg():
    try:
        return [round(value, 2) for value in os.getloadavg()]
    except (OSError, AttributeError):
        return None

def _read_memory():
    try:
        info = {}
        with open("/proc/meminfo", "r") as f:
            for line in f:
                key, value = line.split(":", 1)
                info[key] = int(value.strip().split()[0]) * 1024
        return {"total": info["MemTotal"], "available": info.get("MemAvailable", info.get("MemFree", 0))}
    except (OSError, ValueError, KeyError):
        return None

def _read_disk():
    try:
        usage = shutil.disk_usage("/")
        return {"total": usage.total, "used": usage.used, "free": usage.free}
    except OSError:
        return None

def _verify_signed_request(data, expected_action):
    """驗證 Controller 簽章請求，成功回傳 (payload, None)，失敗回傳 (None, (response, status_code))。"""
    try:
        payload = data["payload"]      # 字典
        signature_b64 = data["signature"]
        if not isinstance(payload, dict):
            raise TypeError("payload must be object")
    except Exception:
        return None, (jsonify({"ok": False, "reason": "bad format"}), 400)

    payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()

    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except (binascii.Error, ValueError, TypeError):
        return None, (jsonify({"ok": False, "reason": "bad signature encoding"}), 400)

    # 驗證簽名
    try:
        pubkey.verify(signature, payload_bytes) # type: ignore
    except InvalidSignature:
        return None, (jsonify({"ok": False, "reason": "invalid signature"}), 403)

    # check timestamp and nonce
    try:
        ts = int(payload.get("timestamp", 0))
    except (TypeError, ValueError):
        return None, (jsonify({"ok": False, "reason": "bad timestamp"}), 400)
    nonce = payload.get("nonce")
    action = payload.get("action")

    if abs(int(time.time()) - ts) > 30:
        return None, (jsonify({"ok": False, "reason": "timestamp skew"}), 403)

    if nonce is None or nonce_seen(nonce):
        return None, (jsonify({"ok": False, "reason": "nonce invalid or replay"}), 403)

    if action != expected_action:
        return None, (jsonify({"ok": False, "reason": "unknown action"}), 400)

    # mark nonce
    mark_nonce(nonce)
    return payload, None

@app.route("/status", methods=["GET"])
def status():
    return jsonify({
        "ok": True,
        "hostname": socket.gethostname(),
        "uptime_seconds": int(time.time() - start_time),
        "timestamp": int(time.time()),
        "capabilities": CAPABILITIES,
        "system": {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "cpu_count": os.cpu_count(),
            "uptime_seconds": _read_system_uptime(),
            "load_avg": _read_load_avg(),
            "memory": _read_memory(),
            "disk": _read_disk(),
        },
    }), 200

@app.route("/verify", methods=["POST"])
def verify():
    # 只驗證簽章、時間戳與 nonce，不執行任何動作；供 Controller 測試中心使用
    payload, error = _verify_signed_request(request.get_json(silent=True), "verify")
    if error is not None:
        return error
    return jsonify({
        "ok": True,
        "message": "signature verified",
        "hostname": socket.gethostname(),
        "timestamp": int(time.time()),
    }), 200

@app.route("/shutdown", methods=["POST"])
def shutdown():
    payload, error = _verify_signed_request(request.get_json(silent=True), "shutdown")
    if error is not None:
        return error

    print('已接收到關機命令')
    try:
        subprocess.run(["sudo", "-n", "shutdown", "-h", "now"], check=True, timeout=10)
    except subprocess.TimeoutExpired:
        return jsonify({"ok": False, "reason": "shutdown command timeout"}), 500
    except subprocess.CalledProcessError as e:
        return jsonify({"ok": False, "reason": f"shutdown command failed: {e}"}), 500

    return jsonify({"ok": True, "message": "shutdown accepted"}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=get_agent_port())
