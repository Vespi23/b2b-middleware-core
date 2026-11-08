import json
import time
import hmac
import hashlib
import requests

API_URL = "http://127.0.0.1:8001/v1/pipeline/process"
API_KEY = "live_sec_prod_88294a8c1f0"
SHARED_SECRET = b"sec_k982_charleston_signing_key_x"

payload = {
    "batch_id": "BATCH_PROD_VERIFIED_002",
    "records": [
        {"record_id": "TX_201", "metric_value": 105.4, "category": "closing_escrow"},
        {"record_id": "TX_202", "metric_value": 112.1, "category": "closing_escrow"},
        {"record_id": "TX_203", "metric_value": 450.8, "category": "closing_escrow"},
        {"record_id": "TX_204", "metric_value": 102.0, "category": "closing_escrow"}
    ]
}

payload_bytes = json.dumps(payload).encode("utf-8")
current_ts = str(int(time.time()))

# Message = timestamp + "." + body
message = f"{current_ts}.".encode("utf-8") + payload_bytes
signature = hmac.new(SHARED_SECRET, message, hashlib.sha256).hexdigest()

headers = {
    "X-Venture-API-Key": API_KEY,
    "X-Signature": signature,
    "X-Timestamp": current_ts,
    "Content-Type": "application/json"
}

resp = requests.post(API_URL, data=payload_bytes, headers=headers)
print(f"Status Code: {resp.status_code}")
print(json.dumps(resp.json(), indent=2))
