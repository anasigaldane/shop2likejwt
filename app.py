import os
import json
import base64
import asyncio
import httpx
from flask import Flask, request, jsonify
from flask_cors import CORS
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf import json_format, message
from google.protobuf.message import Message
import FreeFire_pb2

# === Settings ===
MAIN_KEY = base64.b64decode(os.getenv("MAIN_KEY", "WWcmdGMlREV1aDYlWmNeOA=="))
MAIN_IV = base64.b64decode(os.getenv("MAIN_IV", "Nm95WkRyMjJFM3ljaGpNJQ=="))
RELEASEVERSION = "OB50"
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"

# Flask setup
app = Flask(__name__)
CORS(app)

# Global async client (reuse connection)
async_client = httpx.AsyncClient(
    timeout=10.0,
    headers={"User-Agent": USERAGENT, "Connection": "Keep-Alive"},
    limits=httpx.Limits(max_keepalive_connections=100, max_connections=200)
)

# === Helper Functions ===
def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(pad(plaintext, AES.block_size))

def decode_protobuf(encoded_data: bytes, message_type) -> Message:
    instance = message_type()
    instance.ParseFromString(encoded_data)
    return instance

def json_to_proto(json_data: dict, proto_message: Message) -> bytes:
    json_format.ParseDict(json_data, proto_message)
    return proto_message.SerializeToString()

async def get_access_token(account: str):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = account + "&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    resp = await async_client.post(url, data=payload, headers=headers)
    data = resp.json()
    return data.get("access_token", "0"), data.get("open_id", "0")

async def generate_jwt_token(uid: str, password: str):
    # Validate inputs
    if not uid.isdigit() or len(password) < 6:
        raise ValueError("Invalid UID or password format")

    account = f"uid={uid}&password={password}"
    token_val, open_id = await get_access_token(account)

    body = {
        "open_id": open_id,
        "open_id_type": "4",
        "login_token": token_val,
        "orign_platform_type": "4"
    }

    proto_bytes = json_to_proto(body, FreeFire_pb2.LoginReq())
    payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto_bytes)

    url = "https://loginbp.ggblueshark.com/MajorLogin"
    headers = {
        "Content-Type": "application/octet-stream",
        "Accept-Encoding": "gzip",
        "Expect": "100-continue",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": RELEASEVERSION
    }

    resp = await async_client.post(url, content=payload, headers=headers)
    if resp.status_code != 200:
        raise Exception(f"Login request failed with {resp.status_code}")

    msg = json.loads(json_format.MessageToJson(
        decode_protobuf(resp.content, FreeFire_pb2.LoginRes)
    ))

    return {
        "accountId": msg.get("accountId", ""),
        "agoraEnvironment": msg.get("agoraEnvironment", "live"),
        "ipRegion": msg.get("ipRegion", ""),
        "lockRegion": msg.get("lockRegion", ""),
        "notiRegion": msg.get("notiRegion", ""),
        "serverUrl": msg.get("serverUrl", ""),
        "token": f"Bearer {msg.get('token', '')}"
    }

# === Flask Route ===
@app.route('/token', methods=['GET'])
def get_jwt_token():
    uid = request.args.get("uid", "").strip()
    password = request.args.get("password", "").strip()

    if not uid or not password:
        return jsonify({"error": "Both uid and password are required"}), 400

    try:
        result = asyncio.run(generate_jwt_token(uid, password))
        return jsonify(result), 200
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400
    except Exception as e:
        app.logger.error(f"Internal error: {e}")
        return jsonify({"error": "Internal server error"}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
