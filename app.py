import asyncio
import time
import httpx
import json
from collections import defaultdict
from flask import Flask, request, jsonify
from flask_cors import CORS
from cachetools import TTLCache
from typing import Tuple
from proto import FreeFire_pb2, main_pb2, AccountPersonalShow_pb2
from google.protobuf import json_format, message
from google.protobuf.message import Message
from Crypto.Cipher import AES
import base64
import logging

# === Logging ===
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("FF_API")

# === Settings ===
MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')
RELEASEVERSION = "OB50"
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"
SUPPORTED_REGIONS = {"IND", "BR", "US", "SAC", "NA", "SG", "RU", "ID", "TW", "VN", "TH", "ME", "PK", "CIS", "BD", "EUROPE"}

# === Flask App Setup ===
app = Flask(__name__)
CORS(app)
cache = TTLCache(maxsize=100, ttl=300)
cached_tokens = defaultdict(dict)
token_locks = defaultdict(asyncio.Lock)
MAX_CONCURRENT_REQUESTS = 500
semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)

# === Helper Functions ===
def pad(text: bytes) -> bytes:
    padding_length = AES.block_size - (len(text) % AES.block_size)
    return text + bytes([padding_length] * padding_length)

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(pad(plaintext))

def decode_protobuf(encoded_data: bytes, message_type: message.Message) -> message.Message:
    instance = message_type()
    instance.ParseFromString(encoded_data)
    return instance

async def json_to_proto(json_data: str, proto_message: Message) -> bytes:
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()

# === Access Token ===
async def get_access_token(account: str):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = account + "&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
    headers = {
        'User-Agent': USERAGENT,
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/x-www-form-urlencoded"
    }
    retries = 3
    for attempt in range(retries):
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(url, data=payload, headers=headers)
                resp.raise_for_status()
                data = resp.json()
                return data.get("access_token", "0"), data.get("open_id", "0")
        except Exception as e:
            logger.warning(f"Access token fetch failed ({attempt+1}/{retries}): {e}")
            await asyncio.sleep(1)
    raise RuntimeError("Failed to get access token after retries")

# === JWT Creation ===
async def create_jwt_from_credentials(uid: str, password: str, region: str = "IND"):
    async with token_locks[region]:
        account = f"uid={uid}&password={password}"
        token_val, open_id = await get_access_token(account)
        if token_val == "0":
            raise ValueError("Failed to get access token")
        body = json.dumps({
            "open_id": open_id,
            "open_id_type": "4",
            "login_token": token_val,
            "orign_platform_type": "4"
        })
        proto_bytes = await json_to_proto(body, FreeFire_pb2.LoginReq())
        payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto_bytes)
        url = "https://loginbp.ggblueshark.com/MajorLogin"
        headers = {
            'User-Agent': USERAGENT,
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Content-Type': "application/octet-stream",
            'Expect': "100-continue",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': RELEASEVERSION
        }
        async with httpx.AsyncClient(timeout=20.0) as client:
            resp = await client.post(url, data=payload, headers=headers)
            resp.raise_for_status()
            msg = json.loads(json_format.MessageToJson(
                decode_protobuf(resp.content, FreeFire_pb2.LoginRes)
            ))
            return f"Bearer {msg.get('token','0')}"

# === API Route to get JWT ===
@app.route('/token')
def token_endpoint():
    uid = request.args.get('uid')
    password = request.args.get('password')
    region = request.args.get('region', 'IND').upper()
    if not uid or not password:
        return jsonify({"error": "Please provide UID and password"}), 400
    try:
        jwt = asyncio.run(create_jwt_from_credentials(uid, password, region))
        return jsonify({"jwt": jwt}), 200
    except Exception as e:
        logger.error(f"Error generating JWT: {e}")
        return jsonify({"error": str(e)}), 500

# === Startup Tokens (Optional caching) ===
async def create_jwt(region: str):
    # موجود في الكود القديم لحفظ JWT حسب Region
    pass

async def initialize_tokens():
    pass

async def refresh_tokens_periodically():
    pass

# === تشغيل السيرفر ===
if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
