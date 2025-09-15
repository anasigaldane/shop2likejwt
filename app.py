import asyncio
import base64
import json
from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import httpx
from google.protobuf import json_format
from proto import FreeFire_pb2

# === إعدادات ===
MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"
RELEASEVERSION = "OB50"

app = Flask(__name__)

# === تشفير AES ===
def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    return AES.new(key, AES.MODE_CBC, iv).encrypt(pad(plaintext, AES.block_size))

# === تحويل JSON إلى Proto ===
async def json_to_proto(json_data: str, proto_message):
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()

# === جلب Access Token ===
async def get_access_token(uid: str, password: str):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = f"uid={uid}&password={password}&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
    headers = {
        'User-Agent': USERAGENT,
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/x-www-form-urlencoded"
    }
    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.post(url, data=payload, headers=headers)
        resp.raise_for_status()
        data = resp.json()
        return data.get("access_token"), data.get("open_id")

# === إنشاء JWT ===
async def create_jwt(uid: str, password: str):
    token_val, open_id = await get_access_token(uid, password)
    if not token_val:
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
        'ReleaseVersion': RELEASEVERSION
    }

    async with httpx.AsyncClient(timeout=20.0) as client:
        resp = await client.post(url, data=payload, headers=headers)
        resp.raise_for_status()
        msg = json.loads(json_format.MessageToJson(
            FreeFire_pb2.LoginRes().FromString(resp.content)
        ))
        return f"Bearer {msg.get('token','0')}"

# === نقطة API /token ===
@app.route('/token')
def get_token_endpoint():
    uid = request.args.get('uid')
    password = request.args.get('password')
    if not uid or not password:
        return jsonify({"error": "Please provide UID and password"}), 400
    try:
        jwt = asyncio.run(create_jwt(uid, password))
        return jsonify({"jwt": jwt}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# === تشغيل السيرفر ===
if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
