import httpx
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64
from google.protobuf import json_format
from proto import FreeFire_pb2

MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    return AES.new(key, AES.MODE_CBC, iv).encrypt(pad(plaintext, AES.block_size))

def get_access_token(uid: str, password: str):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = f"uid={uid}&password={password}&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
    headers = {
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    with httpx.Client(timeout=15.0) as client:
        resp = client.post(url, data=payload, headers=headers)
        resp.raise_for_status()
        data = resp.json()
        return data.get("access_token"), data.get("open_id")

def create_jwt(uid: str, password: str):
    token_val, open_id = get_access_token(uid, password)
    if not token_val:
        raise ValueError("Failed to get access token")

    body = json.dumps({
        "open_id": open_id,
        "open_id_type": "4",
        "login_token": token_val,
        "orign_platform_type": "4"
    })
    proto_bytes = FreeFire_pb2.LoginReq()
    json_format.ParseDict(json.loads(body), proto_bytes)
    payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto_bytes.SerializeToString())

    url = "https://loginbp.ggblueshark.com/MajorLogin"
    headers = {
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
        "Content-Type": "application/octet-stream",
        "Expect": "100-continue",
        "X-Unity-Version": "2018.4.11f1",
        "ReleaseVersion": "OB50"
    }

    with httpx.Client(timeout=20.0) as client:
        resp = client.post(url, data=payload, headers=headers)
        resp.raise_for_status()
        msg = json.loads(json_format.MessageToJson(FreeFire_pb2.LoginRes().FromString(resp.content)))
        return f"Bearer {msg.get('token','0')}"

# === مثال تشغيل ===
if __name__ == "__main__":
    uid = "4167202140"
    password = "7F6CDF48F387A1D78010CB3359A3660BCFC5AA0040A0118D0287122973DD1FE3"
    print("JWT:", create_jwt(uid, password))
