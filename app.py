# app.py
# Improved Flask endpoint /token with security + load protections
import os
import time
import json
import base64
import logging
import re
from typing import Tuple, Optional
from functools import wraps
from cachetools import TTLCache
from threading import BoundedSemaphore
import httpx
from flask import Flask, request, jsonify
from flask_cors import CORS
from google.protobuf import json_format, message
from google.protobuf.message import Message
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad as pkcs7_pad

# -----------------------
# Logging
# -----------------------
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("token_service")

# -----------------------
# Settings (ENV-friendly)
# -----------------------
MAIN_KEY_BASE64 = os.getenv("MAIN_KEY_BASE64", "WWcmdGMlREV1aDYlWmNeOA==")
MAIN_IV_BASE64 = os.getenv("MAIN_IV_BASE64", "Nm95WkRyMjJFM3ljaGpNJQ==")

# safe decode (fallback to default bytes if env is invalid)
try:
    MAIN_KEY = base64.b64decode(MAIN_KEY_BASE64)
    MAIN_IV = base64.b64decode(MAIN_IV_BASE64)
except Exception:
    logger.warning("Invalid base64 keys in env, falling back to default raw bytes (not recommended for production)")
    MAIN_KEY = b"Yg&tc%DEuh6%Zc^8"
    MAIN_IV = b"6oyZDr22E3ychjM%"

RELEASEVERSION = os.getenv("RELEASE_VERSION", "OB50")
USERAGENT = os.getenv("USER_AGENT", "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)")

# HTTP / client settings
HTTP_TIMEOUT = float(os.getenv("HTTP_TIMEOUT", "18.0"))  # seconds
HTTP_MAX_KEEPALIVE = int(os.getenv("HTTP_MAX_KEEPALIVE", "100"))
HTTP_MAX_CONNECTIONS = int(os.getenv("HTTP_MAX_CONNECTIONS", "300"))
HTTP_RETRIES = int(os.getenv("HTTP_RETRIES", "3"))
HTTP_BACKOFF_FACTOR = float(os.getenv("HTTP_BACKOFF_FACTOR", "0.6"))

# concurrency control for outbound requests
MAX_CONCURRENT_OUTBOUND = int(os.getenv("MAX_CONCURRENT_OUTBOUND", "250"))
OUTBOUND_SEMAPHORE = BoundedSemaphore(MAX_CONCURRENT_OUTBOUND)

# token caching: avoid regenerating token for same account frequently
TOKEN_CACHE_TTL = int(os.getenv("TOKEN_CACHE_TTL", "25200"))  # default ~7 hours
token_cache = TTLCache(maxsize=200, ttl=TOKEN_CACHE_TTL)

# Rate-limit per IP (simple token-bucket)
RATE_LIMIT_CAPACITY = int(os.getenv("RATE_LIMIT_CAPACITY", "120"))
RATE_LIMIT_WINDOW = int(os.getenv("RATE_LIMIT_WINDOW", "60"))  # seconds
_rate_buckets = {}

# -----------------------
# Protobuf import
# -----------------------
# Ensure the generated proto module FreeFire_pb2 is in PYTHONPATH
try:
    import FreeFire_pb2  # type: ignore
except Exception as e:
    logger.exception("Failed to import FreeFire_pb2 - ensure proto files are available: %s", e)
    FreeFire_pb2 = None  # keep code importable for static analysis

# -----------------------
# Flask app
# -----------------------
app = Flask(__name__)
CORS(app)

# -----------------------
# Shared HTTP client (sync)
# -----------------------
# Reuse httpx.Client to keep connections alive and pooled
_http_client: Optional[httpx.Client] = None


def get_http_client() -> httpx.Client:
    global _http_client
    if _http_client is None:
        _http_client = httpx.Client(
            timeout=HTTP_TIMEOUT,
            headers={"User-Agent": USERAGENT, "Connection": "Keep-Alive"},
            limits=httpx.Limits(max_keepalive_connections=HTTP_MAX_KEEPALIVE,
                                max_connections=HTTP_MAX_CONNECTIONS),
            verify=True
        )
    return _http_client


# -----------------------
# Utilities
# -----------------------
def now_ts() -> int:
    return int(time.time())


def is_valid_uid(uid: str) -> bool:
    return bool(re.fullmatch(r"\d{5,20}", uid))


def is_valid_password(pw: str) -> bool:
    # password in your examples is uppercase hex-like; accept alnum symbols; min length
    return bool(re.fullmatch(r"[A-Za-z0-9]{8,128}", pw))


def safe_response_error(message_text: str, code: int = 400):
    # avoid leaking internals
    return jsonify({"error": message_text}), code


# -----------------------
# AES / Protobuf helpers
# -----------------------
def pkcs7_pad_bytes(data: bytes) -> bytes:
    return pkcs7_pad(data, AES.block_size)


def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return cipher.encrypt(pkcs7_pad_bytes(plaintext))
    except Exception as e:
        logger.exception("AES encryption failed: %s", e)
        raise


def decode_protobuf_safe(encoded: bytes, message_type) -> Message:
    if message_type is None:
        raise RuntimeError("Protobuf type is not available")
    inst = message_type()
    try:
        inst.ParseFromString(encoded)
        return inst
    except Exception as e:
        logger.exception("Protobuf parse failed: %s", e)
        raise


# -----------------------
# HTTP POST with retries (sync)
# -----------------------
def http_post_with_retries_sync(url: str, data: bytes, headers: dict,
                               retries: int = HTTP_RETRIES, backoff_factor: float = HTTP_BACKOFF_FACTOR,
                               timeout: Optional[float] = None) -> httpx.Response:
    client = get_http_client()
    last_exc = None
    for attempt in range(1, retries + 1):
        try:
            with OUTBOUND_SEMAPHORE:
                resp = client.post(url, data=data, headers=headers, timeout=timeout or HTTP_TIMEOUT)
            resp.raise_for_status()
            return resp
        except Exception as exc:
            last_exc = exc
            wait = backoff_factor * (2 ** (attempt - 1))
            logger.warning("HTTP POST failed (%d/%d) to %s: %s — retry in %.2fs", attempt, retries, url, exc, wait)
            time.sleep(wait)
    logger.error("All retries failed for %s — last error: %s", url, last_exc)
    raise last_exc


# -----------------------
# Guest token fetch & MajorLogin flow (improved)
# -----------------------
def _get_account_credentials(region: str) -> str:
    r = (region or "").upper()
    if r == "IND":
        return "uid=3947622285&password=92AAF030CF53C1DD509C3C6070BC79004C64A819F34AB8E07BD0ABCDC424D511"
    elif r == "BD":
        return "uid=3957595605&password=7203510AB3D87E06CE54FC93ABE40D48AA6AEA55E2DEA2D2AA3487CBB20650D7"
    elif r in {"BR", "US", "SAC", "NA"}:
        return "uid=3788023112&password=5356B7495AC2AD04C0A483CF234D6E56FB29080AC2461DD51E0544F8D455CC24"
    else:
        return "uid=4167202140&password=7F6CDF48F387A1D78010CB3359A3660BCFC5AA0040A0118D0287122973DD1FE3"


def get_access_token(account: str) -> Tuple[str, str]:
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = account + "&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    resp = http_post_with_retries_sync(url, data=payload.encode(), headers=headers)
    try:
        data = resp.json()
        return data.get("access_token", "0"), data.get("open_id", "0")
    except Exception:
        logger.exception("Failed to parse guest token response")
        raise RuntimeError("Invalid guest token response")


def generate_jwt_token_internal(uid: str, password: str) -> dict:
    """
    Core logic (synchronous) to create MajorLogin token.
    Uses caching: if same account uid+password requested and token still valid, return cached.
    """
    account_key = f"{uid}:{password}"
    cached = token_cache.get(account_key)
    if cached and time.time() < cached.get("expires_at", 0) - 30:
        logger.debug("Token cache hit for account %s", uid)
        return cached["data"]

    # Build account string & get guest token
    account = f"uid={uid}&password={password}"
    access_token, open_id = get_access_token(account)
    if not access_token:
        logger.error("Empty access token for account %s", uid)
        raise RuntimeError("Failed to get access token")

    body = {"open_id": open_id, "open_id_type": "4", "login_token": access_token, "orign_platform_type": "4"}
    # Convert to proto bytes
    if FreeFire_pb2 is None:
        logger.error("FreeFire_pb2 not imported; cannot build LoginReq")
        raise RuntimeError("Server misconfiguration (proto missing)")

    try:
        login_req = FreeFire_pb2.LoginReq()
        json_format.ParseDict(body, login_req)
        proto_bytes = login_req.SerializeToString()
    except Exception:
        logger.exception("Failed to build LoginReq proto")
        raise RuntimeError("Proto serialization error")

    payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto_bytes)

    url = "https://loginbp.ggblueshark.com/MajorLogin"
    headers = {
        'Content-Type': 'application/octet-stream',
        'Expect': '100-continue',
        'X-Unity-Version': '2018.4.11f1',
        'X-GA': 'v1 1',
        'ReleaseVersion': RELEASEVERSION
    }

    resp = http_post_with_retries_sync(url, data=payload, headers=headers)
    try:
        login_res = decode_protobuf_safe(resp.content, FreeFire_pb2.LoginRes)
        parsed = json.loads(json_format.MessageToJson(login_res))
        token_val = parsed.get("token", "")
        server_url = parsed.get("serverUrl", "")
        lock_region = parsed.get("lockRegion", "")
    except Exception:
        logger.exception("Failed to parse MajorLogin response for uid=%s", uid)
        raise RuntimeError("Invalid MajorLogin response")

    result = {
        "accountId": parsed.get("accountId", ""),
        "agoraEnvironment": parsed.get("agoraEnvironment", "live"),
        "ipRegion": parsed.get("ipRegion", ""),
        "lockRegion": lock_region,
        "notiRegion": parsed.get("notiRegion", ""),
        "serverUrl": server_url,
        "token": f"Bearer {token_val}"
    }

    # cache it (store expiry using TOKEN_CACHE_TTL seconds)
    token_cache[account_key] = {"data": result, "expires_at": time.time() + TOKEN_CACHE_TTL}
    logger.info("Generated and cached JWT for uid=%s", uid)
    return result


# -----------------------
# Rate limiting decorator
# -----------------------
def _get_client_ip():
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "unknown"


def rate_limit_exceeded(ip: str) -> bool:
    now = time.time()
    bucket = _rate_buckets.get(ip)
    if bucket is None:
        _rate_buckets[ip] = {"tokens": RATE_LIMIT_CAPACITY - 1, "last": now}
        return False
    elapsed = now - bucket["last"]
    refill = (elapsed / RATE_LIMIT_WINDOW) * RATE_LIMIT_CAPACITY
    if refill > 0:
        bucket["tokens"] = min(RATE_LIMIT_CAPACITY, bucket["tokens"] + int(refill))
        bucket["last"] = now
    if bucket["tokens"] <= 0:
        return True
    bucket["tokens"] -= 1
    return False


def rate_limit_route(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        ip = _get_client_ip()
        if rate_limit_exceeded(ip):
            logger.warning("Rate limit exceeded for IP %s", ip)
            return jsonify({"error": "Rate limit exceeded"}), 429
        return func(*args, **kwargs)
    return wrapper


# -----------------------
# Flask route (preserve interface)
# -----------------------
@app.route('/token', methods=['GET'])
@rate_limit_route
def get_jwt_token():
    uid = (request.args.get("uid") or "").strip()
    password = (request.args.get("password") or "").strip()

    if not uid or not password:
        return safe_response_error("Both uid and password parameters are required", 400)
    if not is_valid_uid(uid):
        return safe_response_error("Invalid UID format", 400)
    if not is_valid_password(password):
        return safe_response_error("Invalid password format", 400)

    try:
        data = generate_jwt_token_internal(uid, password)
        # Return only safe fields
        safe_out = {
            "accountId": data.get("accountId", ""),
            "lockRegion": data.get("lockRegion", ""),
            "serverUrl": data.get("serverUrl", ""),
            "token": data.get("token", "")
        }
        return jsonify(safe_out), 200
    except Exception as e:
        # log internal detail but return generic message to client
        logger.exception("Failed to generate token for uid=%s: %s", uid, e)
        return jsonify({"error": "Failed to generate token (server error)"}), 500


# -----------------------
# Health endpoint & graceful close
# -----------------------
@app.route('/health', methods=['GET'])
def health():
    try:
        info = {
            "status": "ok",
            "time": now_ts(),
            "cached_tokens": len(token_cache),
            "http_max_connections": HTTP_MAX_CONNECTIONS,
            "semaphore_capacity": MAX_CONCURRENT_OUTBOUND
        }
        return jsonify(info), 200
    except Exception as e:
        logger.exception("Health check failed: %s", e)
        return jsonify({"status": "error"}), 500


# -----------------------
# Shutdown hook for http client
# -----------------------
def _close_http_client():
    global _http_client
    try:
        if _http_client is not None:
            _http_client.close()
            _http_client = None
            logger.info("HTTP client closed")
    except Exception:
        logger.exception("Error closing HTTP client")


# -----------------------
# Run app
# -----------------------
if __name__ == '__main__':
    try:
        port = int(os.getenv("PORT", "5000"))
        app.run(host='0.0.0.0', port=port, debug=False)
    finally:
        _close_http_client()
