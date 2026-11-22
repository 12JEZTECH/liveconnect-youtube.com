import os, sqlite3, hashlib, hmac, secrets, json, subprocess, tempfile, mimetypes, asyncio, time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import FastAPI, Request, Form, HTTPException, UploadFile, File, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request as GoogleRequest

APP_DIR = Path(__file__).parent
DB_PATH = os.getenv("DATABASE_PATH", str(APP_DIR / "liveconnect.db"))
Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
SECRET_KEY = os.getenv("SECRET_KEY", "development-only-change-this-secret")
if os.getenv("RENDER") and SECRET_KEY == "development-only-change-this-secret":
    raise RuntimeError("Set a strong SECRET_KEY in the deployment environment.")
BASE_URL = (os.getenv("BASE_URL") or os.getenv("RENDER_EXTERNAL_URL") or "http://localhost:10000").rstrip("/")
CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
SCOPES = ["openid", "https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/youtube.force-ssl"]

app = FastAPI(title="LiveConnect Creator Studio", version="1.0.0")

PENDING_LIVE_TARGETS = {}
ACTIVE_ENCODERS = {}
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, same_site="lax", https_only=BASE_URL.startswith("https://"))

def db():
    con = sqlite3.connect(DB_PATH, timeout=20)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    con.execute("PRAGMA busy_timeout=20000")
    return con

def init_db():
    with db() as con:
        con.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE NOT NULL,
            salt TEXT NOT NULL, password_hash TEXT NOT NULL, created_at TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0)""")
        con.execute("""CREATE TABLE IF NOT EXISTS youtube_tokens (
            user_id INTEGER PRIMARY KEY, token_json TEXT NOT NULL, channel_title TEXT,
            channel_id TEXT, updated_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id))""")
        con.execute("""CREATE TABLE IF NOT EXISTS media_assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, name TEXT NOT NULL,
            mime_type TEXT NOT NULL, data BLOB NOT NULL, size INTEGER NOT NULL, created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id))""")
        con.execute("""CREATE TABLE IF NOT EXISTS creator_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, kind TEXT NOT NULL,
            title TEXT NOT NULL, payload TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id))""")
        # Safe upgrades for databases created by earlier LiveConnect releases.
        user_cols = [r["name"] for r in con.execute("PRAGMA table_info(users)").fetchall()]
        if "is_admin" not in user_cols:
            con.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0")
        con.execute("""CREATE TABLE IF NOT EXISTS subscription_payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
            mpesa_code TEXT NOT NULL UNIQUE, payer_phone TEXT NOT NULL,
            amount INTEGER NOT NULL DEFAULT 2500, status TEXT NOT NULL DEFAULT 'pending',
            submitted_at TEXT NOT NULL, reviewed_at TEXT, reviewed_by INTEGER,
            FOREIGN KEY(user_id) REFERENCES users(id))""")
        con.execute("""CREATE TABLE IF NOT EXISTS subscriptions (
            user_id INTEGER PRIMARY KEY, plan_name TEXT NOT NULL DEFAULT '3 Months',
            amount INTEGER NOT NULL DEFAULT 2500, starts_at TEXT, expires_at TEXT,
            status TEXT NOT NULL DEFAULT 'unpaid', updated_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id))""")
        con.execute("CREATE INDEX IF NOT EXISTS idx_payments_status ON subscription_payments(status)") 
        con.execute("CREATE INDEX IF NOT EXISTS idx_creator_user_kind ON creator_records(user_id,kind)")

init_db()

def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 310000).hex()
    return salt, digest

def current_user(request):
    uid = request.session.get("uid")
    if not uid:
        return None
    with db() as con:
        row = con.execute("SELECT id,email FROM users WHERE id=?", (uid,)).fetchone()
    return dict(row) if row else None

def require_user(request):
    user = current_user(request)
    if not user:
        raise HTTPException(401, "Please sign in first.")
    return user

ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@jeztech.co.ke").strip().lower()
SUBSCRIPTION_AMOUNT = 2500
SUBSCRIPTION_DAYS = 90

def subscription_for(user_id):
    with db() as con:
        row = con.execute("SELECT * FROM subscriptions WHERE user_id=?", (user_id,)).fetchone()
    if not row:
        return {"status":"unpaid","plan_name":"3 Months","amount":SUBSCRIPTION_AMOUNT,"expires_at":None,"days_remaining":0}
    data = dict(row)
    expires = data.get("expires_at")
    active = bool(expires and datetime.fromisoformat(expires) > datetime.now(timezone.utc))
    data["status"] = "active" if active else ("expired" if expires else data["status"])
    data["days_remaining"] = max(0, (datetime.fromisoformat(expires)-datetime.now(timezone.utc)).days) if active else 0
    return data

def require_paid_user(request):
    user = require_user(request)
    sub = subscription_for(user["id"])
    if sub["status"] != "active":
        raise HTTPException(402, "Subscription required. Pay KSh 2,500 via Paybill 522533, account 8075755, then submit your M-Pesa confirmation code for approval.")
    return user

def require_admin(request):
    user = require_user(request)
    with db() as con:
        row = con.execute("SELECT is_admin FROM users WHERE id=?", (user["id"],)).fetchone()
    if not row or not row["is_admin"]:
        raise HTTPException(403, "Administrator access only.")
    return user

@app.get("/api/subscription/status")
def subscription_status(request: Request):
    user = require_user(request)
    sub = subscription_for(user["id"])
    with db() as con:
        pending = con.execute("SELECT mpesa_code,submitted_at,status FROM subscription_payments WHERE user_id=? ORDER BY id DESC LIMIT 1",(user["id"],)).fetchone()
    return {"amount":SUBSCRIPTION_AMOUNT,"days":SUBSCRIPTION_DAYS,"paybill":"522533","account":"8075755",
            "business":"JEZTECH Enterprises","subscription":sub,"latest_payment":dict(pending) if pending else None}

@app.post("/api/billing/submit")
async def submit_payment(request: Request):
    user = require_user(request)
    body = await request.json()
    code = str(body.get("mpesa_code","")).strip().upper()
    phone = str(body.get("phone","")).strip()
    if not (8 <= len(code) <= 20) or not code.replace(" ","").isalnum():
        raise HTTPException(400,"Enter a valid M-Pesa confirmation code.")
    if len(phone) < 9 or len(phone) > 16:
        raise HTTPException(400,"Enter the phone number used to make payment.")
    now = utc_now()
    try:
        with db() as con:
            con.execute("INSERT INTO subscription_payments(user_id,mpesa_code,payer_phone,amount,status,submitted_at) VALUES(?,?,?,?,?,?)",
                        (user["id"],code,phone,SUBSCRIPTION_AMOUNT,"pending",now))
    except sqlite3.IntegrityError:
        raise HTTPException(409,"That M-Pesa confirmation code has already been submitted.")
    return {"ok":True,"status":"pending","message":"Payment reference submitted. Access activates after JEZTECH Enterprises verifies the payment."}

@app.get("/api/admin/users")
def admin_users(request: Request):
    require_admin(request)
    with db() as con:
        rows=con.execute("""SELECT u.id,u.email,u.created_at,u.is_admin,
            s.status AS subscription_status,s.expires_at,
            (SELECT p.mpesa_code FROM subscription_payments p WHERE p.user_id=u.id ORDER BY p.id DESC LIMIT 1) AS latest_mpesa,
            (SELECT p.status FROM subscription_payments p WHERE p.user_id=u.id ORDER BY p.id DESC LIMIT 1) AS payment_status
            FROM users u LEFT JOIN subscriptions s ON s.user_id=u.id ORDER BY u.id DESC""").fetchall()
    return [dict(r) for r in rows]

@app.get("/api/admin/payments")
def admin_payments(request: Request):
    require_admin(request)
    with db() as con:
        rows=con.execute("""SELECT p.*,u.email FROM subscription_payments p JOIN users u ON u.id=p.user_id
            ORDER BY CASE p.status WHEN 'pending' THEN 0 ELSE 1 END,p.id DESC""").fetchall()
    return [dict(r) for r in rows]

@app.post("/api/admin/payments/{payment_id}/approve")
def approve_payment(payment_id: int, request: Request):
    admin=require_admin(request); now=datetime.now(timezone.utc)
    with db() as con:
        p=con.execute("SELECT * FROM subscription_payments WHERE id=?",(payment_id,)).fetchone()
        if not p: raise HTTPException(404,"Payment not found.")
        if p["status"]=="approved": return {"ok":True,"message":"Payment already approved."}
        if p["status"]!="pending": raise HTTPException(409,"Only pending payments can be approved.")
        existing=con.execute("SELECT expires_at FROM subscriptions WHERE user_id=?",(p["user_id"],)).fetchone()
        prior=datetime.fromisoformat(existing["expires_at"]) if existing and existing["expires_at"] else now
        start=max(now,prior); expiry=start+timedelta(days=SUBSCRIPTION_DAYS)
        con.execute("""INSERT INTO subscriptions(user_id,plan_name,amount,starts_at,expires_at,status,updated_at)
            VALUES(?,?,?,?,?,'active',?) ON CONFLICT(user_id) DO UPDATE SET
            plan_name=excluded.plan_name,amount=excluded.amount,starts_at=excluded.starts_at,
            expires_at=excluded.expires_at,status='active',updated_at=excluded.updated_at""",
            (p["user_id"],"3 Months",SUBSCRIPTION_AMOUNT,start.isoformat(),expiry.isoformat(),now.isoformat()))
        con.execute("UPDATE subscription_payments SET status='approved',reviewed_at=?,reviewed_by=? WHERE id=?",
                    (now.isoformat(),admin["id"],payment_id))
    return {"ok":True,"expires_at":expiry.isoformat()}

@app.post("/api/admin/payments/{payment_id}/reject")
def reject_payment(payment_id: int, request: Request):
    admin=require_admin(request)
    with db() as con:
        cur=con.execute("UPDATE subscription_payments SET status='rejected',reviewed_at=?,reviewed_by=? WHERE id=? AND status='pending'",
                        (utc_now(),admin["id"],payment_id))
        if not cur.rowcount: raise HTTPException(404,"Pending payment not found.")
    return {"ok":True}

@app.post("/api/admin/users/{user_id}/reset-password")
async def admin_reset_password(user_id: int, request: Request):
    require_admin(request); body=await request.json(); password=str(body.get("password",""))
    if len(password)<10: raise HTTPException(400,"Temporary password must be at least 10 characters.")
    salt,digest=hash_password(password)
    with db() as con:
        cur=con.execute("UPDATE users SET salt=?,password_hash=? WHERE id=?",(salt,digest,user_id))
        if not cur.rowcount: raise HTTPException(404,"User not found.")
    return {"ok":True,"message":"Password reset. Share the temporary password securely with the user."}

@app.post("/api/admin/users/{user_id}/subscription")
async def admin_set_subscription(user_id: int, request: Request):
    require_admin(request); body=await request.json(); days=int(body.get("days",90))
    if days not in (0,30,90,180,365): raise HTTPException(400,"Choose 0, 30, 90, 180 or 365 days.")
    with db() as con:
        if not con.execute("SELECT id FROM users WHERE id=?",(user_id,)).fetchone(): raise HTTPException(404,"User not found.")
        now=datetime.now(timezone.utc); expires=(now+timedelta(days=days)).isoformat() if days else None
        con.execute("""INSERT INTO subscriptions(user_id,plan_name,amount,starts_at,expires_at,status,updated_at)
            VALUES(?,?,?,?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET
            starts_at=excluded.starts_at,expires_at=excluded.expires_at,status=excluded.status,updated_at=excluded.updated_at""",
            (user_id,"Admin access",SUBSCRIPTION_AMOUNT,now.isoformat(),expires,"active" if days else "suspended",now.isoformat()))
    return {"ok":True}

def oauth_flow(state=None):
    if not CLIENT_ID or not CLIENT_SECRET:
        raise HTTPException(503, "Google OAuth is not configured. Add GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in Render.")
    config = {
        "web": {
            "client_id": CLIENT_ID, "client_secret": CLIENT_SECRET,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "redirect_uris": [BASE_URL + "/auth/google/callback"]
        }
    }
    flow = Flow.from_client_config(config, scopes=SCOPES, state=state)
    flow.redirect_uri = BASE_URL + "/auth/google/callback"
    return flow

def youtube_credentials(user_id):
    with db() as con:
        row = con.execute("SELECT token_json FROM youtube_tokens WHERE user_id=?", (user_id,)).fetchone()
    if not row:
        raise HTTPException(400, "Connect your YouTube channel first.")
    info = json.loads(row["token_json"])
    creds = Credentials.from_authorized_user_info(info, SCOPES)
    if creds.expired and creds.refresh_token:
        creds.refresh(GoogleRequest())
        with db() as con:
            con.execute("UPDATE youtube_tokens SET token_json=?,updated_at=? WHERE user_id=?",
                        (creds.to_json(), datetime.now(timezone.utc).isoformat(), user_id))
    return creds

@app.get("/health")
def health():
    return {"status": "ok", "service": "LiveConnect Creator Studio"}

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return HTMLResponse((APP_DIR / "templates" / "index.html").read_text())

@app.post("/api/register")
def register(request: Request, email: str = Form(...), password: str = Form(...)):
    email = email.strip().lower()
    if "@" not in email or len(password) < 8:
        raise HTTPException(400, "Enter a valid email and a password of at least 8 characters.")
    salt, digest = hash_password(password)
    try:
        with db() as con:
            cur = con.execute("INSERT INTO users(email,salt,password_hash,created_at,is_admin) VALUES(?,?,?,?,?)",
                              (email, salt, digest, datetime.now(timezone.utc).isoformat(), 1 if email == ADMIN_EMAIL else 0))
            con.execute("INSERT OR IGNORE INTO subscriptions(user_id,plan_name,amount,status,updated_at) VALUES(?,?,?,?,?)",
                        (cur.lastrowid,"3 Months",SUBSCRIPTION_AMOUNT,"unpaid",utc_now()))
            request.session.clear()
            request.session["uid"] = cur.lastrowid
    except sqlite3.IntegrityError:
        raise HTTPException(409, "An account with that email already exists.")
    return {"ok": True, "email": email}

@app.post("/api/login")
def login(request: Request, email: str = Form(...), password: str = Form(...)):
    with db() as con:
        row = con.execute("SELECT * FROM users WHERE email=?", (email.strip().lower(),)).fetchone()
    if not row:
        raise HTTPException(401, "Email or password is incorrect.")
    _, digest = hash_password(password, row["salt"])
    if not hmac.compare_digest(digest, row["password_hash"]):
        raise HTTPException(401, "Email or password is incorrect.")
    request.session.clear()
    request.session["uid"] = row["id"]
    return {"ok": True, "email": row["email"]}

@app.post("/api/logout")
def logout(request: Request):
    request.session.clear()
    return {"ok": True}

@app.get("/api/me")
def me(request: Request):
    user = current_user(request)
    if not user:
        return {"signed_in": False}
    with db() as con:
        row = con.execute("SELECT channel_title,channel_id FROM youtube_tokens WHERE user_id=?", (user["id"],)).fetchone()
    with db() as con:
        admin_row=con.execute("SELECT is_admin FROM users WHERE id=?",(user["id"],)).fetchone()
    return {"signed_in": True, "email": user["email"], "youtube_connected": bool(row),
            "channel_title": row["channel_title"] if row else None,
            "is_admin": bool(admin_row and admin_row["is_admin"]),
            "subscription": subscription_for(user["id"])}

@app.get("/auth/google")
def google_login(request: Request):
    require_user(request)
    flow = oauth_flow()
    url, state = flow.authorization_url(access_type="offline", include_granted_scopes="true",
                                          prompt="consent")
    request.session["oauth_state"] = state
    return RedirectResponse(url)

@app.get("/auth/google/callback")
def google_callback(request: Request, state: str = "", code: str = "", error: str = ""):
    user = require_user(request)
    if error:
        raise HTTPException(400, "Google authorization was not completed: " + error)
    expected = request.session.pop("oauth_state", None)
    if not expected or not hmac.compare_digest(expected, state):
        raise HTTPException(400, "OAuth state validation failed. Please connect again.")
    flow = oauth_flow(state=state)
    flow.fetch_token(code=code)
    creds = flow.credentials
    yt = build("youtube", "v3", credentials=creds, cache_discovery=False)
    response = yt.channels().list(part="snippet", mine=True).execute()
    items = response.get("items", [])
    channel = items[0] if items else {}
    snippet = channel.get("snippet", {})
    with db() as con:
        con.execute("""INSERT INTO youtube_tokens(user_id,token_json,channel_title,channel_id,updated_at)
            VALUES(?,?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET token_json=excluded.token_json,
            channel_title=excluded.channel_title,channel_id=excluded.channel_id,updated_at=excluded.updated_at""",
            (user["id"], creds.to_json(), snippet.get("title", "YouTube channel"),
             channel.get("id", ""), datetime.now(timezone.utc).isoformat()))
    return RedirectResponse("/?youtube=connected")

@app.get("/api/youtube/channel")
def channel(request: Request):
    user = require_user(request)
    creds = youtube_credentials(user["id"])
    yt = build("youtube", "v3", credentials=creds, cache_discovery=False)
    result = yt.channels().list(part="snippet,statistics", mine=True).execute()
    return result.get("items", [])

@app.post("/api/youtube/broadcast")
async def create_broadcast(request: Request):
    user = require_paid_user(request)
    body = await request.json()
    title = str(body.get("title", "LiveConnect Broadcast")).strip()[:100]
    description = str(body.get("description", "Live stream created with LiveConnect")).strip()[:5000]
    privacy = body.get("privacy", "unlisted")
    if not title:
        raise HTTPException(400, "Broadcast title is required.")
    if privacy not in ("public", "unlisted", "private"):
        raise HTTPException(400, "Invalid privacy setting.")
    try:
        start = datetime.now(timezone.utc) + timedelta(minutes=5)
        creds = youtube_credentials(user["id"])
        yt = build("youtube", "v3", credentials=creds, cache_discovery=False)
        broadcast = yt.liveBroadcasts().insert(
            part="snippet,status,contentDetails",
            body={"snippet":{"title":title,"description":description,
                             "scheduledStartTime":start.isoformat().replace("+00:00","Z")},
                  "status":{"privacyStatus":privacy},
                  "contentDetails":{"enableAutoStart":False,"enableAutoStop":False}}
        ).execute()
        try:
            stream = yt.liveStreams().insert(
                part="snippet,cdn,contentDetails,status",
                body={"snippet":{"title":title + " - LiveConnect ingest"},
                      "cdn":{"ingestionType":"rtmp","resolution":"variable","frameRate":"variable"},
                      "contentDetails":{"isReusable":False}}
            ).execute()
            yt.liveBroadcasts().bind(part="id,contentDetails", id=broadcast["id"],
                                     streamId=stream["id"]).execute()
        except Exception:
            # Remove an unbound scheduled broadcast if stream setup fails.
            try:
                yt.liveBroadcasts().delete(id=broadcast["id"]).execute()
            except Exception:
                pass
            raise
        ingest = stream.get("cdn", {}).get("ingestionInfo", {})
        return {"ok":True,"broadcast_id":broadcast["id"],"watch_url":"https://www.youtube.com/watch?v="+broadcast["id"],
                "rtmp_url":ingest.get("ingestionAddress"),"stream_key":ingest.get("streamName"),
                "scheduled_start":broadcast.get("snippet",{}).get("scheduledStartTime"),
                "obs_note":"Enter the RTMP URL as Server and the stream key as Stream Key in OBS. Keep the key private."}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(502, "YouTube could not create the broadcast. Check that live streaming is enabled for your channel, YouTube Data API v3 is enabled, and the connected Google account has the required permissions.")


@app.post("/api/youtube/live/start")
async def start_browser_youtube_live(request: Request):
    user = require_paid_user(request)
    body = await request.json()
    title = str(body.get("title", "LiveConnect Browser Stream")).strip()[:100]
    privacy = body.get("privacyStatus", "unlisted")
    description = str(body.get("description", "Live stream created with LiveConnect")).strip()[:5000]
    if not title or privacy not in ("public", "unlisted", "private"):
        raise HTTPException(400, "Enter a title and valid privacy status.")
    try:
        creds = youtube_credentials(user["id"])
        yt = build("youtube", "v3", credentials=creds, cache_discovery=False)
        scheduled = datetime.now(timezone.utc) + timedelta(minutes=5)
        broadcast = yt.liveBroadcasts().insert(part="snippet,status,contentDetails", body={
            "snippet": {"title": title, "description": description,
                        "scheduledStartTime": scheduled.isoformat().replace("+00:00", "Z")},
            "status": {"privacyStatus": privacy, "selfDeclaredMadeForKids": False},
            "contentDetails": {"enableAutoStart": True, "enableAutoStop": True}
        }).execute()
        try:
            stream = yt.liveStreams().insert(part="snippet,cdn,contentDetails,status", body={
                "snippet": {"title": title + " - LiveConnect Browser Ingest"},
                "cdn": {"ingestionType": "rtmp", "resolution": "variable", "frameRate": "variable"},
                "contentDetails": {"isReusable": False}
            }).execute()
            yt.liveBroadcasts().bind(part="id,contentDetails", id=broadcast["id"], streamId=stream["id"]).execute()
        except Exception:
            try: yt.liveBroadcasts().delete(id=broadcast["id"]).execute()
            except Exception: pass
            raise
        ingest = stream.get("cdn", {}).get("ingestionInfo", {})
        address, key = ingest.get("ingestionAddress"), ingest.get("streamName")
        if not address or not key: raise RuntimeError("Missing YouTube RTMP ingest details.")
        PENDING_LIVE_TARGETS[(user["id"], broadcast["id"])] = {
            "rtmp": address.rstrip("/") + "/" + key, "created": time.time()
        }
        return {"ok": True, "broadcastId": broadcast["id"], "streamId": stream["id"],
                "watchUrl": "https://www.youtube.com/watch?v=" + broadcast["id"],
                "websocketPath": "/ws/youtube-stream/" + broadcast["id"],
                "scheduledStartTime": broadcast.get("snippet", {}).get("scheduledStartTime")}
    except HTTPException: raise
    except Exception:
        raise HTTPException(502, "YouTube could not provision this stream. Check OAuth, live-stream eligibility and YouTube Data API v3.")

@app.websocket("/ws/youtube-stream/{broadcast_id}")
async def youtube_stream_relay(websocket: WebSocket, broadcast_id: str):
    user_id = websocket.scope.get("session", {}).get("uid")
    if not user_id:
        await websocket.close(code=4401, reason="Sign in required")
        return
    if subscription_for(user_id)["status"] != "active":
        await websocket.close(code=4402, reason="Active subscription required")
        return
    target = PENDING_LIVE_TARGETS.get((user_id, broadcast_id))
    if not target or time.time() - target["created"] > 7200:
        await websocket.close(code=4404, reason="Live session missing or expired")
        return
    if (user_id, broadcast_id) in ACTIVE_ENCODERS:
        await websocket.close(code=4409, reason="Encoder already active")
        return
    await websocket.accept()
    ffmpeg = None
    try:
        ffmpeg = subprocess.Popen([
            "ffmpeg", "-hide_banner", "-loglevel", "warning", "-i", "pipe:0",
            "-map", "0:v:0", "-map", "0:a:0?",
            "-c:v", "libx264", "-preset", "veryfast", "-tune", "zerolatency",
            "-b:v", "2500k", "-maxrate", "3000k", "-bufsize", "5000k",
            "-pix_fmt", "yuv420p", "-g", "60", "-c:a", "aac", "-b:a", "128k",
            "-ar", "44100", "-f", "flv", target["rtmp"]
        ], stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, bufsize=0)
        ACTIVE_ENCODERS[(user_id, broadcast_id)] = ffmpeg
        await websocket.send_json({"status": "encoder_started", "broadcastId": broadcast_id})
        while True:
            message = await websocket.receive()
            if message.get("type") == "websocket.disconnect": break
            if message.get("bytes") is not None:
                chunk = message["bytes"]
                if len(chunk) > 8 * 1024 * 1024:
                    await websocket.close(code=4400, reason="Chunk too large")
                    break
                if ffmpeg.poll() is not None:
                    await websocket.send_json({"status": "encoder_failed"})
                    break
                if ffmpeg.stdin and not ffmpeg.stdin.closed:
                    await asyncio.to_thread(ffmpeg.stdin.write, chunk)
            elif message.get("text"):
                try: control = json.loads(message["text"])
                except Exception: continue
                if control.get("type") == "end": break
    except WebSocketDisconnect: pass
    except Exception:
        try: await websocket.send_json({"status": "relay_error"})
        except Exception: pass
    finally:
        ACTIVE_ENCODERS.pop((user_id, broadcast_id), None)
        if ffmpeg:
            try:
                if ffmpeg.stdin and not ffmpeg.stdin.closed: ffmpeg.stdin.close()
                try: ffmpeg.wait(timeout=12)
                except subprocess.TimeoutExpired:
                    ffmpeg.terminate()
                    try: ffmpeg.wait(timeout=4)
                    except subprocess.TimeoutExpired: ffmpeg.kill()
            except Exception:
                try: ffmpeg.kill()
                except Exception: pass
        PENDING_LIVE_TARGETS.pop((user_id, broadcast_id), None)
        try: await websocket.close()
        except Exception: pass

@app.get("/api/youtube/broadcasts")
def broadcasts(request: Request):
    user = require_user(request)
    creds = youtube_credentials(user["id"])
    yt = build("youtube", "v3", credentials=creds, cache_discovery=False)
    return yt.liveBroadcasts().list(part="snippet,status", broadcastStatus="upcoming", maxResults=20).execute().get("items", [])



@app.get("/api/youtube/live-chat")
def youtube_live_chat(request: Request, page_token: str = ""):
    user = require_user(request)
    creds = youtube_credentials(user["id"])
    yt = build("youtube", "v3", credentials=creds, cache_discovery=False)
    try:
        active = yt.liveBroadcasts().list(part="snippet,status,contentDetails",
            broadcastStatus="active", maxResults=5).execute().get("items", [])
        if not active:
            return {"active": False, "messages": [], "message": "No active YouTube broadcast. Start streaming from OBS first."}
        chat_id = active[0].get("snippet", {}).get("liveChatId")
        if not chat_id:
            return {"active": False, "messages": [], "message": "YouTube has not supplied a live chat for this broadcast."}
        params = {"liveChatId": chat_id, "part": "snippet,authorDetails", "maxResults": 50}
        if page_token:
            params["pageToken"] = page_token
        result = yt.liveChatMessages().list(**params).execute()
        messages = []
        for item in result.get("items", []):
            snippet = item.get("snippet", {})
            author = item.get("authorDetails", {})
            messages.append({"id": item.get("id"), "author": author.get("displayName", "Viewer"),
                "text": snippet.get("displayMessage", ""), "published_at": snippet.get("publishedAt", ""),
                "type": snippet.get("type", "")})
        return {"active": True, "messages": messages, "next_page_token": result.get("nextPageToken"),
                "polling_interval_ms": result.get("pollingIntervalMillis", 5000)}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(502, "Could not read YouTube Live chat. Confirm the channel is connected and an active broadcast has chat enabled.")

@app.post("/api/youtube/live-chat")
async def send_youtube_live_chat(request: Request):
    user = require_user(request)
    body = await request.json()
    message = str(body.get("message", "")).strip()
    if not message or len(message) > 200:
        raise HTTPException(400, "Enter a chat message of 1–200 characters.")
    creds = youtube_credentials(user["id"])
    yt = build("youtube", "v3", credentials=creds, cache_discovery=False)
    try:
        active = yt.liveBroadcasts().list(part="snippet", broadcastStatus="active", maxResults=5).execute().get("items", [])
        chat_id = active[0].get("snippet", {}).get("liveChatId") if active else None
        if not chat_id:
            raise HTTPException(409, "No active broadcast chat is available.")
        result = yt.liveChatMessages().insert(part="snippet", body={
            "snippet": {"liveChatId": chat_id, "type": "textMessageEvent",
                        "textMessageDetails": {"messageText": message}}
        }).execute()
        return {"ok": True, "id": result.get("id")}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(502, "YouTube could not send this chat message. Check channel permissions and live chat status.")

def utc_now():
    return datetime.now(timezone.utc).isoformat()

def record_out(row):
    return {"id":row["id"],"kind":row["kind"],"title":row["title"],"payload":json.loads(row["payload"]),"created_at":row["created_at"],"updated_at":row["updated_at"]}

@app.get("/api/creator/records")
def list_creator_records(request:Request, kind:str=""):
    user=require_user(request)
    with db() as con:
        rows=con.execute("SELECT * FROM creator_records WHERE user_id=? AND (?='' OR kind=?) ORDER BY updated_at DESC",(user["id"],kind,kind)).fetchall()
    return [record_out(r) for r in rows]

@app.post("/api/creator/records")
async def save_creator_record(request:Request):
    user=require_user(request); body=await request.json(); kind=str(body.get("kind","")).lower(); title=str(body.get("title","Untitled"))[:180]; payload=body.get("payload",{})
    if kind not in {"speaker","slide","template","scripture","lyric","announcement","scene"} or not isinstance(payload,dict): raise HTTPException(400,"Invalid creator record.")
    now=utc_now()
    with db() as con:
        cur=con.execute("INSERT INTO creator_records(user_id,kind,title,payload,created_at,updated_at) VALUES(?,?,?,?,?,?)",(user["id"],kind,title,json.dumps(payload),now,now))
        return record_out(con.execute("SELECT * FROM creator_records WHERE id=?",(cur.lastrowid,)).fetchone())

@app.put("/api/creator/records/{rid}")
async def update_creator_record(rid:int,request:Request):
    user=require_user(request); body=await request.json()
    with db() as con:
        row=con.execute("SELECT * FROM creator_records WHERE id=? AND user_id=?",(rid,user["id"])).fetchone()
        if not row: raise HTTPException(404,"Record not found.")
        payload=body.get("payload",json.loads(row["payload"]))
        con.execute("UPDATE creator_records SET title=?,payload=?,updated_at=? WHERE id=?",(str(body.get("title",row["title"]))[:180],json.dumps(payload),utc_now(),rid))
        return record_out(con.execute("SELECT * FROM creator_records WHERE id=?",(rid,)).fetchone())

@app.delete("/api/creator/records/{rid}")
def delete_creator_record(rid:int,request:Request):
    user=require_user(request)
    with db() as con:
        cur=con.execute("DELETE FROM creator_records WHERE id=? AND user_id=?",(rid,user["id"]))
        if not cur.rowcount: raise HTTPException(404,"Record not found.")
    return {"ok":True}

@app.post("/api/media/upload")
async def upload_media(request:Request,file:UploadFile=File(...)):
    user=require_user(request); name=Path(file.filename or "upload.bin").name[:180]; mime=file.content_type or mimetypes.guess_type(name)[0] or "application/octet-stream"
    allowed=("video/","image/","audio/","application/pdf","application/vnd.openxmlformats-officedocument.presentationml.presentation")
    if not mime.startswith(allowed): raise HTTPException(415,"Upload a video, image, audio file, PDF or PPTX.")
    data=await file.read(300*1024*1024+1)
    if not data or len(data)>300*1024*1024: raise HTTPException(413,"File is empty or exceeds 300 MB.")
    with db() as con:
        cur=con.execute("INSERT INTO media_assets(user_id,name,mime_type,data,size,created_at) VALUES(?,?,?,?,?,?)",(user["id"],name,mime,data,len(data),utc_now()))
    return {"id":cur.lastrowid,"name":name,"mime_type":mime,"size":len(data)}

@app.get("/api/media")
def list_media(request:Request):
    user=require_user(request)
    with db() as con: rows=con.execute("SELECT id,name,mime_type,size,created_at FROM media_assets WHERE user_id=? ORDER BY id DESC",(user["id"],)).fetchall()
    return [dict(r) for r in rows]

@app.get("/api/media/{asset_id}")
def get_media(asset_id:int,request:Request):
    user=require_user(request)
    with db() as con: row=con.execute("SELECT name,mime_type,data FROM media_assets WHERE id=? AND user_id=?",(asset_id,user["id"])).fetchone()
    if not row: raise HTTPException(404,"Media not found.")
    return Response(row["data"],media_type=row["mime_type"],headers={"Content-Disposition":'inline; filename="'+row["name"].replace('"','')+'"'})

@app.delete("/api/media/{asset_id}")
def delete_media(asset_id:int,request:Request):
    user=require_user(request)
    with db() as con: cur=con.execute("DELETE FROM media_assets WHERE id=? AND user_id=?",(asset_id,user["id"]))
    if not cur.rowcount: raise HTTPException(404,"Media not found.")
    return {"ok":True}

@app.post("/api/media/{asset_id}/trim")
async def trim_media(asset_id:int,request:Request):
    user=require_user(request); body=await request.json(); start=max(0,float(body.get("start",0))); end=float(body.get("end",0))
    if end<=start or end-start>7200: raise HTTPException(400,"Invalid trim range; maximum two hours.")
    with db() as con: row=con.execute("SELECT name,data FROM media_assets WHERE id=? AND user_id=?",(asset_id,user["id"])).fetchone()
    if not row: raise HTTPException(404,"Source clip not found.")
    with tempfile.TemporaryDirectory() as tmp:
        src=Path(tmp)/"input"; out=Path(tmp)/"trimmed.mp4"; src.write_bytes(row["data"])
        try:
            subprocess.run(["ffmpeg","-hide_banner","-loglevel","error","-ss",str(start),"-i",str(src),"-t",str(end-start),"-map","0:v:0?","-map","0:a:0?","-c:v","libx264","-preset","veryfast","-crf","23","-c:a","aac","-movflags","+faststart","-y",str(out)],check=True,capture_output=True,timeout=900)
        except FileNotFoundError: raise HTTPException(503,"FFmpeg is unavailable on this server.")
        except subprocess.TimeoutExpired: raise HTTPException(504,"Clip export timed out.")
        except subprocess.CalledProcessError as e: raise HTTPException(422,"FFmpeg could not process this clip: "+(e.stderr or b"").decode(errors="replace")[-500:])
        data=out.read_bytes()
    name=Path(row["name"]).stem+"_trimmed.mp4"
    with db() as con:
        cur=con.execute("INSERT INTO media_assets(user_id,name,mime_type,data,size,created_at) VALUES(?,?,?,?,?,?)",(user["id"],name,"video/mp4",data,len(data),utc_now()))
    return {"ok":True,"id":cur.lastrowid,"name":name,"download_url":f"/api/media/{cur.lastrowid}"}

@app.get("/overlay/live",response_class=HTMLResponse)
def live_overlay(request:Request):
    require_user(request)
    return HTMLResponse("""<!doctype html><html><head><meta charset=utf-8><style>html,body{margin:0;background:transparent;color:white;font-family:Arial;overflow:hidden}#stage{position:absolute;inset:0;display:flex;align-items:flex-end;justify-content:center;padding:4vw}#box{max-width:90vw;padding:20px 34px;background:rgba(5,9,20,.78);font-size:36px;font-weight:bold;text-align:center;text-shadow:0 2px 8px #000}</style></head><body><div id=stage><div id=box></div></div><script>async function poll(){try{let j=await(await fetch('/api/creator/overlay-state')).json(),b=document.getElementById('box'),s=document.getElementById('stage');b.textContent=j.text||'';b.style.display=j.visible?'block':'none';b.style.color=j.color||'#fff';b.style.fontSize=(j.size||36)+'px';s.style.justifyContent=j.position==='left'?'flex-start':j.position==='right'?'flex-end':'center';s.style.alignItems=j.position==='top'?'flex-start':j.position==='center'?'center':'flex-end'}catch(e){}setTimeout(poll,800)}poll()</script></body></html>""")

@app.get("/api/creator/overlay-state")
def overlay_state(request:Request):
    user=require_user(request)
    with db() as con: row=con.execute("SELECT payload FROM creator_records WHERE user_id=? AND kind='scene' ORDER BY id DESC LIMIT 1",(user["id"],)).fetchone()
    return json.loads(row["payload"]) if row else {"visible":False,"text":""}

@app.post("/api/creator/overlay-state")
async def set_overlay_state(request:Request):
    user=require_user(request); b=await request.json()
    p={"visible":bool(b.get("visible",True)),"text":str(b.get("text",""))[:4000],"position":b.get("position","bottom"),"color":b.get("color","#fff"),"size":max(14,min(100,int(b.get("size",36))))}
    with db() as con:
        row=con.execute("SELECT id,payload FROM creator_records WHERE user_id=? AND kind='scene' ORDER BY id DESC LIMIT 1",(user["id"],)).fetchone()
        if row:
            old=json.loads(row["payload"]); p["token"]=old.get("token")
            con.execute("UPDATE creator_records SET payload=?,updated_at=? WHERE id=?",(json.dumps(p),utc_now(),row["id"]))
        else: con.execute("INSERT INTO creator_records(user_id,kind,title,payload,created_at,updated_at) VALUES(?,?,?,?,?,?)",(user["id"],"scene","Live overlay",json.dumps(p),utc_now(),utc_now()))
    return {"ok":True,"state":p}

@app.get("/api/creator/overlay-url")
def create_overlay_url(request:Request):
    user=require_user(request)
    with db() as con:
        row=con.execute("SELECT id,payload FROM creator_records WHERE user_id=? AND kind='scene' ORDER BY id DESC LIMIT 1",(user["id"],)).fetchone()
        payload=json.loads(row["payload"]) if row else {"visible":False,"text":""}
        token=payload.get("token") or secrets.token_urlsafe(32)
        payload["token"]=token
        now=utc_now()
        if row: con.execute("UPDATE creator_records SET payload=?,updated_at=? WHERE id=?",(json.dumps(payload),now,row["id"]))
        else: con.execute("INSERT INTO creator_records(user_id,kind,title,payload,created_at,updated_at) VALUES(?,?,?,?,?,?)",(user["id"],"scene","OBS overlay",json.dumps(payload),now,now))
    return {"url":BASE_URL+"/overlay/"+token}

@app.get("/overlay/{token}",response_class=HTMLResponse)
def public_overlay(token:str):
    return HTMLResponse("""<!doctype html><html><head><meta charset=utf-8><style>html,body{margin:0;background:transparent;color:white;font-family:Arial;overflow:hidden}#stage{position:absolute;inset:0;display:flex;align-items:flex-end;justify-content:center;padding:4vw}#box{max-width:90vw;padding:20px 34px;background:rgba(5,9,20,.78);font-size:36px;font-weight:bold;text-align:center;text-shadow:0 2px 8px #000;white-space:pre-wrap}</style></head><body><div id=stage><div id=box></div></div><script>const token="""+json.dumps(token)+""";async function poll(){try{let j=await(await fetch('/api/public/overlay-state/'+encodeURIComponent(token))).json(),b=document.getElementById('box'),s=document.getElementById('stage');b.textContent=j.text||'';b.style.display=j.visible?'block':'none';b.style.color=j.color||'#fff';b.style.fontSize=(j.size||36)+'px';s.style.justifyContent=j.position==='left'?'flex-start':j.position==='right'?'flex-end':'center';s.style.alignItems=j.position==='top'?'flex-start':j.position==='center'?'center':'flex-end'}catch(e){}setTimeout(poll,700)}poll()</script></body></html>""")

@app.get("/api/public/overlay-state/{token}")
def public_overlay_state(token:str):
    with db() as con: rows=con.execute("SELECT payload FROM creator_records WHERE kind='scene' ORDER BY id DESC LIMIT 100").fetchall()
    for row in rows:
        p=json.loads(row["payload"])
        saved=p.pop("token",None)
        if saved and hmac.compare_digest(saved,token): return p
    raise HTTPException(404,"Overlay token is invalid or has been rotated.")

@app.get("/api/config")
def config():
    return {"google_oauth_configured": bool(CLIENT_ID and CLIENT_SECRET),
            "base_url_configured": BASE_URL != "http://localhost:10000"}
