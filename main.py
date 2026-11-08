import os, sqlite3, hashlib, hmac, secrets, json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
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
            salt TEXT NOT NULL, password_hash TEXT NOT NULL, created_at TEXT NOT NULL)""")
        con.execute("""CREATE TABLE IF NOT EXISTS youtube_tokens (
            user_id INTEGER PRIMARY KEY, token_json TEXT NOT NULL, channel_title TEXT,
            channel_id TEXT, updated_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id))""")
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
            cur = con.execute("INSERT INTO users(email,salt,password_hash,created_at) VALUES(?,?,?,?)",
                              (email, salt, digest, datetime.now(timezone.utc).isoformat()))
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
    return {"signed_in": True, "email": user["email"], "youtube_connected": bool(row),
            "channel_title": row["channel_title"] if row else None}

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
    user = require_user(request)
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

@app.get("/api/youtube/broadcasts")
def broadcasts(request: Request):
    user = require_user(request)
    creds = youtube_credentials(user["id"])
    yt = build("youtube", "v3", credentials=creds, cache_discovery=False)
    return yt.liveBroadcasts().list(part="snippet,status", broadcastStatus="upcoming", maxResults=20).execute().get("items", [])

@app.get("/api/config")
def config():
    return {"google_oauth_configured": bool(CLIENT_ID and CLIENT_SECRET),
            "base_url_configured": BASE_URL != "http://localhost:10000"}
