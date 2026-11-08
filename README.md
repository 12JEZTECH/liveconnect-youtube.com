# LiveConnect YouTube Creator Studio

LiveConnect is a starter web application for managing YouTube Live broadcasts.

## Included in this release

- Email/password registration and login.
- Google OAuth connection to a YouTube channel.
- YouTube Data API v3 integration to create a scheduled live broadcast and RTMP ingest stream.
- Browser camera preview with device switching, zoom, rotation, brightness, contrast and saturation controls.
- OBS setup information and a private RTMP stream key display.
- Dockerfile and Render Blueprint configuration.

## Important scope and production notes

This release creates and binds YouTube Live broadcasts. **OBS (or another RTMP encoder) sends the actual video/audio to YouTube.** The browser camera panel is a local preview and image-adjustment panel; it does not itself publish a browser camera feed to YouTube.

Remote phone-to-browser WebRTC relay, TURN infrastructure, team workspaces, password reset/email verification, billing, and a production-grade persistent database are not included in this first release.

The Render Blueprint now mounts a persistent disk at `/var/data` and stores the SQLite database at `/var/data/liveconnect.db`, so account and OAuth-token rows survive ordinary deploys. This is a small single-instance starter configuration, not a high-availability database. For a larger production service, migrate to managed PostgreSQL, encrypt stored OAuth refresh tokens, configure backups, add rate limiting and account recovery, and use HTTPS.

## Run locally (Windows PowerShell)

1. Install Python 3.12 or newer.
2. In this folder, create and activate a virtual environment:

   ```powershell
   py -3.12 -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   ```

3. Set environment variables:

   ```powershell
   $env:SECRET_KEY="replace-with-a-long-random-secret"
   $env:BASE_URL="http://localhost:10000"
   $env:GOOGLE_CLIENT_ID="your-google-oauth-client-id"
   $env:GOOGLE_CLIENT_SECRET="your-google-oauth-client-secret"
   ```

4. Start the app:

   ```powershell
   uvicorn main:app --reload --port 10000
   ```

5. Open http://localhost:10000.

## Configure Google / YouTube OAuth

1. Open Google Cloud Console and create/select a project.
2. Enable **YouTube Data API v3**.
3. Configure the OAuth consent screen and add the test users required while the app is in testing.
4. Create an OAuth client ID of type **Web application**.
5. Add this Authorized redirect URI:
   - Local: `http://localhost:10000/auth/google/callback`
   - Render: `https://YOUR-RENDER-DOMAIN/auth/google/callback`
6. Set `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, and `BASE_URL` in the Render service environment. Never commit OAuth secrets to GitHub.
7. Your YouTube channel must have live streaming enabled and be eligible to create broadcasts.

Google may require OAuth app verification before unrestricted public use. The YouTube API has quota limits and may reject broadcast creation if the channel is not eligible.

## Deploy on Render

The repository includes `render.yaml` and a Dockerfile. In Render:

1. Choose **New → Blueprint** and select this GitHub repository, or create a Docker web service from the repository.
2. Add `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` as secret environment variables. The app reads Render's `RENDER_EXTERNAL_URL` automatically for its OAuth callback and secure cookies; set `BASE_URL` only if using a custom domain.
3. After the first service is created, copy its HTTPS URL and add `https://YOUR-RENDER-DOMAIN/auth/google/callback` to the Google OAuth client's Authorized redirect URIs.
4. Deploy and verify `/health` returns JSON with status `ok`.

The Blueprint uses a Starter instance and a 1 GB persistent disk as a starting point. The persistent disk means the service must remain single-instance; do not scale it horizontally while using SQLite. The Google OAuth client secret and client ID are intentionally marked as values you must supply in Render. Never commit real credentials to GitHub.

## OBS workflow

1. Sign in to LiveConnect and connect YouTube.
2. Create a broadcast and copy the RTMP server and stream key.
3. In OBS, open **Settings → Stream**, select **Custom**, and paste the server and stream key.
4. Configure your camera/microphone sources in OBS and click **Start Streaming**.
5. Keep the stream key secret. Regenerate it if it is exposed.

## API endpoints

- `GET /` — Creator Studio UI
- `GET /health` — health check
- `POST /api/register` — create an account
- `POST /api/login` — sign in
- `POST /api/logout` — sign out
- `GET /api/me` — current session status
- `GET /auth/google` — begin Google OAuth
- `GET /auth/google/callback` — OAuth callback
- `GET /api/youtube/channel` — connected channel information
- `POST /api/youtube/broadcast` — create and bind a YouTube Live broadcast and RTMP stream
- `GET /api/youtube/broadcasts` — list upcoming broadcasts

## Security

Do not share the stream key or OAuth client secret. Use a unique random `SECRET_KEY` in deployment. Before public production use, add encrypted token storage, CSRF protection for all state-changing routes, rate limiting, email verification, password reset, database migrations, audit logging and automated backups.
