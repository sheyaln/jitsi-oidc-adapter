# jitsi-oidc-adapter

OIDC-to-JWT bridge for Jitsi Meet. Authenticates meeting hosts through any
OpenID Connect provider and issues Jitsi-compatible JWT tokens. Guests can
join without authenticating -- they wait in the lobby until a host arrives.

## Background

This project was is heavily based on
[aadpM2hhdixoJm3u/jitsi-OIDC-adapter](https://github.com/aadpM2hhdixoJm3u/jitsi-OIDC-adapter),
who did the hard work of figuring out how to wedge OIDC into Jitsi's
JWT auth flow. That project runs as a bare-metal Python service configured
via INI files.

We needed something that works as a Docker container alongside Jitsi's
own Docker deployment, configured entirely through environment variables.
After auditing the original code, I found enough issues (secrets logged
at debug level, no HTTP timeouts, room-wildcard JWTs, missing claims,
hardcoded fallbacks) that a clean rewrite made more sense than a patch.

What changed:

- **Docker-native** -- Dockerfile, gunicorn, env vars, no config files
- **No secrets in logs** -- debug logging never prints credentials
- **HTTP timeouts** -- all outbound requests have a 10s timeout
- **Room-scoped JWTs** -- tokens are locked to the room being joined
- **Standard OIDC claims** -- tries `name`, `preferred_username`,
  `displayName` in that order instead of only `displayName`
- **Proper JWT claims** -- includes `iat`, `nbf`, `sub`, 3h expiry
- **Health check** -- `/oidc/health` for container orchestration
- **No error leaks** -- exception details stay in server logs

## How it works

1. User tries to join a Jitsi room
2. Jitsi redirects to `/oidc/auth?room={room}`
3. Adapter redirects to the OIDC provider (Authentik, Keycloak, Auth0, etc.)
4. User authenticates with the provider
5. Provider redirects back to `/oidc/redirect` with an auth code
6. Adapter exchanges the code for tokens, validates the ID token
7. Adapter issues a Jitsi JWT scoped to the room
8. User lands in the meeting as an authenticated host

## Configuration

All configuration is via environment variables:

| Variable | Required | Default | Description |
|---|---|---|---|
| `OIDC_CLIENT_ID` | yes | | OAuth2 client ID |
| `OIDC_CLIENT_SECRET` | yes | | OAuth2 client secret |
| `OIDC_DISCOVERY_URL` | yes | | OIDC discovery endpoint (`.well-known/openid-configuration`) |
| `OIDC_SCOPE` | no | `openid email profile` | Scopes to request |
| `JITSI_BASE_URL` | yes | | Public URL of your Jitsi instance (e.g. `https://meet.example.com`) |
| `JWT_APP_ID` | no | `jitsi` | Must match Jitsi's `JWT_APP_ID` |
| `JWT_APP_SECRET` | yes | | Must match Jitsi's `JWT_APP_SECRET` |
| `JWT_SUBJECT` | no | `meet.example.com` | JWT `sub` claim, typically your Jitsi domain |
| `LOG_LEVEL` | no | `INFO` | Python log level |

## Running with Docker Compose

The adapter runs as a sidecar alongside the standard Jitsi Docker containers.
Here's the relevant snippet:

```yaml
services:
  jitsi-oidc-adapter:
    build: ./jitsi-oidc-adapter
    # or: image: ghcr.io/dciww/jitsi-oidc-adapter:latest
    restart: unless-stopped
    environment:
      OIDC_CLIENT_ID: ${OIDC_CLIENT_ID}
      OIDC_CLIENT_SECRET: ${OIDC_CLIENT_SECRET}
      OIDC_DISCOVERY_URL: ${OIDC_DISCOVERY_URL}
      JITSI_BASE_URL: https://meet.example.com
      JWT_APP_ID: ${JWT_APP_ID}
      JWT_APP_SECRET: ${JWT_APP_SECRET}
      JWT_SUBJECT: meet.example.com
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.jitsi-oidc.rule=Host(`meet.example.com`) && PathPrefix(`/oidc`)"
      - "traefik.http.services.jitsi-oidc.loadbalancer.server.port=8000"
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/oidc/health"]
      interval: 30s
      timeout: 5s
      retries: 3
```

Your Jitsi web container needs these env vars to enable JWT auth and point
unauthenticated users at the adapter:

```
AUTH_TYPE=jwt
TOKEN_AUTH_URL=https://meet.example.com/oidc/auth?room={room}
ENABLE_GUESTS=1
```

## Running without Docker

```sh
pip install -r requirements.txt
export OIDC_CLIENT_ID=...
export OIDC_CLIENT_SECRET=...
export OIDC_DISCOVERY_URL=https://your-idp.com/.well-known/openid-configuration
export JITSI_BASE_URL=https://meet.example.com
export JWT_APP_SECRET=...
gunicorn --bind 0.0.0.0:8000 --workers 2 app:app
```

Then point your reverse proxy's `/oidc/*` paths at port 8000.

## body.html

The `body.html` file contains JavaScript that intercepts Jitsi's "I am the
host" login dialog and redirects to `/oidc/auth` instead. Mount or copy it
to your Jitsi web container's document root and configure Jitsi to serve it:

```
# In your Jitsi web container or Nginx config
set $body_html_location /path/to/body.html;
location = /body.html {
    alias $body_html_location;
}
```

## License

Apache License 2.0
