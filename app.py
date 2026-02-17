"""
Jitsi OIDC Adapter

OIDC-to-JWT bridge for Jitsi Meet. Authenticates meeting hosts via any
OpenID Connect provider and issues Jitsi-compatible JWT tokens.

See README.md for configuration and deployment.
"""

import os
import datetime
import hashlib
import secrets
import logging
import base64

from flask import Flask, request, session, url_for, redirect
from authlib.integrations.flask_client import OAuth
from flask_session import Session
from werkzeug.middleware.proxy_fix import ProxyFix
import jwt
from jwt import PyJWTError
from urllib.parse import urljoin
import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# -- Config (all from env vars, no config files) --

OIDC_CLIENT_ID = os.environ.get('OIDC_CLIENT_ID', '')
OIDC_CLIENT_SECRET = os.environ.get('OIDC_CLIENT_SECRET', '')
OIDC_DISCOVERY_URL = os.environ.get('OIDC_DISCOVERY_URL', '')
OIDC_SCOPE = os.environ.get('OIDC_SCOPE', 'openid email profile')

JITSI_BASE_URL = os.environ.get('JITSI_BASE_URL', 'https://meet.example.com')
JWT_APP_ID = os.environ.get('JWT_APP_ID', 'jitsi')
JWT_APP_SECRET = os.environ.get('JWT_APP_SECRET', '')
JWT_SUBJECT = os.environ.get('JWT_SUBJECT', 'meet.example.com')

LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL.upper(), logging.INFO),
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# -- Flask setup --

app = Flask(__name__)
app.secret_key = secrets.token_urlsafe(32)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = '/app/flask_session'
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
Session(app)

oauth = OAuth(app)

# -- OIDC discovery + registration --


def fetch_oidc_configuration():
    if not OIDC_DISCOVERY_URL:
        logging.error("OIDC_DISCOVERY_URL not set")
        return None

    try:
        response = requests.get(OIDC_DISCOVERY_URL, timeout=10)
        response.raise_for_status()
        config = response.json()
        logging.info("OIDC discovery OK: %s", OIDC_DISCOVERY_URL)
        return config
    except Exception as e:
        logging.error("OIDC discovery failed: %s", e)
        return None


# Fetch once at startup. If this fails the app will reject all auth
# requests until restarted -- that's intentional.
oidc_config = fetch_oidc_configuration()

if oidc_config:
    oauth.register(
        name='oidc',
        client_id=OIDC_CLIENT_ID,
        client_secret=OIDC_CLIENT_SECRET,
        authorize_url=oidc_config['authorization_endpoint'],
        access_token_url=oidc_config['token_endpoint'],
        jwks_uri=oidc_config['jwks_uri'],
        issuer=oidc_config['issuer'],
        client_kwargs={'scope': OIDC_SCOPE},
    )
    logging.info("OAuth client registered")
else:
    logging.error("OAuth client NOT registered -- OIDC discovery failed")

# -- Token validation helpers --


def get_jwks_keys(jwks_uri):
    resp = requests.get(jwks_uri, timeout=10)
    return resp.json()


def jwks_to_pem(key_json):
    """JWK -> PEM. Only RSA keys."""
    public_num = rsa.RSAPublicNumbers(
        e=int(base64.urlsafe_b64decode(key_json['e'] + '==').hex(), 16),
        n=int(base64.urlsafe_b64decode(key_json['n'] + '==').hex(), 16)
    )
    public_key = public_num.public_key(default_backend())
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem


def parse_id_token(id_token, jwks_uri):
    """Validate the ID token signature and claims, return decoded payload."""
    jwks = get_jwks_keys(jwks_uri)
    header = jwt.get_unverified_header(id_token)

    # Match the signing key by kid
    rsa_key = None
    for key in jwks['keys']:
        if key.get('kid') == header.get('kid'):
            rsa_key = jwks_to_pem(key)
            break

    if not rsa_key:
        logging.error("No matching RSA key for kid=%s", header.get('kid'))
        return None

    try:
        decoded = jwt.decode(
            id_token,
            rsa_key,
            algorithms=['RS256'],
            audience=OIDC_CLIENT_ID,
            issuer=oidc_config['issuer']
        )
        return decoded
    except jwt.ExpiredSignatureError:
        logging.error("ID token expired")
    except jwt.InvalidTokenError as e:
        logging.error("Invalid ID token: %s", e)
    except PyJWTError as e:
        logging.error("JWT error: %s", e)
    except Exception as e:
        logging.error("Unexpected error decoding ID token: %s", e)

    return None


def gravatar_url(email):
    if not email:
        return ''
    email = email.strip().lower()
    h = hashlib.sha256(email.encode('utf-8')).hexdigest()
    return f"https://www.gravatar.com/avatar/{h}"


# -- Routes --

@app.route('/health')
@app.route('/oidc/health')
def health():
    return 'OK', 200


@app.route('/oidc/auth')
def login():
    """Start the OIDC authorization code flow."""
    if not oidc_config:
        return 'OIDC not configured', 500

    redirect_uri = urljoin(JITSI_BASE_URL, '/oidc/redirect')
    result = oauth.oidc.create_authorization_url(redirect_uri=redirect_uri)

    # Jitsi passes the room as ?room={room} via TOKEN_AUTH_URL.
    # Some setups use ?roomname= instead.
    room_name = request.args.get('room', request.args.get('roomname', 'lobby'))

    session['room_name'] = room_name
    session['oauth_state'] = result['state']
    session['oauth_nonce'] = result.get('nonce')

    logging.info("Auth started for room: %s", room_name)
    return redirect(result['url'])


@app.route('/oidc/redirect')
def oauth_callback():
    """OIDC callback. Exchanges the auth code for tokens, validates the
    ID token, stashes user info in the session, then hands off to /oidc/tokenize."""
    try:
        code = request.args.get('code')
        if not code:
            logging.error("No authorization code in callback")
            return "Authorization code not found", 400

        # Exchange code for tokens
        token_url = oidc_config['token_endpoint']
        redirect_uri = urljoin(JITSI_BASE_URL, '/oidc/redirect')

        response = requests.post(token_url, data={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': redirect_uri,
            'client_id': OIDC_CLIENT_ID,
            'client_secret': OIDC_CLIENT_SECRET
        }, timeout=10)

        if response.status_code != 200:
            logging.error("Token exchange failed: %d", response.status_code)
            return "Token exchange failed", 500

        token_data = response.json()

        if 'id_token' not in token_data:
            logging.error("No id_token in token response")
            return "ID token not found", 500

        id_token = parse_id_token(token_data['id_token'], oidc_config['jwks_uri'])
        if not id_token:
            return "Token validation failed", 500

        # Nonce check -- only enforce if we sent one and the provider echoed one.
        # Some providers don't include nonce in the id_token; that's allowed.
        stored_nonce = session.pop('oauth_nonce', None)
        if stored_nonce and id_token.get('nonce') != stored_nonce:
            logging.error("Nonce mismatch")
            return "Nonce mismatch", 400

        # Try standard OIDC claims first, fall back to less common ones.
        name = (id_token.get('name')
                or id_token.get('preferred_username')
                or id_token.get('displayName')
                or 'User')
        email = id_token.get('email', '')

        session['user_info'] = {
            'id': id_token.get('sub', ''),
            'name': name,
            'email': email,
            'avatar': gravatar_url(email),
        }

        logging.info("Authenticated: %s (%s)", name, email)
        return redirect(url_for('tokenize'))

    except Exception as e:
        logging.error("OIDC callback error: %s", e)
        return "Authentication failed", 500


@app.route('/oidc/tokenize')
def tokenize():
    """Build a Jitsi JWT and redirect to the meeting room."""
    user_info = session.get('user_info')
    if not user_info:
        return redirect(url_for('login'))

    room_name = session.get('room_name', 'lobby')
    now = datetime.datetime.now(datetime.timezone.utc)

    payload = {
        "context": {
            "user": {
                "id": user_info.get('id', ''),
                "avatar": user_info.get('avatar', ''),
                "name": user_info['name'],
                "email": user_info.get('email', ''),
                "affiliation": "owner",
            }
        },
        "aud": JWT_APP_ID,
        "iss": JWT_APP_ID,
        "sub": JWT_SUBJECT,
        "room": room_name,
        "iat": now,
        "nbf": now,
        "exp": now + datetime.timedelta(hours=3),
    }

    token = jwt.encode(payload, JWT_APP_SECRET, algorithm='HS256')
    final_url = f"{JITSI_BASE_URL}/{room_name}?jwt={token}#config.prejoinPageEnabled=false"

    logging.info("Issuing JWT for room: %s", room_name)
    return redirect(final_url)


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8000)
