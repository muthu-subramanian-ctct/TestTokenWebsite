import os
import json
import time
import base64
import re
import uuid
from wsgiref.simple_server import WSGIServer, WSGIRequestHandler, make_server
from socketserver import ThreadingMixIn
from urllib.parse import urlencode, urlparse, urlunparse, parse_qs
from io import BytesIO, StringIO
from typing import Dict
from datetime import datetime, timedelta
import pytest
import threading
from queue import SimpleQueue
from TokenTests import test_context
import html
import ssl
import requests
import base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key, load_der_public_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers

import jwt

# This is the private key associated with CTCT Test Environment
# NOTE: It will be replaced at some point in development.

ctct_private_key = '''-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCzVlerHT5f3G+M
JzLjTg8jUBUm9ca+/ScQDpDSWdVg8OlM4/PPfFMgj9rWUT36Em/NtV1m5EywvsR4
wa8LYbnt1VdoBQTyKmO9jARaqBaoKcGz/3a7dccJ/GcsUwFSg/41qJ5xPvFI+BAB
t/B0cABOkxaLMvCPoE0hpOzpI2dthXjrpQ3TQeUHDlo9qUS78A03S3T8x5oBa0ub
FYXaitdttqRACwsmBA+8OgmUEGhMpnVonbHQGPzuyA3lg4bW39b/QxUElJK5wkVJ
4aHjItXlxIsM1c8Sy/4Wg0TCM0crOBZAbeT0JuFUouPk4d+Elg/e7tfJANOYUmXU
BletqhvZAgMBAAECggEAAI6sd71VMUpnv6wWLhCoXrgOqMVWGHKESY98sbqnvW+3
jzlHdltGODFaQRTq4rkQnIy2EpjJCDo/irncsmYGWY/dKqyWpwNXYK0WYmBoBEka
RKtEPNw71x3FWvo9uc+WiFIoKTqZ2LE0qNy1JEIo2MBU70UkQZNXn1rPhatKKf6h
MHDiDaHTM/K5XLh7rGAMl5YHocFxRu1L/JiHukqDYFA+10bpi+nOapG3SJj33ucp
dShT6MdX7F/GX8hKF0Arncdfu26I7RTfiQlK575waQHntlABKNfPJiYcyNvpJQyG
DFgyeJoYkgO72NE69CHRB4nozzHtr4VnksRkKxA70QKBgQDpBJ5xULRrrVIqZZyE
6xSn/0DqwH3wcTvq4JaC2KsmjqZe6UiNg/pj4ADQWJ7jr06M3dNOS0ryRCkYJznc
LGVgVgcwkRgVNeLyzmMUbgKEUjHnaXs/yC2hdAhQoiIhMMki7zA4b1TOv/y3eU1J
vPVp0pyYG3Av5upF7F1bensJLQKBgQDFBlvh1T7pgTYj+OzUhjUZbA0y7/BgnUpN
K894IP6x7V2WzaSLrb6te7DRxI3W5clrSHEPloDnaGGvfcSWtrg4txKbyrf0kfN/
AjR3NJayo4RTweB17M4i3hEIsP/3GkYv0SRY+Wx2KQGvtTmIwTZxOnyMOJQkLOTd
EgWpgd3w3QKBgQC5UTQVWKL0k9Yp47/0MeWuqiFd0ZMXW2bUqKLrExgixQZpq0xJ
R/Il5iufhytuVqi4/V4lAVpsjGrGS8QHZ8OEN0bmiC5ICCAjDKLdx5P22kvYCBq+
IhywL9DBGADetqbwQpvt9hTTjPqWjEE8aKwg6iAiFIhHgHVHAPFKZIFfTQKBgC1f
0odG6g8yr7pHGJu1MMNjDAMgGPbXIoZ1QXmD98QYS0Zwo6V7ZP9lDgqxPo0wLFvl
ugwB+DvS4TRePYkMGY8OMl3oqMbNWgt1AYo2dUI8wDvd2Yiu+aY0CC49PSW2SlW2
z60h/CWWOgoyLUbeYGBhPM+6M/vEzwxOmzk3bFqNAoGBAIAu5MS/RUet8E9nCIVP
qLdirGs9su/UtTKxykcNJ5d+CCBRIzM7eEDGcuA7PvUCOjWGcxPE6qiTWAAW1eXx
gyLed/J39onHthsY0G8Mv+OS8PjjGkjUhcaJFQNsvMkOZCc69d3a7KYsdKoKlRUX
qs2faq9olCg+MuSa9q3GVmXx
-----END PRIVATE KEY-----'''

def pad_base64(data: str) -> bytes:
    # Pad base64url string if needed
    rem = len(data) % 4
    if rem:
        data += '=' * (4 - rem)
    return data.encode()

def get_public_key_from_jwks(jwks_url, kid, alg=None):
    try:
        # Fetch the JWKS document
        response = requests.get(jwks_url)
        response.raise_for_status()
        jwks = response.json()
    except Exception as e:
        return ("Failed to retrieve JWKS URL", None)

    # Find the required RSA key
    public_key = None    
    for key in jwks.get("keys", []):
        if key.get("kid") == kid:
            public_key = key
            break

    if public_key is None:
        return (f"Public key {kid} not found", None)

    if public_key.get("kty") != "RSA":
        return ("Public key type is not an RSA key", None)

    if alg is not None and public_key.get("alg") != alg:
        return (f"Public key has incorrect alg value", None)
            
    n = int.from_bytes(base64.urlsafe_b64decode(pad_base64(key["n"])), 'big')
    e = int.from_bytes(base64.urlsafe_b64decode(pad_base64(key["e"])), 'big')
    public_numbers = RSAPublicNumbers(e, n)
    
    return (None, public_numbers.public_key(backend=default_backend()))
            
def get_public_key_from_token(kid: str, issuer: str):
    try:
        # Assume the token provider implements the OpenID Connect standard so use that to fetch the public key
        oidc_config_url = f"{issuer.rstrip('/')}/.well-known/openid-configuration"
        config = requests.get(oidc_config_url).json()
        jwks_uri = config.get("jwks_uri")
    except Exception as e:
        return ("Failed to obtain OpenID Configuration URL", None)

    if not jwks_uri:
        return ("OpenID config document missing 'jwks_uri'", None)

    # Step 2: Fetch JWKS and get matching public key
    return get_public_key_from_jwks(jwks_uri, kid)

# Function to generate the JWT token
def generate_jwt(payload):
    private_key_obj = load_pem_private_key(ctct_private_key.encode(), password=None)
    return jwt.encode(payload, private_key_obj, algorithm='RS256', headers=dict(kid="1"))

# Function to validate the JWT token
def validate_jwt(token, environ):
    try:
        if token == '':
            return None, None, None, None, "Invalid token", None

        # Extract the header and claims without verifying the validity of the token
        header = jwt.get_unverified_header(token)
        claims = jwt.decode(token, options={"verify_signature": False, "verify_exp": False, "verify_nbf": False, "verify_iat": False})

        # Extract required fields
        jwt_error = None

        issuer_name = None

        kid = header.get("kid")
        azp = claims.get('azp')
        issuer = claims.get("iss")

        jwt_id = claims.get('jti', None)
        subject = claims.get('sub', None)
        exp_timestamp = claims.get('exp', None)
        expiry = None

        # Check for missing claims
        for claim in ['iss', 'azp', 'exp', 'jti', 'sub']:
            if claim not in claims:
                jwt_error = f"Missing {claim} claim"

        # Verify issuer and authorized party values
        # PRIVATE
        cat_production_azp = [
            '2a672db6-19d1-4fa7-b7f5-c70cc7211928'  # CAT Production
        ]
        cal_nonpreproduction_azp = [
            '0b5e766b-c46b-47f9-b39f-2a4b376eb332', # CAT Development
            '163f8684-2491-4315-aaaa-1ba18a68de03', # CAT Integration
            'e2277e28-d2c3-43e8-a14d-a6818454e540', # CAT QA
            '76fd9676-bf3f-4c29-807e-24f2b5733c31', # CAT Performance
            'cf2ab9e3-a46e-4744-be2c-a2f354299f90', # CAT Staging
        ]
        # PRIVATE

        if issuer == 'https://example-trimble.ctct.com':
            issuer_name = 'CTCT Test (Trimble Style)'
            if azp != '4c6f46d7-4504-4db4-ae9e-bcd1a5500c34':
                jwt_error = "Invalid authorised party"
        elif issuer == 'https://example-cat.ctct.com':
            issuer_name = 'CTCT Test (CAT Style)'
            if azp != '4c6f46d7-4504-4db4-ae9e-bcd1a5500c34':
                jwt_error = "Invalid authorised party"

        # PRIVATE
        elif issuer == 'https://stage.id.trimblecloud.com':
            issuer_name = 'Trimble Staging'
            if azp != '2ff4ef0c-51e4-4369-b406-93b69e96d39b':
                jwt_error = "Invalid authorised party"
        elif issuer == 'https://id.trimble.com':
            issuer_name = 'Trimble Producton'
            if azp != '2539b60a-b3bc-4d14-add2-8dcd30bc7260':
                jwt_error = "Invalid authorised party"
        elif issuer == 'https://signin.cat.com/tfp/4f0f19d0-f44c-4a03-b8cb-ab327bd2b12b/b2c_1a_p2_v1_signin_staging/v2.0/':
            issuer_name = 'CAT Non Production'
            if azp not in cal_nonpreproduction_azp:
                jwt_error = "Invalid authorised party"
        elif issuer == 'https://signin.cat.com/tfp/4f0f19d0-f44c-4a03-b8cb-ab327bd2b12b/b2c_1a_p2_v1_signin_prod/v2.0/':
            issuer_name = 'CAT Production'
            if azp not in cat_production_azp:
                jwt_error = "Invalid authorised party"
        # PRIVATE
        else:
            jwt_error = "Invalid issuer"

        # Check for expired tokens
        if exp_timestamp is not None:
            if isinstance(exp_timestamp, int):
                exp_time = datetime.utcfromtimestamp(exp_timestamp)
                expiry = exp_time.strftime("%d %B %Y %H:%M:%S")
            elif jwt_error == None:
                jwt_error = "Invalid exp claim value"

            # Check if the exp claim is more than 120 minutes in the future
            if exp_time > datetime.utcnow() + timedelta(minutes=120):
                jwt_error = "Expiry is too far in the future"

        # Verify the token signature and expiry fields etc
        if issuer == 'https://example-trimble.ctct.com' or issuer == 'https://example-cat.ctct.com':
            # Our internal tokens don't have a valid OpenID Connect server implementation so we
            # just rewrite the URL to point to the current server hosting this reference implementation
            # which actually has the .well-known/openid-configuration and JWKS documents...
            issuer = generate_local_server_url(environ)

        (public_key_err, public_key) = get_public_key_from_token(kid, issuer)
        if public_key is None:
            jwt_error = public_key_err

        if jwt_error is None:
            jwt.decode(token, public_key, algorithms=['RS256'])

        return issuer_name, expiry, subject, jwt_id, jwt_error
    except jwt.ExpiredSignatureError:
        return issuer_name, expiry, subject, jwt_id, "Token has expired"
    except jwt.InvalidSignatureError:
        return issuer_name, expiry, subject, jwt_id, "Invalid signature"
    except jwt.DecodeError:
        return issuer_name, expiry, subject, jwt_id, "Error decoding token"
    except jwt.InvalidTokenError:
        return issuer_name, expiry, subject, jwt_id, "Invalid token"

# Function to validate the form field signature
def validate_signature(data, signature, jwks_url, kid, alg):
    if signature == '':
        return 'Signature field missing'

    (public_key_err, public_key) = get_public_key_from_jwks(jwks_url, kid, alg)
    if public_key is None:
        return public_key_err
    try:
        public_key.verify(
            base64.b64decode(signature),
            data.encode(),
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        return None
    except Exception as e:
        return 'Invalid signature'

def validate_form_submission(environ):
    # Check if the request method is POST
    if environ['REQUEST_METHOD'] != 'POST':
        return (None, None, None, None, None, None, None, None, "Missing", "Invalid HTTP method. POST required", {}, '401 Access Denied')

    # Check if the content type is correct
    if environ.get('CONTENT_TYPE') != 'application/x-www-form-urlencoded':
        return (None, None, None, None, None, None, None, None, "Missing", "Invalid content type. application/x-www-form-urlencoded required", {}, '401 Access Denied')

    # Extract POST data
    try:
        request_body_size = int(environ.get('CONTENT_LENGTH', 0))
    except ValueError:
        request_body_size = 0

    try:
        request_body = environ['wsgi.input'].read(request_body_size)
        post_data = parse_qs(request_body.decode('utf-8'))
    except Exception as e:
        return (None, None, None, None, None, None, None, None, None, "Error reading request body", {}, '401 Access Denied')

    # Convert post_data values from lists to single values for easier handling
    form_error = None
    form_fields = {key: value[0] for key, value in post_data.items()}

    # Extract fields from POST data
    jwt_token = post_data.get('access_token', [''])[0]
    dsn = post_data.get('device', [''])[0]
    username = post_data.get('user', [''])[0]
    roles = post_data.get('roles', [''])[0]
    redirect = post_data.get('redirect', [''])[0]
    signature = post_data.get('signature', [''])[0]
    kid = post_data.get('kid', [''])[0]
    alg = post_data.get('alg', [''])[0]
    issurl = post_data.get('issurl', [''])[0]

    # Check for missing form fields (redirect is optional, all others are required)
    for field in ['access_token', 'device', 'user', 'roles']:
        if field not in post_data:
            form_error = f"Missing {field} field"

    # Validate JWT
    (issuer, expiry, subject, jwt_id, jwt_error) = validate_jwt(jwt_token, environ)

    if form_error == None and roles != '':
        for role in [r.strip() for r in roles.split(',')]:
            if role not in ['technician', 'admin', 'operator', 'operatorplus']:
                form_error = f"Invalid role - {role}"

    # Validate form signature
    if form_error == None:
        if issuer and 'CAT' in issuer: # Will be true for either true CAT tokens or the CTCT (CAT style) token types....
            # Check for missing form fields required for CAT style access requests
            for field in ['kid', 'alg', 'issurl', 'signature']:
                if field not in post_data:
                    form_error = f"Missing {field} field"

            # Real CAT tokens must be using a URL to the form public key
            # that is present on the correct host
            # 
            # We won't perform this validation for CTCT Test tokens to make
            # it easier for different testers to host this script in different
            # environments but the EC520 still performs the check against the
            # CAT app setting in that scenario...
            if issuer != 'CTCT Test (CAT Style)':
                required_hostname = 'stage-vlproductivity.cat.com' if issuer == 'CAT Non Production' else 'vlproductivity.cat.com'

                url = urlparse(issurl)
                if url.scheme not in ("http", "https"):
                    form_error = 'issurl is not a valid HTTP or HTTPS URL'
                elif url.hostname != required_hostname:
                    form_error = f'issurl has hostname other than {required_hostname}'
            
            # If all CAT related form fields are present verify the signature is correct
            if form_error == None:
                data_to_sign = f"{dsn};{username};{roles};{redirect};{kid};{alg};{issurl}"
                form_error = validate_signature(data_to_sign, signature, issurl, kid, alg)

    http_result_code = '401 Access Denied' if jwt_error is not None or form_error is not None else '200 OK'
    return (issuer, expiry, subject, jwt_id, dsn, username, roles, redirect, jwt_error, form_error, form_fields, http_result_code)

def handle_authentication(environ, overrideJTI=False, overrideExpiry=False):
    # Extract query parameters
    query_string = environ['QUERY_STRING']
    query_params = parse_qs(query_string)

    url = query_params.get('url', [''])[0]

    expiry = (int(time.time()) + 120) if overrideExpiry else int(query_params.get('expiry', [''])[0])
    dsn = query_params.get('dsn', [''])[0]

    username = query_params.get('username', [''])[0]
    roles = query_params.get('roles', [''])[0]

    authRedirect = query_params.get('redirecturl', [''])[0]

    tokentype = query_params.get('tokentype', [''])[0]
    jti = str(uuid.uuid4()) if overrideJTI else query_params.get('jti', [''])[0]

    azp = query_params.get('azp',[''])[0]
    kid = query_params.get('kid', [''])[0]
    alg = query_params.get('alg', [''])[0]

    issurl = query_params.get('issurl', [''])[0]

    redirect = ''
    if (authRedirect != ''):
        params = {
            'tokentype': tokentype,

            'url': url,

            'dsn': dsn,

            'username': username,
            'roles': roles,

            'authRedirect': authRedirect,
        }

        if tokentype == 'cat':
            params.update({
                'kid': kid,
                'alg': alg,
                'issurl': issurl
            })

        redirect = authRedirect + '?' + urlencode(params)

    # Handle the JWT creation
    jwt_token = generate_jwt({
        "iss": "https://example-trimble.ctct.com" if tokentype == "trimble" else "https://example-cat.ctct.com",
        "jti": jti,
        "exp": expiry,
        "azp": azp,
        "sub": "a324d232-76a8-4f11-bef5-5100b8dc60b2"
    })

    if tokentype == 'cat':
        # Sign the form fields (generate a hash of the field's contents, we ignore the access_token field as its a JWT with its own internal signature)
        data_to_sign = f"{dsn};{username};{roles};{redirect};{kid};{alg};{issurl}"

        private_key_obj = load_pem_private_key(ctct_private_key.encode(), password=None)

        # Sign the data with the private key using PSS padding and SHA256 hash
        signature = private_key_obj.sign(data_to_sign.encode(), padding.PKCS1v15(), hashes.SHA256())
        signature = base64.b64encode(signature).decode()
    else:
        signature = None

    return (url, jwt_token, dsn, username, roles, redirect, kid, alg, issurl, signature)

# Helper: convert an int to un‑padded base64url, per RFC 7518 §6.3.1
def _b64url_uint(val: int) -> str:
    byte_length = (val.bit_length() + 7) // 8 or 1
    int_bytes = val.to_bytes(byte_length, "big")
    return base64.urlsafe_b64encode(int_bytes).decode("ascii").rstrip("=")

def generate_local_server_url(environ):
    # Determine the scheme from WSGI environment
    scheme = environ.get('wsgi.url_scheme', 'http')

    # Get the port the server is running on
    port = environ.get('SERVER_PORT', '80')

    # Construct new netloc for localhost
    if (scheme == 'http' and port == '80') or (scheme == 'https' and port == '443'):
        url = f'{scheme}://localhost'
    else:
        url = f'{scheme}://localhost:{port}'

    return url

def get_openid_configuration(environ):
    """
    Return a stub of a OpenID Configuration document that allows the JWKS keyset URL to be determined
    """

    # Build the OpenID Configuration by hand
    config = {
        'jwks_uri': generate_local_server_url(environ) + '/public-key'
    }

    # return pretty‑printed JSON
    return json.dumps(config, indent=2)

def get_public_key_jwks():
    """
    Convert the PEM‐encoded key in `ctct_private_key` to a JWKS containing
    the corresponding **public** RSA key.  The sole JWK is given kid "1".
    """

    # Load the private key
    private_key = load_pem_private_key(ctct_private_key.encode(), password=None, backend=default_backend())

    # Derive the public half we must publish
    public_key = private_key.public_key()
    numbers = public_key.public_numbers()

    # Build the JWK by hand
    jwk = {
        "kty": "RSA",
        "kid": "1",
        "alg": "RS256",
        "use": "sig",
        "n": _b64url_uint(numbers.n),  # modulus
        "e": _b64url_uint(numbers.e),  # public exponent
    }

    # Wrap in a JWKS set and return pretty‑printed JSON
    jwks = {"keys": [jwk]}
    return json.dumps(jwks, indent=2)


def run_integration_tests(environ, start_response):
    # --- Queue to collect chunks ---
    queue = SimpleQueue()

    def chunk(html_str):
        return html_str.encode('utf-8')

    queue.put("<html><style>.fail { color:red; margin-left: 15px; } .pass { color:green; margin-left: 15px; } .skipped { color:gray; }</style><body><h2>Running Tests</h2><ul>")

    # Plugin that hooks into pytest test events
    class StreamPlugin:
        def pytest_runtest_logstart(self, nodeid, location):
            queue.put(f"<li>🟡 Running: {html.escape(nodeid)}</li>")
        def pytest_runtest_logreport(self, report):
            if report.when == 'call':
                if report.passed:
                    queue.put(f"<li class='pass'>✅ Passed</li>")
                elif report.failed:
                    queue.put(f"<li class='fail'>❌ Failed:<pre>{html.escape(report.longreprtext)}</pre></li>")
                elif report.skipped:
                    queue.put(f"<li class='skipped'>⚪ Skipped</li>")

    # --- Background test thread ---
    def run_tests():
        exit_code = pytest.main(["TokenTests.py", "-q", "--tb=short"], plugins=[StreamPlugin()])
        queue.put("</ul><p>✅ All tests complete.</p></body></html>")
        queue.put(None)  # Sentinel

    request_body_size = int(environ.get('CONTENT_LENGTH', 0))
    request_body = environ['wsgi.input'].read(request_body_size)
    form = parse_qs(request_body.decode('utf-8'))

    test_context['url'] =  form.get('url', [''])[0]
    test_context['pkey_url'] =  form.get('pkey_url', [''])[0]
    test_context['serial_number'] = form.get('serial_number', [''])[0]

    start_response('200 OK', [
        ('Content-Type', 'text/html; charset=utf-8')
    ])

    threading.Thread(target=run_tests, daemon=False).start()

    # --- HTML generator that yields queued chunks ---       
    def chunked_html_generator():
        while True:
            msg = queue.get()
            if msg is None:
                break
            yield chunk(msg)
            time.sleep(0.05)

    return chunked_html_generator()

def render_integration_test_form():
    return b"""
    <html><body>
        <h2>Integration Test Runner</h2>
        <form method="post">
            <input type="hidden" id="pkey_url" name="pkey_url" value="" />

            Remote.IT Proxy URL: <input type="url" id="url" name="url" value="" placeholder="Enter the current Remote.IT Proxy URL" />
            <br><br>
            <!-- Edit Box for username-->
            Enter your name: <input type="text" id="username" name="username" value="" placeholder="Enter your name" />
            <br><br>
            <br><br>
            <!-- Edit Box for Serial Number -->
            Enter Serial Number: <input type="text" id="serial_number" name="serial_number" value="" placeholder="Enter the serial number" />
            <br><br>
            <input type="submit" value="Run Tests" />
        </form>
        <script>
                window.onload = function() {
                    document.getElementById('url').value = window.location.origin + '/validate-token';
                    document.getElementById('pkey_url').value = window.location.origin + '/public-key';
                }
        </script>
    </body></html>
    """

# WSGI application
def application(environ, start_response):
    path = urlparse(environ['PATH_INFO']).path
    method = environ.get('REQUEST_METHOD', 'GET')

    status = '200 OK'
    headers = [('Content-type', 'text/html')]

    if path == '/':
        response_body = get_html_form().encode('utf-8')
    elif path == '/grant-remote-access':
       # Demonstrates how to generate a suitable form post and return it to the client for auto submission
       (url, jwt_token, dsn, username, roles, redirect, kid, alg, issurl, signature) = handle_authentication(environ)
       response_body = get_auto_submit_html(url, jwt_token, dsn, username, roles,  redirect, kid, alg, issurl, signature).encode('utf-8')
    elif path == '/reauthenticate':
       # Demonstrates how the parent can supply a URL that Earthworks will redirect the user to in order to re-authenticate
       # their permission to access a given EC520 (i.e. if they are still allowed to access it this API end point
       # should generate a new access token and post it back to the EC520
       (url, jwt_token, dsn, username, roles, redirect, kid, alg, issurl, signature) = handle_authentication(environ, overrideJTI=True, overrideExpiry=True)
       response_body = get_reauthenticate_html(url, jwt_token, dsn, username, roles, redirect, kid, alg, issurl, signature).encode('utf-8')
    elif path == '/validate-token':
       # A "helper" page - parent's can test out their token generation and form posts by sending them to this
       # end point and they will get feedback on the contents and validity of the token.
       (issuer, expiry, subject, jwt_id, dsn, username, roles, redirect, jwt_error, form_error, form_fields, status) = validate_form_submission(environ)
       print('the status is ', status, jwt_error, form_error)
       response_body = get_validation_html(issuer, expiry, subject, jwt_id, dsn, username, roles, redirect, jwt_error, form_error, form_fields).encode('utf-8')
    elif path == '/integration-tests':
        if method == 'POST':
            return run_integration_tests(environ, start_response)
        else:
            response_body = render_integration_test_form()
    elif path == '/.well-known/openid-configuration':
        # A OpenID Configuration "stub" that will point to the below JWKS document to allow the public key to be obtained
        headers = [('Content-type', 'application/json')]
        response_body = get_openid_configuration(environ).encode('utf-8')
    elif path == '/public-key':
        # A JWKS document that includes CTCT's token public key
        headers = [('Content-type', 'application/json')]
        response_body = get_public_key_jwks().encode('utf-8')
    elif path == '/css':
       # Return the CSS stylesheet used to style the various forms
       headers = [('Content-type', 'text/css')]
       response_body = get_css().encode('utf-8')
    elif path == '/src':
       # Returns the source code of this script minus some "sensitive" parts...
       headers = [('Content-type', 'text/plain; charset=utf-8')]
       response_body = get_source_code(environ)
    else:
       status = '404 Not Found'
       response_body = b'Not Found'

    start_response(status, headers)
    return [response_body]

def get_css():
    return """
    body {
        font-family: 'Arial', sans-serif;
        background-color: #f7f9fb;
        color: #333;
        display: flex;
        justify-content: center;
        align-items: center;
        height: 100vh;
        margin: 0;
    }

    .form-container {
        background-color: #fff;
        padding: 20px 30px;
        border-radius: 8px;
        box-shadow: 0 4px 10px rgba(0, 0, 0, 0.1);
        width: 100%;
        max-width: 500px;
    }

    h2 {
        text-align: center;
        color: #2d3e50;
        margin-bottom: 20px;
    }

    label {
        font-size: 14px;
        color: #2d3e50;
        margin-bottom: 8px;
        display: block;
        font-weight: bold;
    }

    input[type="text"] {
        width: 100%;
        padding: 10px;
        margin: 10px 0;
        border: 1px solid #ccc;
        border-radius: 4px;
        font-size: 14px;
        box-sizing: border-box;
        transition: all 0.3s;
    }

    input[type="text"]:focus {
        border-color: #007bff;
        outline: none;
        box-shadow: 0 0 5px rgba(0, 123, 255, 0.2);
    }

    button {
        width: 100%;
        padding: 12px;
        background-color: #007bff;
        border: none;
        border-radius: 4px;
        color: white;
        font-size: 16px;
        cursor: pointer;
        transition: all 0.3s;
    }

    button:hover {
        background-color: #0056b3;
    }

    button.reauth {
        width: auto;
    }

    .form-group {
        margin-bottom: 15px;
    }

    .form-row {
        display: flex;
        justify-content: space-between;
    }

    .half-width {
        width: 48%; /* Adjust width to ensure space between fields */
    }

    .checkbox-group {
        display: flex;
        align-items: center;
        margin-bottom: 18px;
    }

    .checkbox-group input[type="checkbox"] {
        margin-right: 10px;
    }

    .checkbox-group label {
        font-size: 14px;
        color: #2d3e50;
        font-weight: bold;
        margin: 0px;
    }

    .tabs {
        display: flex;
        cursor: pointer;
    }

    .tab {
        flex: 1;
        padding: 10px;
        text-align: center;
        background-color: #e0e0e0;
        border-radius: 4px 4px 0 0;
    }

    .tab.active {
        background-color: #007bff;
        color: white;
    }

    .tab-content {
        display: none;
        border: 1px solid #ccc;
        padding: 10px;
        box-sizing: border-box;
    }

    .tab-content.active {
        display: block;
    }

    .section {
        margin-bottom: 20px;
    }

    .section h3 {
        margin: 0px 0px 10px 0px;
        color: #2d3e50;
    }

    .row {
        display: flex;
        justify-content: space-between;
        margin-bottom: 10px;
    }

    .label {
        font-weight: bold;
        color: #2d3e50;
    }

    .value {
        color: #333;
    }

    .valid {
        color: green;
    }

    .invalid {
        color: red;
    }

    pre {
        white-space: pre-wrap;
        word-wrap: break-word;
    }

    /* Style for the source code link */
    .source-code-link {
        text-align: right;
        margin-top: 15px; /* Add space between the button and the link */
    }

    .source-code-link a {
        color: #007bff;
        text-decoration: none;
        font-size: 14px;
    }

    .source-code-link a:hover {
        text-decoration: underline;
    }
    """

def get_html_form():
    return f"""
    <!DOCTYPE html>
    <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Parent Token Simulator</title>
            <script src="https://cdnjs.cloudflare.com/ajax/libs/jsrsasign/11.1.0/jsrsasign-all-min.js" integrity="sha512-Eu9j+HZBor7muHf6IDWoWZ8FKVr6nKe9eIIVR28NEte4Y4GiYRlke26XGdR/re81XE/FfLoLYYVkvNk5GY9RvQ==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
            <script src="https://cdn.jsdelivr.net/npm/flatpickr"></script>
            <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/flatpickr/dist/flatpickr.min.css">
            <link rel="stylesheet" href="/css">
        </head>
        <body>
            <div class="form-container">
                <h2>Parent Token Simulator</h2>
                <form action="/grant-remote-access" method="GET" target="_blank">
                    <input type="hidden" name="alg" value="RS256" />

                    <div class="form-row">
                        <div class="form-group half-width">
                            <label for="tokentype">Token Type:</label>
                            <select id="tokentype" name="tokentype" required>
                                <option value="cat">CTCT Test (CAT Style)</option>
                                <option value="trimble">CTCT Test (Trimble Style)</option>
                            </select>
                        </div>

                        <div class="form-group half-width">
                            <label for="jti">JTI:</label>
                            <input type="text" id="jti" name="jti" required placeholder="Enter JWT Token Identifier" value="{str(uuid.uuid4())}">
                        </div>
                    </div>

                    <div class="form-row">
                        <div class="form-group half-width">
                            <label for="kid">KID:</label>
                            <input type="text" id="kid" name="kid" required placeholder="Enter Key ID" value="1">
                        </div>

                        <div class="form-group half-width">
                            <label for="issurl">Public Key URL:</label>
                            <input type="text" id="issurl" name="issurl" required placeholder="Enter public key URL">
                        </div>
                    </div>

                    <div class="form-row">
                        <div class="form-group half-width">
                            <label for="azp">AZP:</label>
                            <input type="text" id="azp" name="azp" required placeholder="Enter Authorized party" value="4c6f46d7-4504-4db4-ae9e-bcd1a5500c34">
                        </div>

                        <div class="form-group half-width">
                            <label for="dsn">EC520 Serial Number:</label>
                            <input type="text" id="dsn" name="dsn" placeholder="Enter EC520 serial number" value="3107J131YU">
                        </div>
                    </div>

                    <div class="form-group">
                        <label for="urlInput">Remote.IT URL:</label>
                        <input type="text" id="urlInput" name="url" required placeholder="Enter target URL" value="http://localhost">
                    </div>

                    <div class="form-group">
                        <label for="redirect">Redirect URL:</label>
                        <input type="text" id="redirecturl" name="redirecturl" placeholder="Enter redirect URL">
                    </div>

                    <div class="form-group">
                        <label for="username">User Name:</label>
                        <input type="text" id="username" name="username" required placeholder="Enter TechUI user name" value="chris_fairbairn@trimble.com">
                    </div>

                    <div class="form-row">
                        <div class="form-group half-width">
                            <label for="roles">Roles:</label>
                            <input type="text" id="roles" name="roles" placeholder="Enter roles" value="admin,technician">
                        </div>

                        <div class="form-group half-width">
                            <label for="expiry">Expiry:</label>
                            <input type="text" id="expiry" name="expiry" required placeholder="Enter parent access token expiry date">
                        </div>
                    </div>

                    <button type="submit">Send to TechUI</button>

                    <div class="source-code-link">
                        <a href="/integration-tests" target="_blank">Integration Tests</a>
                    </div>
                </form>
            </div>
           
            <script>
                window.onload = function() {{
                    // Make a fancy date/time picker for the expiry timestamp input
                    // that defaults to 5 minutes in the future
                    var futureDate = new Date();
                    futureDate.setMinutes(futureDate.getMinutes() + 5);

                    flatpickr("#expiry", {{
                        defaultDate: futureDate,
                        enableTime: true,
                        altInput: true,
                        altFormat: "Y-m-d H:i:S",  // Display format for the user
                        dateFormat: "U",           // Format to submit in post (number of seconds since UNIX Epoch)
                        time_24hr: true            // Use 24-hour time
                    }});

                    document.getElementById('issurl').value = 'https://stage-vlproductivity.cat.com/.well-known/ec520/keys/';
                    document.getElementById('redirecturl').value = window.location.href + 'reauthenticate';
                    document.getElementById('urlInput').value = window.location.href + 'validate-token';

                    const tokentypeSelect = document.getElementById("tokentype");
                    const kidInput = document.getElementById("kid");
                    const issurlInput = document.getElementById("issurl");
                    const formRow = kidInput.closest(".form-row");

                    function updateFormFieldPublicKeyVisibility() {{
                        const selectedValue = tokentypeSelect.value;
                        const show = selectedValue === "cat";

                        formRow.style.display = show ? "" : "none";

                        kidInput.required = show;
                        issurlInput.required = show;
                    }}

                    tokentypeSelect.addEventListener("change", updateFormFieldPublicKeyVisibility);
                    updateFormFieldPublicKeyVisibility();
                }}
            </script>
        </body>
    </html>
    """

def get_auto_submit_html(url: str, jwt_token: str, dsn: str, username: str, roles: str, redirect: str, kid: str, alg: str, issurl: str, signature: str):
    html = f"""
    <html>
        <body onload="document.getElementById('autoSubmitForm').submit();">
            <form id="autoSubmitForm" method="POST" action="{url}">
                <input type="hidden" name="access_token" value="{jwt_token}" />
                <input type="hidden" name="device" value="{dsn}" />
                <input type="hidden" name="user" value="{username}" />
                <input type="hidden" name="roles" value="{roles}" />
                <input type="hidden" name="redirect" value="{redirect}" />
"""

    if signature is not None:
        html = html + f"""
                <input type="hidden" name="kid" value="{kid}" />
                <input type="hidden" name="alg" value="{alg}" />
                <input type="hidden" name="issurl" value="{issurl}" />
                <input type="hidden" name="signature" value="{signature}" />
"""

    html = html + f"""            </form>
        </body>
    </html>
    """

    return html

def get_reauthenticate_html(url: str, jwt_token: str, dsn: str, username: str, roles: str, redirect: str, kid: str, alg: str, issurl: str, signature: str):
    html = f"""
    <!DOCTYPE html>
    <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Parent Cloud Platform Simulator</title>
            <link rel="stylesheet" href="/css">
        </head>
        <body>
            <div class="form-container">

                <h2>Simulate the parent cloud reauthenticating the user and regranting EC520 access by pressing the button below</h2>

                <form method="POST" action="{url}">
                    <input type="hidden" name="access_token" value="{jwt_token}" />
                    <input type="hidden" name="device" value="{dsn}" />
                    <input type="hidden" name="user" value="{username}" />
                    <input type="hidden" name="roles" value="{roles}" />
                    <input type="hidden" name="redirect" value="{redirect}" />
"""

    if signature is not None:
        html = html + f"""
                    <input type="hidden" name="kid" value="{kid}" />
                    <input type="hidden" name="alg" value="{alg}" />
                    <input type="hidden" name="issurl" value="{issurl}" />
                    <input type="hidden" name="signature" value="{signature}" />
"""

    html = html + f"""
    	            <button type="submit">Reauthenticate</button>
                </form>
            </div>
        </body>
    </html>
    """

    return html

def get_validation_html(issuer, expiry, subject, jwt_id, dsn, username, roles, redirect, jwt_error, form_error, form_fields):
    validity_status = "Valid" if jwt_error is None and form_error is None else "Invalid"
    redirect_script = f"window.location.href = \'{redirect}\';"
    form_fields_str = "\n".join([f"<strong>{key}:</strong> {value}" for key, value in form_fields.items()])

    return f"""
    <!DOCTYPE html>
    <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Token Validation</title>
            <link rel="stylesheet" href="/css">
            <script>
                function showTab(tabIndex) {{
                    var tabs = document.querySelectorAll('.tab');
                    var contents = document.querySelectorAll('.tab-content');
                    tabs.forEach((tab, index) => {{
                        tab.classList.toggle('active', index === tabIndex);
                        contents[index].classList.toggle('active', index === tabIndex);
                    }});
                }}
            </script>
        </head>
        <body>
            <div class="form-container">
                <h2>Token Validation Result</h2>
                <div class="tabs">
                    <div class="tab active" onclick="showTab(0)">Access Token</div>
                    <div class="tab" onclick="showTab(1)">Raw Form Post</div>
                </div>
                <div class="tab-content active">
                    <div class="section details">
                        <h3>Details</h3>
                        <div class="row">
                            <span class="label">Token ID:</span>
                            <span class="value">{jwt_id}</span>
                        </div>
                        <div class="row">
                            <span class="label">Issuer:</span>
                            <span class="value">{issuer}</span>
                        </div>
                        <div class="row">
                            <span class="label">Expires:</span>
                            <span class="value">{expiry}</span>
                        </div>
                        <div class="row">
                            <span class="label">Subject:</span>
                            <span class="value">{subject}</span>
                        </div>
                        <div class="row">
                            <span class="label">EC520 Serial Number:</span>
                            <span class="value">{dsn}</span>
                        </div>
                        <div class="row">
                            <span class="label">Username:</span>
                            <span class="value">{username}</span>
                        </div>
                        <div class="row">
                            <span class="label">Roles:</span>
                            <span class="value">{roles}</span>
                        </div>
                        <div class="row">
                            <span class="label">Reauthentication:</span>
                            { f'<button class="reauth" onclick="{redirect_script}">Reauthenticate</button>' if redirect else '<span class="value">URL not supplied</span>' }
                        </div>
                    </div>
                    <div class="section jwt-status">
                        <h3>Validation</h3>
                        <div class="row jwt">
                            <span class="label">ID Token:</span>
                            <span class="value {'invalid' if jwt_error else 'valid'}">{jwt_error if jwt_error else 'Valid'}</span>
                        </div>
                        <div class="row form-status">
                            <span class="label">Form:</span>
                            <span class="value {'invalid' if form_error else 'valid'}">{form_error if form_error else 'Valid'}</span>
                        </div>
                    </div>
                    <div class="row overall-status">
                        <span class="label">Overall Status:</span>
                        <span class="value {'valid' if validity_status == 'Valid' else 'invalid'}">{validity_status}</span>
                    </div>
                </div>
                <div class="tab-content">
                    <pre>{form_fields_str}</pre>
                </div>
            </div>
        </body>
    </html>
    """

def get_source_code(environ):
    # Path of the current script
    script_path = os.path.abspath(__file__)
    print(script_path)
    try:
        with open(script_path, 'r') as f:
            source_code = f.read()

        pattern = r'(?!\n)\s*# PRI' + r'VATE.*?\n(.*?)# PRI' + r'VATE.*?\n'
        source_code = re.sub(pattern, '', source_code, flags=re.DOTALL)

        return source_code.encode('utf-8')
    except Exception as e:
        # If there's an error reading the script, return an error message
        return f"Error reading the source code: {str(e)}".encode('utf-8')

# Set up the server to listen on port 8000
class ThreadedWSGIServer(ThreadingMixIn, WSGIServer):
    pass

def run(port=8000):
    server_address = ('', port)
    with make_server('', port, application, server_class=ThreadedWSGIServer, handler_class=WSGIRequestHandler) as httpd:
        print(f'Starting server on port {port}...')
        print("OpenSSL version:", ssl.OPENSSL_VERSION)
        httpd.serve_forever()

if __name__ == "__main__":
    run()
