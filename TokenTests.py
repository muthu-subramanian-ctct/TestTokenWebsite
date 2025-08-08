import pytest
import jwt
import requests
import time
import base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key, load_der_public_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers

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

ctct_trimble_issuer = 'https://example-trimble.ctct.com'
ctct_cat_issuer = 'https://example-cat.ctct.com'

ctct_azp = '4c6f46d7-4504-4db4-ae9e-bcd1a5500c34'
cat_production_azp = '2a672db6-19d1-4fa7-b7f5-c70cc7211928'

test_context = {
    'url': None,
    'pkey_url': None
}

@pytest.mark.parametrize("a, b, expected", [
    (2, 3, 5),
    (5, 7, 12),
])
def test_addition(a, b, expected):
    assert a + b == expected

@pytest.mark.parametrize("a, b, expected", [
    (2, 3, -1),
    (5, 2, 3),
])
def test_subtraction(a, b, expected):
    assert a - b == expected

@pytest.mark.parametrize("iss, jti, sub, exp, azp, jwt_sig, access_token, device, user, roles, redirect, kid, alg, issurl, form_sig, http_result_code", [
    # Trimble style token tests
    #
    #            JWT                                                                           | Form fields                                                                                | Expected Result
    #            issuer,              JWT ID,   subject, expiry, authorizedParty,    signature | access_token, device, user,  roles,              redirect, kid,  alg,    issurl, signature | http result code
    # pytest.param( ctct_trimble_issuer, 'random', '1234',  +5,     ctct_azp,           True,       True,         'msubram-nz-ll02', 'Bob', 'admin,technician', None,     None, None,   None,   None,       200, id='ctct trimble valid request'),           # Success - Correctly signed and submitted CTCT Trimble access request
    # pytest.param( ctct_trimble_issuer, 'random', '1234',  +5,     cat_production_azp, True,       True,         '1234', 'Bob', 'admin,technician', None,     None, None,   None,   None,       401, id='ctct trimble incorrect azp claim'),     # Failure - JWT has incorrect azp claim
    # pytest.param( ctct_trimble_issuer, 'random', '1234',  +5,     None,               True,       True,         '1234', 'Bob', 'admin,technician', None,     None, None,   None,   None,       401, id='ctct trimble missing azp claim'),       # Failure - JWT is missing azp claim 
    # pytest.param( ctct_trimble_issuer, 'random', '1234',  +5,     ctct_azp,           False,      True,         '1234', 'Bob', 'admin,technician', None,     None, None,   None,   None,       401, id='ctct trimble incorrect jwt signature'), # Failure - JWT is signed with the wrong key
    # pytest.param( ctct_trimble_issuer, 'random', '1234',  +5,     ctct_azp,           None,       True,         '1234', 'Bob', 'admin,technician', None,     None, None,   None,   None,       401, id='ctct trimble missing jwt signature'),   # Failure - JWT isn't signed

    # CAT style token tests
    #
    #            JWT                                                                           | Form fields                                                                                | Expected Result
    #            issuer,              JWT ID,   subject, expiry, authorizedParty,    signature | access_token, device, user,  roles,              redirect, kid, alg,     issurl, signature | http result code
    pytest.param(ctct_cat_issuer,     'random', '1234',  +5,     ctct_azp,           True,       True,         '1234', 'Bob', 'admin,technician', None,       1,   'RS256', True,   True,     200, id='ctct cat valid request'),            # Success - Correctly signed and submitted CTCT CAT access request
    # pytest.param(ctct_cat_issuer,     'random', '1234',  +5,     ctct_azp,           True,       True,         '1234', 'Bob', 'admin,technician', None,       1,   'RS256', False,  False,    401, id='ctct cat incorrect form signature'), # Failure - form field has incorrect signature
    # pytest.param(ctct_cat_issuer,     'random', '1234',  +5,     ctct_azp,           True,       True,         '1234', 'Bob', 'admin,technician', None,       1,   'RS256', None,   False,    401, id='ctct cat missing form siganture'),   # Failure - form field has no signature

    # Tokens issued by someone else
    # pytest.param('http://mickey-mouse.com', 'random', '1234',  +5,     ctct_azp,           True,       True,         '1234', 'Bob', 'admin,technician', None,     None, None,   None,   None, 401, id='incorrect issuer'), # Failure - JWT has incorrect issuer
])
def test_parent_access_token_login(iss, jti, sub, exp, azp, jwt_sig, access_token, device, user, roles, redirect, kid, alg, issurl, form_sig, http_result_code):
    form_fields = {}

    if access_token is not None:
        private_key_obj = load_pem_private_key(ctct_private_key.encode(), password=None)

        payload = {}

        if iss is not None:
            payload["iss"] = iss

        if jti is not None:
            payload["jti"] = jti

        if sub is not None:
            payload["sub"] = sub

        if exp is not None:
            current_time_utc = int(time.time())
            payload["exp"] = current_time_utc + exp # exp is the offset +/- the current time measured in seconds

        if azp is not None:
            payload["azp"] = azp

        if jwt_sig is not None:
            private_key = private_key_obj if jwt_sig else rsa.generate_private_key(public_exponent=65537, key_size=2048)
            form_fields['access_token'] = jwt.encode(payload, private_key, algorithm='RS256', headers=dict(kid="1"))
        else:
            form_fields['access_token'] = jwt.encode(payload, key=None, algorithm='none', headers=dict(kid="1"))
    
    if device is not None:
        form_fields['device'] = device

    if user is not None:
        form_fields['user'] = user

    if roles is not None:
        form_fields['roles'] = roles

    if redirect is not None:
        form_fields['redirect'] = redirect

    if kid is not None:
        form_fields['kid'] = kid

    if alg is not None:
        form_fields['alg'] = alg

    if issurl is not None:
        issurl = test_context['pkey_url'] if issurl else 'http://www.trimble.com' # use www.trimble.com as a random but incorrect pubic key url...
        form_fields['issurl'] = issurl

    if form_sig is not None:
        # Sign the form fields (generate a hash of the field's contents, we ignore the access_token field as its a JWT with its own internal signature)
        data_to_sign = f"{device or ''};{user or ''};{roles or ''};{redirect or ''};{kid or ''};{alg or ''};{issurl or ''}"
        private_key_obj = load_pem_private_key(ctct_private_key.encode(), password=None)

        # Sign the data with the private key using PSS padding and SHA256 hash
        signature = private_key_obj.sign(data_to_sign.encode(), padding.PKCS1v15(), hashes.SHA256())
        good_signature = base64.b64encode(signature).decode()
        bad_signature = base64.b64encode(bytes(~b & 0xFF for b in signature)).decode()  # 'corrupt' the signature by negating each byte

        form_fields['signature'] = good_signature if form_sig else bad_signature

    response = requests.post(test_context['url'], data=form_fields)

    # Print the HTTP status code
    print("response code:", response.status_code)
    print("http_result code:",http_result_code)
    assert response.status_code == http_result_code