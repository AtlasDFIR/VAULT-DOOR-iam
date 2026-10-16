"""Offline test of the SAML flow against a simulated Okta IdP.

Generates a throwaway IdP signing certificate, builds signed SAML responses the
way Okta would, and checks that the service provider accepts the valid one and
rejects tampered, unsigned, expired, misdirected, and unsolicited ones.

Run inside the container from the repository root:
    docker compose run --rm saml-sp python tests/test_flow.py
"""

import base64
import os
import sys
import zlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from onelogin.saml2.constants import OneLogin_Saml2_Constants as C
from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser
from onelogin.saml2.utils import OneLogin_Saml2_Utils

APP_DIR = Path(__file__).resolve().parent.parent
os.environ.update({
    "SAML_IDP_METADATA_URL": "https://integrator-0000000.okta.com/app/test/sso/saml/metadata",
    "FLASK_SECRET_KEY": "x" * 64,
})
sys.path.insert(0, str(APP_DIR))
import app as vault  # noqa: E402

IDP_ENTITY = "http://www.okta.com/exkTESTIDP"
IDP_SSO = "https://integrator-0000000.okta.com/app/test/sso/saml"
ACS = "http://localhost:8000/saml/acs"
AUDIENCE = "http://localhost:8000/saml/metadata"


def make_cert():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "simulated-okta")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption()).decode()
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    return key_pem, cert_pem


KEY_PEM, CERT_PEM = make_cert()
CERT_B64 = "".join(CERT_PEM.strip().splitlines()[1:-1])

# Metadata shaped like Okta's real document, parsed by the same parser the app
# uses at runtime. Okta's metadata includes a NameIDFormat, which the parser
# returns as an "sp" section the app must not let overwrite its own settings.
IDP_METADATA = f"""<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{IDP_ENTITY}">
<md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
<md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>{CERT_B64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>
<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{IDP_SSO}"/>
<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{IDP_SSO}"/>
</md:IDPSSODescriptor>
</md:EntityDescriptor>"""
vault._idp_settings = OneLogin_Saml2_IdPMetadataParser.parse(IDP_METADATA)


def ts(delta_minutes=0):
    return (datetime.now(timezone.utc) + timedelta(minutes=delta_minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_response(request_id, audience=AUDIENCE, name_id="hbass2+resident@wgu.edu",
                   expires_in=5, sign=True, tamper=False, destination=ACS):
    assertion = f"""<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a{os.urandom(8).hex()}" IssueInstant="{ts()}" Version="2.0">
<saml:Issuer>{IDP_ENTITY}</saml:Issuer>
<saml:Subject>
<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{name_id}</saml:NameID>
<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
<saml:SubjectConfirmationData InResponseTo="{request_id}" NotOnOrAfter="{ts(expires_in)}" Recipient="{ACS}"/>
</saml:SubjectConfirmation>
</saml:Subject>
<saml:Conditions NotBefore="{ts(-5)}" NotOnOrAfter="{ts(expires_in)}">
<saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction>
</saml:Conditions>
<saml:AuthnStatement AuthnInstant="{ts()}" SessionIndex="_s{os.urandom(6).hex()}">
<saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext>
</saml:AuthnStatement>
<saml:AttributeStatement>
<saml:Attribute Name="firstName"><saml:AttributeValue>Jesse</saml:AttributeValue></saml:Attribute>
<saml:Attribute Name="lastName"><saml:AttributeValue>Dunn</saml:AttributeValue></saml:Attribute>
<saml:Attribute Name="email"><saml:AttributeValue>{name_id}</saml:AttributeValue></saml:Attribute>
<saml:Attribute Name="groups"><saml:AttributeValue>Vault101-Residents</saml:AttributeValue></saml:Attribute>
</saml:AttributeStatement>
</saml:Assertion>"""
    if sign:
        assertion = OneLogin_Saml2_Utils.add_sign(
            assertion, KEY_PEM, CERT_PEM, sign_algorithm=C.RSA_SHA256, digest_algorithm=C.SHA256
        ).decode()
        assertion = assertion.replace('<?xml version="1.0"?>', "")
    if tamper:
        assertion = assertion.replace(name_id, "hbass2+overseer@wgu.edu", 1)
    response = f"""<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r{os.urandom(8).hex()}" Version="2.0" IssueInstant="{ts()}" Destination="{destination}" InResponseTo="{request_id}">
<saml:Issuer>{IDP_ENTITY}</saml:Issuer>
<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
{assertion}
</samlp:Response>"""
    return base64.b64encode(response.encode()).decode()


results = []


def check(name, cond, detail=""):
    results.append(bool(cond))
    print(("PASS " if cond else "FAIL ") + name + (f"  [{detail}]" if detail and not cond else ""))


def start_login(client):
    r = client.get("/saml/login")
    loc = r.headers.get("Location", "")
    raw = parse_qs(urlparse(loc).query).get("SAMLRequest", [""])[0]
    xml = zlib.decompress(base64.b64decode(raw), -15).decode() if raw else ""
    request_id = xml.split('ID="', 1)[1].split('"', 1)[0] if 'ID="' in xml else ""
    return r, loc, xml, request_id


def post_acs(client, saml_response):
    return client.post("/saml/acs", data={"SAMLResponse": saml_response}, base_url="http://localhost:8000")


app = vault.app
client = app.test_client()
BASE = {"base_url": "http://localhost:8000"}

r = client.get("/", **BASE)
check("home page renders signed out", r.status_code == 200 and b"Enter the Vault" in r.data)

r = client.get("/saml/metadata", **BASE)
check("SP metadata publishes entity ID and ACS", r.status_code == 200 and AUDIENCE.encode() in r.data and ACS.encode() in r.data)

r, loc, req_xml, request_id = start_login(client)
check("login redirects to Okta SSO URL", r.status_code == 302 and loc.startswith(IDP_SSO), loc)
check("AuthnRequest carries an ID and the ACS URL", bool(request_id) and ACS in req_xml)

with client.session_transaction() as s:
    stored = s.get("request_id")
check("request ID stored for InResponseTo matching", stored == request_id)

r = post_acs(client, build_response(request_id))
check("valid signed assertion accepted", r.status_code == 302, f"{r.status_code} {r.data[:300]}")

r = client.get("/", **BASE)
check("signed-in home shows user and group", b"Jesse Dunn" in r.data and b"Vault101-Residents" in r.data)

r = client.get("/assertion", **BASE)
check("assertion inspector shows audience and NameID", AUDIENCE.encode() in r.data and b"hbass2+resident@wgu.edu" in r.data)
check("signature values truncated in display", b"[truncated]" in r.data)

client.get("/logout", **BASE)
r = client.get("/assertion", **BASE)
check("sign-out clears the session", r.status_code == 302)


def rejected(name, **kwargs):
    c = app.test_client()
    _, _, _, rid = start_login(c)
    resp = post_acs(c, build_response(rid, **kwargs))
    check(name, resp.status_code == 401 and b"Assertion rejected" in resp.data, resp.status_code)


rejected("tampered assertion rejected (signature breaks)", tamper=True)
rejected("unsigned assertion rejected", sign=False)
rejected("assertion for another app rejected (audience)", audience="http://evil.example/saml/metadata")
rejected("expired assertion rejected", expires_in=-10)
rejected("response sent to another URL rejected (destination)", destination="http://evil.example/saml/acs")

c = app.test_client()
start_login(c)
r = post_acs(c, build_response("_someone_elses_request"))
check("unsolicited response rejected (InResponseTo mismatch)", r.status_code == 401)

passed = sum(results)
print(f"\n{passed}/{len(results)} checks passed")
sys.exit(0 if passed == len(results) else 1)
