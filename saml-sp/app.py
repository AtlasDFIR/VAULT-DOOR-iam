"""VAULT-DOOR SAML service provider.

A small Flask app that trusts Okta as its SAML (Security Assertion Markup
Language) identity provider. It starts SP-initiated sign-in, validates the
signed assertion Okta posts back, and shows everything inside it.

Runs in Docker: from the repository root, `docker compose up --build`.
"""

import logging
import os
import re
import secrets
import sys
from datetime import datetime, timezone
from xml.dom import minidom

from flask import Flask, redirect, render_template, request, session, url_for
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser

REQUIRED = ["SAML_IDP_METADATA_URL", "FLASK_SECRET_KEY"]
missing = [name for name in REQUIRED if not os.getenv(name) or os.getenv(name) == "replace-me"]
if missing:
    sys.exit("Missing settings in .env: " + ", ".join(missing))

SP_BASE_URL = os.getenv("SAML_SP_BASE_URL", "http://localhost:8000").rstrip("/")
SP_ENTITY_ID = f"{SP_BASE_URL}/saml/metadata"
ACS_URL = f"{SP_BASE_URL}/saml/acs"
EMAIL_FORMAT = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
audit = logging.getLogger("vault-door.saml.audit")

app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET_KEY"]
app.config.update(
    # Browsers share cookies across ports on localhost. A unique name keeps
    # this app's session from colliding with the OIDC app on port 5000.
    SESSION_COOKIE_NAME="vaultdoor_saml",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

# Assertions are kept server side, keyed by a random id, never in the cookie.
ASSERTION_STORE = {}
_idp_settings = None


def idp_settings():
    """Download Okta's IdP metadata once: its entity ID, sign-in URL, and signing certificate."""
    global _idp_settings
    if _idp_settings is None:
        url = os.environ["SAML_IDP_METADATA_URL"]
        _idp_settings = OneLogin_Saml2_IdPMetadataParser.parse_remote(url, timeout=15)
        audit.info("IDP METADATA loaded entity_id=%s", _idp_settings.get("idp", {}).get("entityId"))
    return _idp_settings


def saml_settings():
    settings = {
        "strict": True,
        "debug": False,
        "sp": {
            "entityId": SP_ENTITY_ID,
            "assertionConsumerService": {
                "url": ACS_URL,
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            },
            "NameIDFormat": EMAIL_FORMAT,
        },
        "security": {
            # Okta signs the assertion. Refuse anything unsigned.
            "wantAssertionsSigned": True,
            "wantMessagesSigned": False,
            "wantNameId": True,
            "authnRequestsSigned": False,
            # Don't demand a password-specific authentication context, so a
            # passkey sign-in at Okta is accepted.
            "requestedAuthnContext": False,
            "rejectDeprecatedAlgorithm": True,
        },
    }
    # Take only the IdP section from Okta's parsed metadata. The parser also
    # returns "sp" and "security" sections, and merging those wholesale would
    # overwrite this app's own entity ID, ACS URL, and security settings.
    settings["idp"] = idp_settings()["idp"]
    return settings


def build_request():
    return {
        "https": "on" if request.scheme == "https" else "off",
        "http_host": request.host,  # includes the port, so Destination checks match localhost:8000
        "script_name": request.path,
        "get_data": request.args.copy(),
        "post_data": request.form.copy(),
    }


def saml_auth():
    return OneLogin_Saml2_Auth(build_request(), saml_settings())


def readable_xml(raw):
    """Pretty-print the response and shorten signatures and certificates for display."""
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    pretty = minidom.parseString(raw).toprettyxml(indent="  ")
    pretty = "\n".join(line for line in pretty.splitlines() if line.strip())
    for tag in ("SignatureValue", "X509Certificate"):
        pattern = rf"(<(?:\w+:)?{tag}>)\s*([A-Za-z0-9+/=\s]{{24}})[A-Za-z0-9+/=\s]*(</(?:\w+:)?{tag}>)"
        pretty = re.sub(pattern, lambda m: f"{m.group(1)}{m.group(2).strip()}...[truncated]{m.group(3)}", pretty)
    return pretty


def current_assertion():
    sid = session.get("sid")
    return ASSERTION_STORE.get(sid) if sid else None


@app.route("/")
def index():
    return render_template("index.html", user=current_assertion())


@app.route("/saml/login")
def login():
    auth = saml_auth()
    sso_url = auth.login()
    # Remember the request ID so the response can be matched to it (InResponseTo).
    session["request_id"] = auth.get_last_request_id()
    audit.info("AUTH START SP-initiated request_id=%s", session["request_id"])
    return redirect(sso_url)


@app.route("/saml/acs", methods=["POST"])
def acs():
    auth = saml_auth()
    request_id = session.pop("request_id", None)
    auth.process_response(request_id=request_id)
    errors = auth.get_errors()

    if errors or not auth.is_authenticated():
        reason = auth.get_last_error_reason() or "Not authenticated"
        audit.warning("AUTH REJECTED errors=%s reason=%s", errors, reason)
        return render_template("denied.html", errors=errors, reason=reason), 401

    attributes = auth.get_attributes()
    expires = auth.get_last_assertion_not_on_or_after()
    record = {
        "name_id": auth.get_nameid(),
        "name_id_format": auth.get_nameid_format(),
        "session_index": auth.get_session_index(),
        "attributes": attributes,
        "assertion_id": auth.get_last_assertion_id(),
        "issued_at": auth.get_last_assertion_issue_instant(),
        "not_on_or_after": expires,
        "in_response_to": request_id,
        "issuer": saml_settings()["idp"]["entityId"],
        "audience": SP_ENTITY_ID,
        "xml": readable_xml(auth.get_last_response_xml()),
        "signed_in_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    }

    sid = secrets.token_urlsafe(32)
    ASSERTION_STORE[sid] = record
    session.clear()
    session["sid"] = sid

    audit.info(
        "AUTH SUCCESS name_id=%s groups=%s assertion_id=%s",
        record["name_id"], attributes.get("groups"), record["assertion_id"],
    )
    return redirect(url_for("index"))


@app.route("/assertion")
def assertion():
    record = current_assertion()
    if not record:
        return redirect(url_for("index"))
    stamps = {}
    for key in ("issued_at", "not_on_or_after"):
        value = record.get(key)
        if isinstance(value, (int, float)):
            stamps[key] = datetime.fromtimestamp(value, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        else:
            stamps[key] = value
    return render_template("assertion.html", a=record, stamps=stamps)


@app.route("/saml/metadata")
def metadata():
    """This SP's own metadata, the document an IdP admin would import."""
    auth = saml_auth()
    sp_settings = auth.get_settings()
    xml = sp_settings.get_sp_metadata()
    errors = sp_settings.validate_metadata(xml)
    if errors:
        return "Metadata errors: " + ", ".join(errors), 500
    return xml, 200, {"Content-Type": "text/xml"}


@app.route("/logout")
def logout():
    record = current_assertion()
    sid = session.get("sid")
    session.clear()
    if record:
        ASSERTION_STORE.pop(sid, None)
        audit.info("AUTH LOGOUT name_id=%s", record["name_id"])
    return redirect(url_for("index"))


if __name__ == "__main__":
    print("\nVAULT-DOOR SAML service provider running. Open http://localhost:8000 in your browser.")
    print("Press Ctrl + C to stop it.\n")
    # 0.0.0.0 inside the container so Docker can forward port 8000 to it.
    app.run(host="0.0.0.0", port=8000, debug=False)
