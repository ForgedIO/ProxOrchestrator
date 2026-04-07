"""
ACME protocol client (RFC 8555).

Pure protocol implementation using `requests` and `cryptography`.
Works with any ACME-compliant CA: Let's Encrypt, Microsoft ADCS,
Smallstep, Keyfactor, etc.

No Django imports — this module is testable in isolation.
"""

import base64
import hashlib
import json
import logging
import time

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 30
POLL_INTERVAL = 5
POLL_MAX_SECONDS = 300


class AcmeError(Exception):
    """Raised for ACME protocol errors."""
    pass


# ---------------------------------------------------------------------------
# Encoding helpers
# ---------------------------------------------------------------------------

def _b64url(data):
    """Base64url-encode bytes without padding."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_int(n):
    """Base64url-encode a positive integer."""
    length = (n.bit_length() + 7) // 8
    return _b64url(n.to_bytes(length, byteorder="big"))


# ---------------------------------------------------------------------------
# Key management
# ---------------------------------------------------------------------------

def generate_account_key():
    """Generate an EC P-256 private key and return PEM bytes."""
    key = ec.generate_private_key(ec.SECP256R1())
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _load_key(pem_bytes):
    """Load a PEM-encoded private key."""
    if isinstance(pem_bytes, str):
        pem_bytes = pem_bytes.encode("utf-8")
    return serialization.load_pem_private_key(pem_bytes, password=None)


def _jwk_thumbprint(key):
    """Compute the JWK thumbprint (RFC 7638) of an EC public key."""
    pub = key.public_key()
    nums = pub.public_numbers()
    jwk = {
        "crv": "P-256",
        "kty": "EC",
        "x": _b64url_int(nums.x),
        "y": _b64url_int(nums.y),
    }
    # Thumbprint uses lexicographic JSON with no spaces
    jwk_json = json.dumps(jwk, sort_keys=True, separators=(",", ":"))
    return _b64url(hashlib.sha256(jwk_json.encode("utf-8")).digest())


def _jwk(key):
    """Return the JWK dict for an EC public key."""
    pub = key.public_key()
    nums = pub.public_numbers()
    return {
        "crv": "P-256",
        "kty": "EC",
        "x": _b64url_int(nums.x),
        "y": _b64url_int(nums.y),
    }


# ---------------------------------------------------------------------------
# JWS signing
# ---------------------------------------------------------------------------

def _sign_request(key, url, payload, kid=None, nonce=None):
    """Build a JWS-signed ACME request body.

    Uses `jwk` in the header for new-account requests (kid=None),
    and `kid` for all subsequent requests.
    """
    protected = {"alg": "ES256", "nonce": nonce, "url": url}
    if kid:
        protected["kid"] = kid
    else:
        protected["jwk"] = _jwk(key)

    protected_b64 = _b64url(json.dumps(protected))

    if payload is None:
        # POST-as-GET: empty payload
        payload_b64 = ""
    elif payload == "":
        payload_b64 = ""
    else:
        payload_b64 = _b64url(json.dumps(payload))

    signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")

    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    der_sig = key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_sig)
    # ES256 signature is r || s, each 32 bytes
    sig_bytes = r.to_bytes(32, byteorder="big") + s.to_bytes(32, byteorder="big")

    return {
        "protected": protected_b64,
        "payload": payload_b64,
        "signature": _b64url(sig_bytes),
    }


# ---------------------------------------------------------------------------
# ACME directory & nonce
# ---------------------------------------------------------------------------

_directory_cache = {}
_active_directory_url = None


def get_directory(directory_url, verify=True):
    """Fetch the ACME directory JSON. Cached per URL.

    Also stores the directory_url as the active directory so that
    subsequent calls to _acme_post can always find it.
    """
    global _active_directory_url

    _active_directory_url = directory_url

    if directory_url in _directory_cache:
        return _directory_cache[directory_url]

    resp = requests.get(directory_url, timeout=DEFAULT_TIMEOUT, verify=verify)
    if resp.status_code != 200:
        raise AcmeError(f"Failed to fetch ACME directory: HTTP {resp.status_code}")

    directory = resp.json()
    _directory_cache[directory_url] = directory
    return directory


def _get_nonce(directory, verify=True):
    """Fetch a fresh anti-replay nonce."""
    resp = requests.head(
        directory["newNonce"], timeout=DEFAULT_TIMEOUT, verify=verify,
    )
    nonce = resp.headers.get("Replay-Nonce")
    if not nonce:
        raise AcmeError("No Replay-Nonce header in newNonce response")
    return nonce


def _acme_post(key, url, payload, kid=None, verify=True, directory_url=None):
    """Send a signed ACME POST request and return the response.

    Handles nonce refresh on badNonce errors (one retry).
    """
    # Always use the directory to get nonces — some ACME servers (Smallstep)
    # only provide nonces via the newNonce endpoint
    dir_url = directory_url or _active_directory_url
    if not dir_url:
        raise AcmeError("No ACME directory URL available — call get_directory() first")

    directory = get_directory(dir_url, verify=verify)
    nonce = _get_nonce(directory, verify=verify)

    body = _sign_request(key, url, payload, kid=kid, nonce=nonce)
    headers = {"Content-Type": "application/jose+json"}

    # Use a fresh session for each POST to avoid stale TLS connections
    # (nginx reloads during challenge setup can break connection pools)
    session = requests.Session()
    session.verify = verify
    try:
        resp = session.post(url, json=body, headers=headers, timeout=DEFAULT_TIMEOUT)

        # Retry once on badNonce
        if resp.status_code == 400:
            try:
                err = resp.json()
                if err.get("type", "").endswith("badNonce"):
                    new_nonce = resp.headers.get("Replay-Nonce")
                    if not new_nonce and directory:
                        new_nonce = _get_nonce(directory, verify=verify)
                    if new_nonce:
                        body = _sign_request(key, url, payload, kid=kid, nonce=new_nonce)
                        resp = session.post(
                            url, json=body, headers=headers,
                            timeout=DEFAULT_TIMEOUT,
                        )
            except (ValueError, KeyError):
                pass

        return resp
    finally:
        session.close()


# ---------------------------------------------------------------------------
# Account management
# ---------------------------------------------------------------------------

def register_account(account_key_pem, directory_url, email=None, verify=True):
    """Register an ACME account (or find existing). Returns the account URL."""
    key = _load_key(account_key_pem)
    directory = get_directory(directory_url, verify=verify)

    payload = {"termsOfServiceAgreed": True}
    if email:
        payload["contact"] = [f"mailto:{email}"]

    nonce = _get_nonce(directory, verify=verify)
    body = _sign_request(key, directory["newAccount"], payload, nonce=nonce)
    headers = {"Content-Type": "application/jose+json"}

    resp = requests.post(
        directory["newAccount"], json=body, headers=headers,
        timeout=DEFAULT_TIMEOUT, verify=verify,
    )

    if resp.status_code not in (200, 201):
        raise AcmeError(
            f"Account registration failed: HTTP {resp.status_code} — {resp.text}"
        )

    account_url = resp.headers.get("Location")
    if not account_url:
        raise AcmeError("No Location header in account registration response")

    logger.info("ACME account registered/found: %s", account_url)
    return account_url


# ---------------------------------------------------------------------------
# Certificate ordering
# ---------------------------------------------------------------------------

def create_order(account_key_pem, account_url, directory_url, domain,
                  ip_sans=None, verify=True):
    """Create a new certificate order. Returns (order_url, order_body)."""
    key = _load_key(account_key_pem)
    directory = get_directory(directory_url, verify=verify)

    identifiers = [{"type": "dns", "value": domain}]
    for ip in (ip_sans or []):
        identifiers.append({"type": "ip", "value": ip.strip()})

    payload = {
        "identifiers": identifiers,
    }

    resp = _acme_post(
        key, directory["newOrder"], payload,
        kid=account_url, verify=verify, directory_url=directory_url,
    )

    if resp.status_code not in (200, 201):
        raise AcmeError(f"Order creation failed: HTTP {resp.status_code} — {resp.text}")

    order_url = resp.headers.get("Location", "")
    return order_url, resp.json()


def get_authorization(account_key_pem, account_url, auth_url, verify=True):
    """Fetch an authorization object. Returns the JSON body."""
    key = _load_key(account_key_pem)
    resp = _acme_post(key, auth_url, None, kid=account_url, verify=verify)

    if resp.status_code != 200:
        raise AcmeError(f"Authorization fetch failed: HTTP {resp.status_code}")

    return resp.json()


def get_http01_challenge(authorization):
    """Extract the HTTP-01 challenge from an authorization, or None."""
    for chall in authorization.get("challenges", []):
        if chall.get("type") == "http-01":
            return chall
    return None


def get_dns01_challenge(authorization):
    """Extract the DNS-01 challenge from an authorization, or None."""
    for chall in authorization.get("challenges", []):
        if chall.get("type") == "dns-01":
            return chall
    return None


# ---------------------------------------------------------------------------
# Challenge computation
# ---------------------------------------------------------------------------

def compute_key_authorization(account_key_pem, token):
    """Compute the key authorization string for HTTP-01: token.thumbprint."""
    key = _load_key(account_key_pem)
    thumbprint = _jwk_thumbprint(key)
    return f"{token}.{thumbprint}"


def compute_dns01_txt_value(account_key_pem, token):
    """Compute the DNS-01 TXT record value: base64url(SHA256(keyAuthorization))."""
    key_auth = compute_key_authorization(account_key_pem, token)
    digest = hashlib.sha256(key_auth.encode("utf-8")).digest()
    return _b64url(digest)


# ---------------------------------------------------------------------------
# Challenge response & polling
# ---------------------------------------------------------------------------

def respond_to_challenge(account_key_pem, account_url, challenge_url, verify=True):
    """Tell the ACME server the challenge is ready for validation."""
    key = _load_key(account_key_pem)
    resp = _acme_post(
        key, challenge_url, {}, kid=account_url, verify=verify,
    )

    if resp.status_code not in (200, 202):
        raise AcmeError(
            f"Challenge response failed: HTTP {resp.status_code} — {resp.text}"
        )

    return resp.json()


def poll_order(account_key_pem, account_url, order_url, verify=True,
               timeout=POLL_MAX_SECONDS):
    """Poll an order until it reaches 'ready' or 'valid' state.

    Returns the order JSON. Raises AcmeError on 'invalid' or timeout.
    """
    key = _load_key(account_key_pem)
    deadline = time.time() + timeout

    while time.time() < deadline:
        resp = _acme_post(key, order_url, None, kid=account_url, verify=verify)

        if resp.status_code != 200:
            raise AcmeError(f"Order poll failed: HTTP {resp.status_code}")

        order = resp.json()
        status = order.get("status")

        if status in ("ready", "valid"):
            return order
        if status == "invalid":
            raise AcmeError(f"Order became invalid: {json.dumps(order)}")

        logger.debug("Order status: %s — polling again in %ds", status, POLL_INTERVAL)
        time.sleep(POLL_INTERVAL)

    raise AcmeError(f"Order did not become ready within {timeout}s")


# ---------------------------------------------------------------------------
# Finalization & certificate download
# ---------------------------------------------------------------------------

def generate_csr(domain, ip_sans=None):
    """Generate a fresh RSA 2048 key + CSR for the given domain.

    Returns (private_key_pem, csr_der).
    """
    import ipaddress as _ipaddress

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    san_list = [x509.DNSName(domain)]
    for ip in (ip_sans or []):
        try:
            san_list.append(x509.IPAddress(_ipaddress.ip_address(ip.strip())))
        except ValueError:
            logger.warning("Skipping invalid IP SAN: %s", ip)

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)]))
        .add_extension(
            x509.SubjectAlternativeName(san_list),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    csr_der = csr.public_bytes(serialization.Encoding.DER)

    return key_pem, csr_der


def finalize_order(account_key_pem, account_url, finalize_url, csr_der, verify=True):
    """Submit a CSR to finalize the order. Returns the updated order JSON."""
    key = _load_key(account_key_pem)
    payload = {"csr": _b64url(csr_der)}

    resp = _acme_post(
        key, finalize_url, payload, kid=account_url, verify=verify,
    )

    if resp.status_code not in (200, 201):
        raise AcmeError(
            f"Order finalization failed: HTTP {resp.status_code} — {resp.text}"
        )

    return resp.json()


def download_certificate(account_key_pem, account_url, cert_url, verify=True):
    """Download the issued certificate chain. Returns PEM bytes."""
    key = _load_key(account_key_pem)
    resp = _acme_post(key, cert_url, None, kid=account_url, verify=verify)

    if resp.status_code != 200:
        raise AcmeError(
            f"Certificate download failed: HTTP {resp.status_code} — {resp.text}"
        )

    return resp.content
