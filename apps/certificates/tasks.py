import logging
import os
import tempfile

import redis
from celery import shared_task
from django.conf import settings
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.utils import timezone

from apps.certificates import acme
from apps.certificates.acme import AcmeError

logger = logging.getLogger(__name__)

CERT_DIR = "/opt/proxmigrate/certs"
CERT_FILE = os.path.join(CERT_DIR, "proxmigrate.crt")
KEY_FILE = os.path.join(CERT_DIR, "proxmigrate.key")
CHALLENGE_DIR = os.path.join(CERT_DIR, "acme-challenge")
ACME_NGINX_CONF = "/opt/proxmigrate/deploy/acme-challenge.conf"

REDIS_DNS_CONFIRM_KEY = "acme:dns_confirmed"
DNS_POLL_INTERVAL = 10
DNS_POLL_TIMEOUT = 1800  # 30 minutes

ACME_NGINX_BLOCK = """server {
    listen 80;
    server_name _;
    location /.well-known/acme-challenge/ {
        alias /opt/proxmigrate/certs/acme-challenge/;
    }
    location / {
        return 301 https://$host$request_uri;
    }
}
"""


def _get_redis():
    """Return a Redis client using the Celery broker URL."""
    broker_url = getattr(settings, "CELERY_BROKER_URL", "redis://127.0.0.1:6379/0")
    return redis.Redis.from_url(broker_url)


def _install_cert_and_key(cert_pem, key_pem):
    """Write certificate and key files to disk."""
    os.makedirs(CERT_DIR, exist_ok=True)
    with open(CERT_FILE, "wb") as f:
        f.write(cert_pem if isinstance(cert_pem, bytes) else cert_pem.encode())
    with open(KEY_FILE, "wb") as f:
        f.write(key_pem if isinstance(key_pem, bytes) else key_pem.encode())
    os.chmod(KEY_FILE, 0o600)


def _reload_nginx():
    """Reload nginx. Raises RuntimeError on failure."""
    import subprocess

    result = subprocess.run(
        ["sudo", "nginx", "-s", "reload"],
        capture_output=True, text=True, shell=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"nginx reload failed: {result.stderr.strip()}")


def _test_nginx():
    """Test nginx config. Returns True if valid."""
    import subprocess

    result = subprocess.run(
        ["sudo", "nginx", "-t"],
        capture_output=True, text=True, shell=False,
    )
    return result.returncode == 0


def _write_acme_nginx(content):
    """Write the ACME challenge nginx config file."""
    with open(ACME_NGINX_CONF, "w") as f:
        f.write(content)


def _cleanup_challenge(token=None):
    """Remove challenge token file and clear the nginx config."""
    if token:
        token_path = os.path.join(CHALLENGE_DIR, token)
        if os.path.exists(token_path):
            os.remove(token_path)

    _write_acme_nginx("")
    try:
        _reload_nginx()
    except RuntimeError:
        logger.warning("nginx reload failed during challenge cleanup")


def _get_verify(config):
    """Build the requests verify parameter from AcmeConfig."""
    if config.skip_tls_verify:
        return False
    if config.ca_bundle.strip():
        # Write CA bundle to a temp file for requests to use
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".pem", delete=False,
            dir=CERT_DIR,
        )
        tmp.write(config.ca_bundle.strip())
        tmp.close()
        return tmp.name
    return True


def _cleanup_ca_bundle(verify):
    """Remove temporary CA bundle file if one was created."""
    if isinstance(verify, str) and verify.startswith(CERT_DIR) and verify.endswith(".pem"):
        try:
            os.remove(verify)
        except OSError:
            pass


def _get_cert_info():
    """Parse the current certificate and return info dict."""
    from cryptography import x509

    if not os.path.exists(CERT_FILE):
        return None
    try:
        with open(CERT_FILE, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())
        return {
            "not_after": cert.not_valid_after_utc,
            "not_before": cert.not_valid_before_utc,
        }
    except Exception:
        return None


@shared_task(bind=True, name="certificates.issue_acme_certificate")
def issue_acme_certificate(self):
    """Issue or renew a certificate via ACME protocol."""
    from apps.certificates.models import AcmeConfig, AcmeLog

    config = AcmeConfig.get_config()
    if not config.domain:
        raise AcmeError("No domain configured for ACME")

    verify = _get_verify(config)
    token = None

    try:
        # Step 1: Account registration
        if not config.acme_account_key_pem:
            logger.info("Generating ACME account key")
            key_pem = acme.generate_account_key()
            config.acme_account_key_pem = key_pem.decode("utf-8")
            config.save(update_fields=["acme_account_key_pem", "updated_at"])

        if not config.acme_account_url:
            logger.info("Registering ACME account at %s", config.directory_url)
            account_url = acme.register_account(
                config.acme_account_key_pem,
                config.directory_url,
                email=config.email or None,
                verify=verify,
            )
            config.acme_account_url = account_url
            config.save(update_fields=["acme_account_url", "updated_at"])
            AcmeLog.log("account_registered", f"Account: {account_url}")

        key_pem = config.acme_account_key_pem
        account_url = config.acme_account_url

        # Step 2: Create order
        logger.info("Creating ACME order for %s", config.domain)
        order_url, order = acme.create_order(
            key_pem, account_url, config.directory_url, config.domain,
            verify=verify,
        )
        AcmeLog.log("order_created", f"Order for {config.domain}")

        # Step 3: Handle authorizations (if needed)
        if order.get("status") not in ("ready", "valid"):
            for auth_url in order.get("authorizations", []):
                auth = acme.get_authorization(
                    key_pem, account_url, auth_url, verify=verify,
                )

                if auth.get("status") == "valid":
                    continue

                if config.challenge_type == "http-01":
                    challenge = acme.get_http01_challenge(auth)
                    if not challenge:
                        raise AcmeError("No HTTP-01 challenge available")

                    token = challenge["token"]
                    key_auth = acme.compute_key_authorization(key_pem, token)

                    # Write challenge token file
                    os.makedirs(CHALLENGE_DIR, exist_ok=True)
                    token_path = os.path.join(CHALLENGE_DIR, token)
                    with open(token_path, "w") as f:
                        f.write(key_auth)

                    # Enable nginx port 80 block
                    _write_acme_nginx(ACME_NGINX_BLOCK)
                    if not _test_nginx():
                        _cleanup_challenge(token)
                        raise AcmeError(
                            "nginx config test failed — port 80 may be in use. "
                            "Ensure port 80 is available for HTTP-01 challenges."
                        )
                    _reload_nginx()

                    # Respond to challenge
                    acme.respond_to_challenge(
                        key_pem, account_url, challenge["url"], verify=verify,
                    )
                    AcmeLog.log("challenge_completed", "HTTP-01 challenge submitted")

                else:
                    # DNS-01
                    challenge = acme.get_dns01_challenge(auth)
                    if not challenge:
                        raise AcmeError("No DNS-01 challenge available")

                    txt_value = acme.compute_dns01_txt_value(
                        key_pem, challenge["token"],
                    )
                    config.dns_txt_value = txt_value
                    config.dns_challenge_pending = True
                    config.save(update_fields=[
                        "dns_txt_value", "dns_challenge_pending", "updated_at",
                    ])

                    # Wait for user to confirm DNS record creation
                    r = _get_redis()
                    r.delete(REDIS_DNS_CONFIRM_KEY)
                    logger.info(
                        "Waiting for DNS-01 TXT record confirmation. "
                        "Record: _acme-challenge.%s = %s",
                        config.domain, txt_value,
                    )

                    import time

                    deadline = time.time() + DNS_POLL_TIMEOUT
                    while time.time() < deadline:
                        if r.get(REDIS_DNS_CONFIRM_KEY):
                            break
                        time.sleep(DNS_POLL_INTERVAL)
                    else:
                        config.dns_challenge_pending = False
                        config.save(update_fields=["dns_challenge_pending", "updated_at"])
                        raise AcmeError(
                            "DNS-01 confirmation timed out after 30 minutes"
                        )

                    config.dns_challenge_pending = False
                    config.save(update_fields=["dns_challenge_pending", "updated_at"])
                    r.delete(REDIS_DNS_CONFIRM_KEY)

                    acme.respond_to_challenge(
                        key_pem, account_url, challenge["url"], verify=verify,
                    )
                    AcmeLog.log("challenge_completed", "DNS-01 challenge submitted")

            # Poll order until ready
            order = acme.poll_order(
                key_pem, account_url, order_url, verify=verify,
            )

        # Step 4: Generate CSR and finalize
        logger.info("Finalizing ACME order for %s", config.domain)
        cert_key_pem, csr_der = acme.generate_csr(config.domain)

        finalize_url = order.get("finalize")
        if not finalize_url:
            raise AcmeError("No finalize URL in order")

        order = acme.finalize_order(
            key_pem, account_url, finalize_url, csr_der, verify=verify,
        )

        # Poll again if needed after finalization
        if order.get("status") != "valid":
            order = acme.poll_order(
                key_pem, account_url, order_url, verify=verify,
            )

        # Step 5: Download and install certificate
        cert_url = order.get("certificate")
        if not cert_url:
            raise AcmeError("No certificate URL in finalized order")

        cert_pem = acme.download_certificate(
            key_pem, account_url, cert_url, verify=verify,
        )

        _install_cert_and_key(cert_pem, cert_key_pem)
        _reload_nginx()
        logger.info("ACME certificate installed for %s", config.domain)

        # Step 6: Update config
        config.is_enabled = True
        config.last_renewed_at = timezone.now()
        config.last_renewal_error = ""
        config.notify_30_sent = False
        config.notify_14_sent = False
        config.notify_7_sent = False
        config.save(update_fields=[
            "is_enabled", "last_renewed_at", "last_renewal_error",
            "notify_30_sent", "notify_14_sent", "notify_7_sent", "updated_at",
        ])

        AcmeLog.log("cert_issued", f"Certificate issued for {config.domain}")

    except Exception as exc:
        config.refresh_from_db()
        config.last_renewal_error = str(exc)
        config.save(update_fields=["last_renewal_error", "updated_at"])
        AcmeLog.log("renewal_failed", str(exc))
        logger.error("ACME certificate issuance failed: %s", exc)
        raise

    finally:
        _cleanup_challenge(token)
        _cleanup_ca_bundle(verify)


@shared_task(name="certificates.check_cert_expiry")
def check_cert_expiry():
    """Daily task: check certificate expiry, auto-renew or send alerts."""
    from apps.certificates.models import AcmeConfig

    cert_info = _get_cert_info()
    if not cert_info or "not_after" not in cert_info:
        return

    days_remaining = (cert_info["not_after"] - timezone.now()).days
    logger.info("Certificate expires in %d days", days_remaining)

    config = AcmeConfig.get_config()

    # Auto-renew if ACME is enabled and HTTP-01
    if config.is_enabled and days_remaining <= 30:
        if config.challenge_type == "http-01":
            logger.info("Auto-renewing certificate via ACME (HTTP-01)")
            issue_acme_certificate.delay()
            return
        else:
            logger.info(
                "Certificate expiring but DNS-01 requires manual renewal — sending alerts"
            )

    # Send email alerts at thresholds
    _send_expiry_alerts(config, days_remaining)


def _send_expiry_alerts(config, days_remaining):
    """Send email alerts at 30/14/7 day thresholds."""
    thresholds = [
        (30, "notify_30_sent"),
        (14, "notify_14_sent"),
        (7, "notify_7_sent"),
    ]

    staff_emails = list(
        User.objects.filter(is_staff=True)
        .exclude(email="")
        .values_list("email", flat=True)
    )
    if not staff_emails:
        return

    for days_threshold, flag_field in thresholds:
        if days_remaining <= days_threshold and not getattr(config, flag_field):
            urgency = "URGENT: " if days_threshold == 7 else ""
            subject = (
                f"[ProxMigrate] {urgency}TLS certificate expires "
                f"in {days_remaining} days"
            )
            body = (
                f"The TLS certificate for ProxMigrate expires in "
                f"{days_remaining} days.\n\n"
                f"Please log in to ProxMigrate and visit Settings > "
                f"Certificates to renew.\n\n"
                f"— ProxMigrate"
            )

            try:
                send_mail(
                    subject,
                    body,
                    None,  # uses DEFAULT_FROM_EMAIL
                    staff_emails,
                    fail_silently=True,
                )
                setattr(config, flag_field, True)
                config.save(update_fields=[flag_field, "updated_at"])
                logger.info("Sent %d-day expiry alert to %d staff users",
                            days_threshold, len(staff_emails))
            except Exception as exc:
                logger.error("Failed to send expiry alert: %s", exc)

            break  # Only send the most relevant threshold
