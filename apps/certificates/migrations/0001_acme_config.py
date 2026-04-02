import django.db.models.deletion
import encrypted_model_fields.fields
from django.db import migrations
from django.db import models


class Migration(migrations.Migration):

    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="AcmeConfig",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("is_enabled", models.BooleanField(default=False)),
                (
                    "provider",
                    models.CharField(
                        choices=[
                            ("letsencrypt", "Let's Encrypt"),
                            ("letsencrypt_staging", "Let's Encrypt (Staging)"),
                            ("custom", "Custom / Internal CA"),
                        ],
                        default="letsencrypt",
                        max_length=30,
                    ),
                ),
                (
                    "directory_url",
                    models.CharField(
                        default="https://acme-v02.api.letsencrypt.org/directory",
                        help_text="ACME directory URL for the certificate authority.",
                        max_length=500,
                    ),
                ),
                (
                    "domain",
                    models.CharField(
                        blank=True,
                        help_text="Fully qualified domain name for the certificate.",
                        max_length=255,
                    ),
                ),
                (
                    "email",
                    models.EmailField(
                        blank=True,
                        help_text="Contact email for the ACME account. Required by Let's Encrypt.",
                        max_length=254,
                    ),
                ),
                (
                    "challenge_type",
                    models.CharField(
                        choices=[("http-01", "HTTP-01"), ("dns-01", "DNS-01")],
                        default="http-01",
                        max_length=10,
                    ),
                ),
                (
                    "acme_account_key_pem",
                    encrypted_model_fields.fields.EncryptedCharField(
                        blank=True, max_length=2000,
                    ),
                ),
                ("acme_account_url", models.CharField(blank=True, max_length=500)),
                (
                    "ca_bundle",
                    models.TextField(
                        blank=True,
                        help_text="PEM-encoded CA certificate for verifying the ACME server's TLS.",
                    ),
                ),
                (
                    "skip_tls_verify",
                    models.BooleanField(
                        default=False,
                        help_text="Disable TLS verification for the ACME server. Testing only.",
                    ),
                ),
                ("dns_txt_value", models.CharField(blank=True, max_length=500)),
                ("dns_challenge_pending", models.BooleanField(default=False)),
                ("last_renewed_at", models.DateTimeField(blank=True, null=True)),
                ("last_renewal_error", models.TextField(blank=True)),
                ("notify_30_sent", models.BooleanField(default=False)),
                ("notify_14_sent", models.BooleanField(default=False)),
                ("notify_7_sent", models.BooleanField(default=False)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={
                "verbose_name": "ACME Configuration",
            },
        ),
        migrations.CreateModel(
            name="AcmeLog",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("event", models.CharField(max_length=50)),
                ("detail", models.TextField(blank=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
            ],
            options={
                "ordering": ["-created_at"],
            },
        ),
    ]
