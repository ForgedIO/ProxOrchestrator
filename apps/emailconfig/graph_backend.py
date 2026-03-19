import logging

import requests
from django.core.mail.backends.base import BaseEmailBackend

logger = logging.getLogger(__name__)

_TOKEN_URL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
_SEND_URL = "https://graph.microsoft.com/v1.0/users/{from_email}/sendMail"


class GraphEmailBackend(BaseEmailBackend):
    """Django email backend that sends via Microsoft Graph API.

    Uses the client credentials (application) flow — requires the
    Mail.Send application permission on the App Registration in Azure.
    The from_email must be a mailbox in the same tenant.
    """

    def _get_token(self, tenant_id, client_id, client_secret):
        resp = requests.post(
            _TOKEN_URL.format(tenant_id=tenant_id),
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": "https://graph.microsoft.com/.default",
            },
            timeout=15,
        )
        resp.raise_for_status()
        return resp.json()["access_token"]

    def send_messages(self, email_messages):
        from apps.emailconfig.models import EmailConfig

        config = EmailConfig.objects.first()
        if not config or not config.is_enabled:
            return 0
        if not config.graph_tenant_id or not config.graph_client_id or not config.graph_client_secret:
            logger.error("GraphEmailBackend: incomplete Graph API configuration")
            return 0

        try:
            token = self._get_token(
                config.graph_tenant_id,
                config.graph_client_id,
                config.graph_client_secret,
            )
        except Exception as exc:
            logger.error("GraphEmailBackend: failed to obtain access token: %s", exc)
            if not self.fail_silently:
                raise
            return 0

        sent = 0
        for message in email_messages:
            try:
                self._send_one(token, message, config.from_email)
                sent += 1
            except Exception as exc:
                logger.error(
                    "GraphEmailBackend: failed to send to %s: %s", message.to, exc
                )
                if not self.fail_silently:
                    raise
        return sent

    def _send_one(self, token, message, from_email):
        content_type = "html" if getattr(message, "content_subtype", "plain") == "html" else "text"
        payload = {
            "message": {
                "subject": message.subject,
                "body": {
                    "contentType": "HTML" if content_type == "html" else "Text",
                    "content": message.body,
                },
                "toRecipients": [
                    {"emailAddress": {"address": addr}} for addr in message.to
                ],
                "from": {"emailAddress": {"address": from_email}},
            },
            "saveToSentItems": False,
        }

        if message.cc:
            payload["message"]["ccRecipients"] = [
                {"emailAddress": {"address": addr}} for addr in message.cc
            ]
        if message.bcc:
            payload["message"]["bccRecipients"] = [
                {"emailAddress": {"address": addr}} for addr in message.bcc
            ]

        resp = requests.post(
            _SEND_URL.format(from_email=from_email),
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=30,
        )
        resp.raise_for_status()
