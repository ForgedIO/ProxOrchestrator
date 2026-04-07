from django.db import migrations
from django.db import models


class Migration(migrations.Migration):

    dependencies = [
        ("certificates", "0004_acme_dns_provider"),
    ]

    operations = [
        migrations.AddField(
            model_name="acmeconfig",
            name="ip_sans",
            field=models.CharField(
                blank=True, max_length=500,
                help_text="Comma-separated IP addresses to include as SANs.",
            ),
        ),
    ]
