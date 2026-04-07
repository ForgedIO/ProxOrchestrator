from django.db import migrations
from django.db import models


class Migration(migrations.Migration):

    dependencies = [
        ("certificates", "0001_acme_config"),
    ]

    operations = [
        migrations.AddField(
            model_name="acmeconfig",
            name="issuing_in_progress",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="acmeconfig",
            name="issuing_stage",
            field=models.CharField(blank=True, max_length=100),
        ),
    ]
