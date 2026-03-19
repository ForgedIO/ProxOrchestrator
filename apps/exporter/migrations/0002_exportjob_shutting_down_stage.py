from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("exporter", "0001_initial"),
    ]

    operations = [
        migrations.AlterField(
            model_name="exportjob",
            name="stage",
            field=models.CharField(
                choices=[
                    ("QUEUED", "Queued"),
                    ("READING_CONFIG", "Reading Config"),
                    ("SHUTTING_DOWN", "Shutting Down"),
                    ("EXPORTING_DISKS", "Exporting Disks"),
                    ("BUILDING_MANIFEST", "Building Manifest"),
                    ("PACKAGING", "Packaging Archive"),
                    ("DONE", "Done"),
                    ("FAILED", "Failed"),
                ],
                default="QUEUED",
                max_length=30,
            ),
        ),
    ]
