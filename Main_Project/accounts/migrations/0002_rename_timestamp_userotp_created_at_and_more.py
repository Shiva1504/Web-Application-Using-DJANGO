# Generated by Django 5.0.3 on 2024-12-25 11:04

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0001_initial"),
    ]

    operations = [
        migrations.RenameField(
            model_name="userotp",
            old_name="timestamp",
            new_name="created_at",
        ),
        migrations.DeleteModel(
            name="UserProfile",
        ),
    ]