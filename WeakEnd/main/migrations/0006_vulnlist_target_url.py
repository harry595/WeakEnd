# Generated by Django 3.1 on 2021-04-04 15:34

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0005_vulnlist'),
    ]

    operations = [
        migrations.AddField(
            model_name='vulnlist',
            name='target_url',
            field=models.CharField(blank=True, max_length=200),
        ),
    ]
