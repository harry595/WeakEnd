# Generated by Django 3.1 on 2021-03-30 08:47

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Profile',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('user_pk', models.IntegerField(blank=True)),
                ('age', models.IntegerField(blank=True)),
                ('job', models.CharField(blank=True, max_length=50)),
                ('gender', models.CharField(blank=True, max_length=10)),
                ('purpose', models.CharField(blank=True, max_length=200)),
                ('sub_first', models.DateTimeField(blank=True)),
                ('sub_second', models.DateTimeField(blank=True)),
                ('sub_third', models.DateTimeField(blank=True)),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
