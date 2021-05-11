from django.db.models.signals import post_save
from django.dispatch import receiver
from django.db import models
from django.contrib.auth.models import User

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    age = models.IntegerField(blank=True)
    job = models.CharField(max_length=50, blank=True)
    gender = models.CharField(max_length=10, blank=True)
    purpose = models.CharField(max_length=200, blank=True)
    sub_url= models.CharField(max_length=200, null=True)
    sub_first= models.DateField(null=True)
    sub_second= models.DateField(null=True)
    sub_third= models.DateField(null=True)

class Vulnlist(models.Model):
    vuln_id = models.AutoField(primary_key=True)
    user_id = models.ForeignKey(User, on_delete=models.CASCADE, db_column="user_id")
    target_url = models.CharField(max_length=200, blank=True)
    detect_date= models.DateField(auto_now=True)
