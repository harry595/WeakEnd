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
    sub_first= models.DateTimeField(null=True)
    sub_second= models.DateTimeField(null=True)
    sub_third= models.DateTimeField(null=True)

