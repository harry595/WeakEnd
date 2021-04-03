from django.shortcuts import render, get_object_or_404, redirect
from django.views import View
from django.http import HttpResponse, HttpResponseRedirect
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from datetime import datetime
from django.core.exceptions import ObjectDoesNotExist
from django.views.decorators.csrf import csrf_exempt
from django.utils.dateparse import parse_date
from datetime import timedelta
from django.template import loader, RequestContext
from collections import OrderedDict
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.contrib.auth.forms import UserCreationForm
#from django.contrib.auth import get_user_model
from django.contrib.auth.views import LoginView
from django.views.decorators.http import require_GET, require_POST
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
import json
from django.db import connection
from django.views.generic import ListView
from django.db.models import Q
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib import messages as msgs
from .forms import UserForm, ProfileForm
from django.contrib.auth.models import User
from django.db import models
from .models import Profile
from django.contrib import auth
from django.contrib.auth import authenticate, login
import os
import requests
import time

# Create your views here.
def index(request):
    return render(request,'index.html')

@login_required 
def detect(request):
    return render(request,'detect.html')

@login_required 
def reports(request):
    return render(request,'reports.html')

@login_required 
def directory(request):
    if request.method == 'POST':
        session = requests.Session() 
        session.verify = False
        url = request.POST["url"]
        result=[]
        if url == "":
            return render(request,'directory.html')
        else:
            f = open(os.path.dirname(os.path.realpath(__file__)) + '/dataset/dir_scan_list.txt', "r")
            while True:
                data = f.readline()
                r = session.get(url+data)
                if r.status_code == 200:
                    print(url+data)
                    result.append("Connect → " + r.url)
                if not data: break
            result.append("")
            print(result)
            f.close()
    return render(request,'directory.html')

@login_required 
def mypage(request):
    return render(request,'mypage.html')

@login_required 
def changeUserInfo(request):
    if request.method == 'POST':
        user = request.user
        profile=user.profile

        profile.age = request.POST["age"]
        profile.job = request.POST["job"]
        profile.gender = request.POST["gender"]
        user.first_name = request.POST["first_name"]
        user.last_name = request.POST["last_name"]
        user.email = request.POST["email"]

        user.save()
        profile.save()
        return redirect('/')
    return render(request,'changeUserInfo.html')

@login_required 
def patch(request):
    return render(request,'patch.html')

@login_required 
def subscribe(request):
    return render(request,'subscribe.html')

@login_required 
def vulndetected(request):
    return render(request,'vulndetected.html')


def signup(request):
    if request.method == 'POST':
        if request.POST["password_first"] == request.POST["password_second"]:
            user = User.objects.create_user(
                username=request.POST["username"],
                password=request.POST["password_first"],
                email=request.POST["username"],
                first_name=request.POST["first_name"],
                last_name=request.POST["last_name"],
                )
            age = request.POST["age"]
            job = request.POST["job"]
            gender = request.POST["gender"]
            purpose = request.POST["purpose"]
            profile = Profile(user=user, age=age, job=job, gender=gender, purpose=purpose)
            profile.save()
            auth.login(request,user)
            return redirect('/')
    return render(request, 'signup.html')

def signin(request):
    if request.method == 'POST':
        username = request.POST['email']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('/')
        else:
            return render(request, 'signin.html')
    else:
        return render(request, 'signin.html')

