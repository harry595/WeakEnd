from django.shortcuts import render, get_object_or_404, redirect
from django.views import View
from django.http import HttpResponse, HttpResponseRedirect
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
import datetime
from django.core.exceptions import ObjectDoesNotExist
from django.views.decorators.csrf import csrf_exempt
from django.utils.dateparse import parse_date
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
from .models import Profile, Vulnlist
from django.contrib import auth
from django.contrib.auth import authenticate, login
import os
import requests
import time
#from .vuln_detect.vuln_code import attack_all
from .tasks import checkvuln
from celery.result import AsyncResult
from celery.states import state, PENDING, SUCCESS
from dateutil.relativedelta import relativedelta
from .autopatch.autopatch import vulnerability_patch

# Create your views here.
def index(request):
    return render(request,'index.html')

@login_required 
def detect(request):
    return render(request,'detect.html')

@login_required 
def reports(request,new_id):
    #user check
    check_user=Vulnlist.objects.values().filter(vuln_id=new_id)[0]['user_id_id']
    target_url=Vulnlist.objects.values().filter(vuln_id=new_id)[0]['target_url']
    detect_date=Vulnlist.objects.values().filter(vuln_id=new_id)[0]['detect_date']
    if(check_user!=request.user.id):
        return redirect('/')
    #json file create
    file_path = os.path.dirname(os.path.realpath(__file__)) + '/detectedVuln/'+str(new_id)+'.json'
    with open(file_path, "r") as json_file:
        json_data = json.load(json_file)
    # make form to jinja ex) {'LFI':2,'RFI':1,'CI':1}
    outputs=list(json_data.keys())
    print(json_data[outputs[0]])
    return render(request,'reports.html',{'json_data':json_data,'outputs':outputs,'new_id':new_id,'target_url':target_url,'detect_date':detect_date})

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
                    result.append(r.url)
                if not data: break
            f.close()
        print(result)
        return render(request,'directoryresult.html',{'result':result})
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
def subscribe(request):
    if request.method == 'POST':
        user = request.user
        profile=user.profile

        profile.sub_url = request.POST['url']
        term = int(request.POST['term'])
        num = int(request.POST['num'])

        current=datetime.date.today()
        # datetime term
        if term == 1:
            profile.sub_first = current + relativedelta(days=7*num)
            profile.sub_second = current + relativedelta(days=2*7*num)
            profile.sub_third = current + relativedelta(days=3*7*num)
        elif term == 2:
            profile.sub_first = current + relativedelta(months=num)
            profile.sub_second = current + relativedelta(months=2*num)
            profile.sub_third = current + relativedelta(months=3*num)
        else:
            profile.sub_first = current + relativedelta(years=num)
            profile.sub_second = current + relativedelta(years=2*num)
            profile.sub_third =current + relativedelta(years=3*num)
        profile.save()

        return render(request,'mypage.html')
    return render(request,'subscribe.html')


# get data by ajax
@login_required 
def vulngive(request):
    # get inform that clicked
    search_key = int(request.GET['search_key'])
    search_id = request.GET['search_id']
    new_id = request.GET['new_id']
    #check user
    check_user=Vulnlist.objects.values().filter(vuln_id=new_id).last()['user_id_id']
    if(check_user!=request.user.id):
        return redirect('/')
    # read json file
    file_path = os.path.dirname(os.path.realpath(__file__)) + '/detectedVuln/'+str(new_id)+'.json'
    with open(file_path, "r") as json_file:
        json_data = json.load(json_file)
    # return value of json
    output_data=json_data[search_id][search_key]
    context = {'output_data':output_data}
    return HttpResponse(json.dumps(context), content_type="application/json")

@csrf_exempt
@login_required 
def patching(request):
    # get inform that clicked
    VulnType = int(request.POST['VulnType'])
    BackType = int(request.POST['BackType'])
    beforecode = request.POST['beforecode']
    patch_result=vulnerability_patch(BackType,VulnType,beforecode)
    print(patch_result)
    # return value of json
    context = {'patch_result':patch_result}
    return HttpResponse(patch_result)

@login_required 
def patch(request):
    return render(request,'patch.html')

@login_required 
def vulndetected(request,new_id):
    #user check
    try:
        task_id=request.GET['task_id']
    except:
        task_id=0
    check_user=Vulnlist.objects.values().filter(vuln_id=new_id).last()['user_id_id']
    if(check_user!=request.user.id):
        return redirect('/')
    #json file create
    file_path = os.path.dirname(os.path.realpath(__file__)) + '/detectedVuln/'+str(new_id)+'.json'
    with open(file_path, "r") as json_file:
        json_data = json.load(json_file)
    # make form to jinja ex) {'LFI':2,'RFI':1,'CI':1}
    outputs={}
    forjinja='0'*100
    for vuln_keys in json_data.keys():
        outputs[vuln_keys]=forjinja[0:len(json_data[vuln_keys])]
    print(outputs)
    return render(request,'vulndetected.html',{'outputs':outputs,'new_id':new_id,'task_id':task_id})

@login_required 
def vulndetecting(request):
    # CHECK URL
    '''
    if not url.startswith("http"):
        url = "http://" + input_url
    else:
        url = input_url
    check_url = requests.get(url,verify=False)
    if res_rfi.status_code != 200:
        return render(request,'detect.html')        
    '''
    url=request.POST["url"]
    cookie=request.POST["cookie"]
    level=request.POST["level"]
    new_id=Vulnlist.objects.all().values('vuln_id').last()['vuln_id']+1
    new_vuln = Vulnlist(
        vuln_id=new_id,
        user_id=request.user,
        target_url=url,
        cookie=cookie,
        level=level
    )
    new_vuln.save()
    f = open(os.path.dirname(os.path.realpath(__file__)) + '/detectedVuln/'+str(new_id)+'.json', 'w')
    f.write("{}")
    f.close()
    time.sleep(2)
    
    # insert finding subdomain code (blackwidow)
    # DO SOMETHING
    # 파일 경로는 os.path.dirname(os.path.realpath(__file__)) + '/vuln_detect/vuln_code/dirscanning/'+user_id'/'+url+'/'+url+'-subdomains-sorted.txt'
    time.sleep(1)
    url='192.168.112.130'
    url+='_80'
    #here
    #171=user_id
    with open(os.path.dirname(os.path.realpath(__file__)) + '/vuln_detect/vuln_code/dirscanning/171/'+url+'/'+url+'-subdomains-sorted.txt', "r") as f:
        urllist = f.readlines()
    urllist = [x.strip() for x in urllist] 
    context={'urllist':urllist,'new_id':new_id }
    return render(request, 'detectsearch.html',context)
    
    


@login_required 
def detectsearch(request):
    urls=request.POST.getlist('urls[]')
    #hidden 형식으로 데이터 가져오기
    new_id=request.POST["new_id"]

    vulner=Vulnlist.objects.values().filter(vuln_id=new_id).last()
    cookies=vulner['cookie']
    level=vulner['level']
    cookies=cookies.replace("'",'\"')
    cookies=json.loads(cookies)
    # 아래에서 선택한 서브 도메인들 리스트에 맞춰 black widow 돌리기
    time.sleep(5)
    # 여기까지 
    detected_vuln=checkvuln.delay(urls,cookies,level,new_id)
    return HttpResponseRedirect('/vulndetected/'+str(new_id)+'?task_id='+detected_vuln.id)


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


# Create your views here.
def progress(request):
    """ A view to report the progress to the user """
    data = 'Fail'
    if request.is_ajax():
        if 'task_id' in request.POST.keys() and request.POST['task_id']:
            task_id = request.POST['task_id']
            task = AsyncResult(task_id)
            data = task.result or task.state
        else:
            data = 'No task_id in the request'
    else:
        data = 'This is not an ajax request'

    json_data = json.dumps(data)
    print(json_data)
    return HttpResponse(json_data, content_type='application/json')
