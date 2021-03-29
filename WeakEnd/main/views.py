from django.shortcuts import render

# Create your views here.
def index(request):
    return render(request,'index.html')

def detect(request):
    return render(request,'detect.html')

def directory(request):
    return render(request,'directory.html')

def mypage(request):
    return render(request,'mypage.html')

def patch(request):
    return render(request,'patch.html')

def signup(request):
    return render(request,'signup.html')

def signin(request):
    return render(request,'signin.html')

def subscribe(request):
    return render(request,'subscribe.html')

def vulndetected(request):
    return render(request,'vulndetected.html')