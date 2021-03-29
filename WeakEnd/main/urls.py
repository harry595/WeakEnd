from django.contrib import admin
from django.urls import path,include
from main import views
from django.contrib.auth import views as auth_views
from django.views.static import serve
from django.urls import re_path
from django.conf import settings
from django.conf.urls import url
from django.conf.urls.static import static
from . import views

app_name = 'main'

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.index, name='index'),
    path('detect/', views.detect, name='detect'), 
    path('directory/', views.directory, name='directory'), 
    path('mypage/', views.mypage, name='mypage'), 
    path('patch/', views.patch, name='patch'), 
    path('signup/', views.signup, name='signup'), 
    path('signin/', views.signin, name='signin'), 
    path('subscribe/', views.subscribe, name='subscribe'), 
    path('vulndetected/', views.vulndetected, name='vulndetected'), 
] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)