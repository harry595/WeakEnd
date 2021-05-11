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
    path('reports/<int:new_id>', views.reports, name='reports'), 
    path('detect/', views.detect, name='detect'), 
    path('directory/', views.directory, name='directory'), 
    path('mypage/', views.mypage, name='mypage'), 
    path('changeUserInfo/', views.changeUserInfo, name='changeUserInfo'), 
    path('patch/', views.patch, name='patch'), 
    path('patch/patching/', views.patching, name='patching'),
    path('signup/', views.signup, name='signup'), 
    path('signin/', views.signin, name='signin'), 
    path('signout/', auth_views.LogoutView.as_view(), name="signout"),
    path('subscribe/', views.subscribe, name='subscribe'), 
    path('vulndetecting/', views.vulndetecting, name='vulndetecting'), 
    path('vulndetected/<int:new_id>', views.vulndetected, name='vulndetected'),
    path('vulndetected/progress', views.progress, name='progress'),
    path('vulndetected/vulngive/', views.vulngive, name="vulngive"),

] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)