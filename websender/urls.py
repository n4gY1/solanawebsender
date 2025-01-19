from django.urls import path

from websender.views import home_view, sender_view, logs_view, login_view, user_view, logout_view

urlpatterns = [
    path('', home_view,name="home"),
    path('send', sender_view,name="send"),
    path('logs',logs_view,name="logs"),
    path('login',login_view,name="login"),
    path('user',user_view,name="user"),
    path('logout',logout_view,name="logout"),
]