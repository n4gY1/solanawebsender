from django.urls import path

from websender.views import home_view, sender_view, logs_view

urlpatterns = [
    path('', home_view,name="home"),
    path('send', sender_view,name="send"),
    path('logs',logs_view,name="logs"),
]