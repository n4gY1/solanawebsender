import time

from django.http import HttpResponse
from django.shortcuts import render, redirect

from websender.models import SolanaLog
from websender.utils import send_from_wallets


def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

# Create your views here.
def home_view(request):
    template = "websender/home.html"
    context = {}
    return render(request, template, context)


def sender_view(request):
    template = "websender/sender.html"
    logs = []
    if request.method == "POST":
        #print(request.POST)
        wallets = request.POST.get("wallets")
        key_name = request.POST.get("key_name")
        name = request.POST.get("name")
        key_secret = request.POST.get("key_secret")
        ip = get_client_ip(request)

        if key_name and key_secret and name:
            logs = send_from_wallets(wallets, key_name=key_name, key_secret=key_secret, name=name,ip=ip)
            print("[+] finished log")
    context = {
        "logs": logs
    }

    return render(request, template, context)

def logs_view(request):
    ip = get_client_ip(request)
    template = "websender/logs.html"
    obj = SolanaLog.objects.all().order_by("-when_created")
    context = {
        "logs":obj,
        "ip":ip
    }

    return render(request,template,context)
