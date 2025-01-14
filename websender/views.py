import time

from django.http import HttpResponse
from django.shortcuts import render, redirect

from websender.utils import send_from_wallets


# Create your views here.
def home_view(request):
    template = "websender/home.html"
    context = {}
    return render(request, template, context)


def sender_view(request):
    template = "websender/sender.html"
    logs = []
    if request.method == "POST":
        print(request.POST)
        wallets = request.POST.get("wallets")
        key_name = request.POST.get("key_name")
        name = request.POST.get("name")
        key_secret = request.POST.get("key_secret")

        if key_name and key_secret and name:
            logs = send_from_wallets(wallets, key_name=key_name, key_secret=key_secret, name=name)
            print("[+] finished log", logs)
    context = {
        "logs": logs
    }

    return render(request, template, context)
