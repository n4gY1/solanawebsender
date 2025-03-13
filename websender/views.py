import datetime
import threading

from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.decorators import login_required


from django.shortcuts import render, redirect


from websender.forms import SolanaUserForm
from websender.get_sol_sum import get_solana_sum
from websender.models import SolanaLog, SolanaUser
from websender.utils import send_from_wallets


def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


@login_required(login_url="login")
def home_view(request):
    user = request.user

    solana_user = SolanaUser.objects.get(user=user)
    template = "websender/home.html"
    if solana_user.key_name == "" or solana_user.key_secret == "" or solana_user.wallets == "" or solana_user.receiver_name == "":
        return redirect("user")
    context = {
        "solana_user": solana_user
    }
    return render(request, template, context)


@login_required(login_url="login")
def sender_view(request):
    template = "websender/sender.html"
    user = request.user
    sol_user = SolanaUser.objects.get(user=user)
    logs = []
    if request.method == "POST":
        #print(request.POST)
        wallets = request.POST.get("wallets")
        key_name = request.POST.get("key_name")
        name = request.POST.get("name")
        key_secret = request.POST.get("key_secret")
        ip = get_client_ip(request)
        send_usdc = False
        send_eurc = False
        if "usdc" in request.POST:
            send_usdc = True
        if "eurc" in request.POST:
            send_eurc = True



        if key_name and key_secret and name:
            thread = threading.Thread(target=send_from_wallets,
                                      args=(wallets, key_name, key_secret, name, ip, sol_user, send_usdc, send_eurc))
            thread.start()
            #logs = send_from_wallets(wallets, key_name=key_name, key_secret=key_secret, name=name,ip=ip,user=sol_user)

    context = {
        "logs": logs
    }
    return redirect("logs")

    #return render(request, template, context)


@login_required(login_url="login")
def logs_view(request):
    ip = get_client_ip(request)
    solana_user = SolanaUser.objects.get(user=request.user)
    now = datetime.datetime.now()
    yesterday = now - datetime.timedelta(hours=24)
    last_month = now - datetime.timedelta(days=31)
    yesterday_logs_free = SolanaLog.objects.filter(user=solana_user, when_created__gte=yesterday,fee__in=["0","-1"]).count()
    yesterday_logs_all = SolanaLog.objects.filter(user=solana_user,when_created__gte=yesterday).count()
    last_month_logs_free = SolanaLog.objects.filter(user=solana_user,when_created__gte=last_month,fee__in=["0","-1"]).count()
    last_month_logs_all = SolanaLog.objects.filter(user=solana_user,when_created__gte=last_month).count()


    template = "websender/logs.html"
    logs = SolanaLog.objects.filter(user=solana_user).order_by("-when_created")[:100]
    context = {
        "logs": logs,
        "ip": ip,
        "yesterday_logs_free":yesterday_logs_free,
        "yesterday_logs_all":yesterday_logs_all,
        "last_month_logs_free":last_month_logs_free,
        "last_month_logs_all":last_month_logs_all,
    }

    return render(request, template, context)


def login_view(request):
    template = "websender/login.html"
    context = {}
    if request.method == "POST":
        username = request.POST["username"]
        password = request.POST["password"]
        print(username, password)
        user = authenticate(username=username, password=password)
        print(user)
        if user is not None:
            login(request, user)

            return redirect('home')
        else:
            context = {
                "error": "not valid username/password"
            }

    return render(request, template, context)


@login_required(login_url="login")
def user_view(request):
    template = "websender/user.html"
    sol_user = SolanaUser.objects.get(user=request.user)
    sol_sum = get_solana_sum(wallets=sol_user.wallets)
    form = SolanaUserForm(instance=sol_user)

    if request.method == "POST":
        form = SolanaUserForm(request.POST, instance=sol_user)
        if form.is_valid():
            form.save()

            return redirect("home")

    context = {
        "form": form,
        "sol_sum": sol_sum
    }

    return render(request, template, context)


@login_required(login_url="login")
def logout_view(request):
    logout(request)
    return redirect("login")