

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
# Create your views here.
def home_view(request):
    user = request.user

    solana_user = SolanaUser.objects.get(user=user)
    template = "websender/home.html"
    if solana_user.key_name == "" or solana_user.key_secret == "" or solana_user.wallets == "" or solana_user.receiver_name == "" :
        return redirect("user")
    context = {
        "solana_user":solana_user
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

        if key_name and key_secret and name:
            logs = send_from_wallets(wallets, key_name=key_name, key_secret=key_secret, name=name,ip=ip,user=sol_user)
            print("[+] finished log")
    context = {
        "logs": logs
    }

    return render(request, template, context)

@login_required(login_url="login")
def logs_view(request):
    ip = get_client_ip(request)
    solana_user = SolanaUser.objects.get(user=request.user)

    template = "websender/logs.html"
    logs = SolanaLog.objects.filter(user=solana_user).order_by("-when_created")
    context = {
        "logs":logs,
        "ip":ip
    }

    return render(request,template,context)


def login_view(request):
    template = "websender/login.html"
    context ={}
    if request.method == "POST":
        username = request.POST["username"]
        password = request.POST["password"]
        print(username,password)
        user = authenticate(username=username,password=password)
        print(user)
        if user is not None:
            login(request,user)

            return redirect('home')
        else:
            context = {
                "error":"not valid username/password"
            }


    return render(request,template,context)

@login_required(login_url="login")
def user_view(request):


    template = "websender/user.html"
    sol_user = SolanaUser.objects.get(user=request.user)
    sol_sum = get_solana_sum(wallets=sol_user.wallets)
    form = SolanaUserForm(instance=sol_user)

    if request.method == "POST":
        form = SolanaUserForm(request.POST,instance=sol_user)
        if form.is_valid():
            form.save()


            return redirect("home")

    context ={
        "form":form,
        "sol_sum":sol_sum
    }

    return render(request,template,context)


@login_required(login_url="login")
def logout_view(request):
    logout(request)
    return redirect("login")
