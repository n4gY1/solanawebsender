import time

from django.http import HttpResponse
from django.shortcuts import render, redirect


# Create your views here.
def home_view(request):
    template = "websender/home.html"
    context = {}
    return render(request, template, context)


def sender_view(request):
    template = "websender/sender.html"
    context = {}
    if request.method == "POST":
        print(request.POST)

    return render(request, template, context)
