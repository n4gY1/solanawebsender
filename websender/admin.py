from django.contrib import admin

from websender.models import SolanaLog, SolanaUser

# Register your models here.
admin.site.register(SolanaLog)
admin.site.register(SolanaUser)