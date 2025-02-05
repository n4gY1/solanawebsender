from django.contrib import admin
from django.contrib.admin import ModelAdmin

from websender.models import SolanaLog, SolanaUser

# Register your models here.

class SolanaLogAdmin(ModelAdmin):
    list_display = ["user","fee","ip","currency","when_created","destination_address"]
    list_filter = ["user"]

admin.site.register(SolanaLog,SolanaLogAdmin)
admin.site.register(SolanaUser)