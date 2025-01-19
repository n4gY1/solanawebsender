from django.contrib.auth.models import User
from django.db import models

# Create your models here.


class SolanaUser(models.Model):
    user = models.ForeignKey(User,on_delete=models.CASCADE)
    key_name = models.CharField(max_length=200,blank=True,null=True)
    key_secret = models.TextField(blank=True,null=True)
    wallets = models.TextField(blank=True,null=True)
    receiver_name = models.CharField(blank=True,null=True,max_length=100)

    def __str__(self):
        return self.user.username

class SolanaLog(models.Model):
    user = models.ForeignKey(SolanaUser,on_delete=models.CASCADE)
    fee = models.CharField(max_length=10,blank=True,null=True)
    transaction_id = models.CharField(max_length=100, blank=True,null=True)
    destination_address = models.CharField(max_length=100,blank=True,null=True)
    when_created = models.DateTimeField(auto_created=True)
    amount = models.CharField(max_length=10,blank=True,null=True)
    ip = models.CharField(max_length=50,blank=True,null=True)
    currency = models.CharField(max_length=6,blank=True,null=True)