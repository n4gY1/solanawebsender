from django.db import models

# Create your models here.
class SolanaLog(models.Model):
    fee = models.CharField(max_length=10,blank=True,null=True)
    transaction_id = models.CharField(max_length=100, blank=True,null=True)
    destination_address = models.CharField(max_length=100,blank=True,null=True)
    when_created = models.DateTimeField(auto_created=True)
    amount = models.CharField(max_length=10,blank=True,null=True)
    ip = models.CharField(max_length=50,blank=True,null=True)
    currency = models.CharField(max_length=6,blank=True,null=True)

