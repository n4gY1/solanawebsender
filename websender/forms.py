from django.forms import models

from websender.models import SolanaUser


class SolanaUserForm(models.ModelForm):
    class Meta:
        model = SolanaUser
        fields = ["key_name","key_secret","wallets","receiver_name"]

    def __init__(self, *args, **kwargs):
        super(SolanaUserForm, self).__init__(*args, **kwargs)
        for field_name, field in self.fields.items():
            field.widget.attrs['class'] = '_textarea form-control'