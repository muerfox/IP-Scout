from django import forms

from .models import CountryNetwork


class CountryNetworkForm(forms.ModelForm):
    class Meta:
        model = CountryNetwork
        fields = ["country_code", "cidr", "network", "enabled"]
        widgets = {
            "country_code": forms.TextInput(attrs={"maxlength": 2, "placeholder": "IR"}),
            "cidr": forms.TextInput(attrs={"placeholder": "5.1.0.0/22"}),
        }

    def clean_country_code(self):
        return self.cleaned_data["country_code"].strip().upper()
