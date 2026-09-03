from django import forms

from .models import ProxyEndpoint


class ProxyEndpointForm(forms.ModelForm):
    class Meta:
        model = ProxyEndpoint
        fields = ["label", "scheme", "host", "port", "username", "password", "enabled"]
        widgets = {
            "host": forms.TextInput(attrs={"placeholder": "proxy.example.com or 203.0.113.5"}),
            "port": forms.NumberInput(attrs={"placeholder": "1080"}),
            "password": forms.PasswordInput(render_value=True),
        }
