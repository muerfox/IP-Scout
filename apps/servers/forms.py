from django import forms

from .models import Server


class ServerForm(forms.ModelForm):
    ssh_private_key = forms.CharField(
        required=False,
        widget=forms.Textarea(
            attrs={"rows": 6, "placeholder": "Leave blank to keep the existing credential"}
        ),
        help_text="SSH private key (PEM) or password, depending on auth type below. Stored encrypted.",
    )
    log_search_paths_text = forms.CharField(
        required=False,
        label="Extra log search paths",
        help_text="One directory per line, in addition to /var/log/nginx/ which is always scanned.",
        widget=forms.Textarea(attrs={"rows": 3, "placeholder": "/var/log/nginx-custom/"}),
    )

    class Meta:
        model = Server
        fields = ["name", "hostname", "ip_address", "ssh_port", "ssh_username", "ssh_auth_type", "enabled"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance.pk:
            self.fields["log_search_paths_text"].initial = "\n".join(self.instance.log_search_paths)
        if not self.instance.pk:
            self.fields["ssh_private_key"].widget.attrs["placeholder"] = "Paste the private key or password"

    def clean_log_search_paths_text(self):
        raw = self.cleaned_data.get("log_search_paths_text", "")
        return [line.strip() for line in raw.splitlines() if line.strip()]

    def clean(self):
        cleaned = super().clean()
        if not self.instance.pk and not cleaned.get("ssh_private_key"):
            self.add_error("ssh_private_key", "Required when adding a new server.")
        return cleaned

    def save(self, commit: bool = True) -> Server:
        instance = super().save(commit=False)
        instance.log_search_paths = self.cleaned_data.get("log_search_paths_text", [])
        key = self.cleaned_data.get("ssh_private_key")
        if key:
            instance.ssh_private_key = key
        if commit:
            instance.save()
        return instance
