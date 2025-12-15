# -*- coding: utf-8 -*-
"""
form definitions (which fields are available, order, autofocus, ...)
"""
import base64
import binascii

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from django import forms
from django.utils.translation import gettext_lazy as _

from .models import Host, RelatedHost, Domain, ServiceUpdaterHostConfig
from .dnstools import check_domain, NameServerNotAvailable


class CreateHostForm(forms.ModelForm):
    class Meta(object):
        model = Host
        fields = ['name', 'domain', 'wildcard', 'comment']
        widgets = {
            'name': forms.widgets.TextInput(attrs=dict(autofocus=None)),
        }


class EditHostForm(forms.ModelForm):
    class Meta(object):
        model = Host
        fields = ['comment', 'available', 'abuse', 'netmask_ipv4', 'netmask_ipv6']

    netmask_ipv4 = forms.IntegerField(min_value=0, max_value=32)
    netmask_ipv6 = forms.IntegerField(min_value=0, max_value=64)


class CreateRelatedHostForm(forms.ModelForm):
    class Meta(object):
        model = RelatedHost
        fields = ['name', 'comment', 'available', 'interface_id_ipv4', 'interface_id_ipv6']
        widgets = {
            'name': forms.widgets.TextInput(attrs=dict(autofocus=None)),
        }


class EditRelatedHostForm(forms.ModelForm):
    class Meta(object):
        model = RelatedHost
        fields = ['name', 'comment', 'available', 'interface_id_ipv4', 'interface_id_ipv6']


class CreateDomainForm(forms.ModelForm):
    def clean_nameserver_update_secret(self):
        secret = self.cleaned_data['nameserver_update_secret']
        try:
            binascii.a2b_base64(secret.encode(encoding="ascii", errors="strict"))
        except (binascii.Error, UnicodeEncodeError):
            raise forms.ValidationError(_("Enter a valid secret in base64 format."), code='invalid')
        return secret

    class Meta(object):
        model = Domain
        fields = ['name', 'nameserver_ip', 'nameserver2_ip', 'nameserver_update_algorithm', 'comment']
        widgets = {
            'name': forms.widgets.TextInput(attrs=dict(autofocus=None)),
        }


class EditDomainForm(forms.ModelForm):
    def clean_nameserver_update_secret(self):
        secret = self.cleaned_data['nameserver_update_secret']
        try:
            binascii.a2b_base64(secret.encode(encoding="ascii", errors="strict"))
        except (binascii.Error, UnicodeEncodeError):
            raise forms.ValidationError(_("Enter a valid secret in base64 format."), code='invalid')
        return secret

    def clean(self):
        cleaned_data = super(EditDomainForm, self).clean()

        if self.cleaned_data['available'] and 'nameserver_ip' in cleaned_data:
            try:
                check_domain(self.instance.name, cleaned_data['nameserver_ip'])

            except (NameServerNotAvailable,):
                raise forms.ValidationError(
                    _("Failed to add/delete host connectivity-test.%(domain)s, check your DNS server configuration. "
                      "This is a requirement for setting the available flag."),
                    code='invalid',
                    params={'domain': self.instance.name}
                )

        if cleaned_data['public'] and not cleaned_data['available']:
            raise forms.ValidationError(
                _("Domain must be available to be public"),
                code='invalid')

    class Meta(object):
        model = Domain
        fields = ['comment', 'nameserver_ip', 'nameserver2_ip', 'public', 'available',
                  'nameserver_update_algorithm', 'nameserver_update_secret']


class CreateUpdaterHostConfigForm(forms.ModelForm):
    class Meta(object):
        model = ServiceUpdaterHostConfig
        fields = ['service', 'hostname', 'name', 'password',
                  'give_ipv4', 'give_ipv6', 'comment']
        widgets = {
            'hostname': forms.widgets.TextInput(attrs=dict(autofocus=None)),
        }


class EditUpdaterHostConfigForm(forms.ModelForm):
    class Meta(object):
        model = ServiceUpdaterHostConfig
        fields = ['hostname', 'comment', 'name', 'password',
                  'give_ipv4', 'give_ipv6']


class HostCsrUploadForm(forms.ModelForm):
    error_messages = {
        "missing_csr_file": _("CSR file is required."),
        "invalid_content_type": _("The content of the uploaded file is not application/pkcs10."),
        "empty_csr_file": _("The uploaded CSR file is empty."),
        "invalid_base64_data": _("CSR is not valid Base64 data."),
        "invalid_csr_format": _("Invalid CSR format (expected DER or PEM)."),
        "csr_public_key_verification_error": _("CSR public key verification failed."),
    }

    csr_file = forms.FileField(
        label=_("CSR file"),
        help_text=_("Upload the Certificate Sign Request (CSR) file."),
    )

    class Meta(object):
        model = Host
        fields = []

    def clean(self):
        cleaned = super().clean()

        file = cleaned.get('csr_file')

        if not file:
            code = 'missing_csr_file'
            raise forms.ValidationError(
                self.error_messages[code],
                code=code,
            )

        # TODO: problems with CSR generated on Windows machine
        # # content type validation
        # if file.content_type.lower() != 'application/pkcs10':
        #     raise forms.ValidationError(
        #         self.error_messages["invalid_content_type"],
        #         code="invalid_content_type",
        #     )

        # read the content of the uploaded file
        try:
            file_content = file.read().decode('utf-8')
        except UnicodeDecodeError:
            file_content = file.read().decode('ascii')

        # content validation
        if not file_content.strip():
            code = "empty_csr_file"
            raise forms.ValidationError(
                self.error_messages[code],
                code=code,
            )

        if 'BEGIN CERTIFICATE REQUEST' in file_content:
            lines = file_content.strip().splitlines()
            # Filter out header/footer lines
            b64_lines = [
                line for line in lines
                if not line.startswith("-----BEGIN")
                   and not line.startswith("-----END")
                   and line.strip() != ""
            ]
            file_content_b64 = ''.join(b64_lines)
        else:
            file_content_b64 = file_content

        # decode from base64
        try:
            csr_der = base64.b64decode(file_content_b64)
        except Exception:
            code = "invalid_base64_data"
            raise forms.ValidationError(
                self.error_messages[code],
                code=code,
            )

        # try DER
        try:
            csr = x509.load_der_x509_csr(csr_der)
        except Exception:
            # try PEM
            try:
                csr_pem = csr_der.decode("utf-8")
                csr = x509.load_pem_x509_csr(csr_pem.encode("utf-8"))
            except Exception:
                code = "invalid_csr_format"
                raise forms.ValidationError(
                    self.error_messages[code],
                    code=code,
                )

        # Validate CSR signature
        try:
            csr.public_key().verify(
                csr.signature,
                csr.tbs_certrequest_bytes,
                padding.PKCS1v15(),
                csr.signature_hash_algorithm,
            )
        except Exception as e:
            code = "csr_public_key_verification_error"
            raise forms.ValidationError(
                self.error_messages[code],
                code=code,
            )

        # Store content for save() method
        cleaned['csr'] = file_content
        return cleaned
