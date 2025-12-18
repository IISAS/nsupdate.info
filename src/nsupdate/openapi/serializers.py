from rest_framework import serializers

from nsupdate.main.forms import CreateDomainForm
from nsupdate.main.models import Host, Domain


class DomainSerializer(serializers.HyperlinkedModelSerializer):
    owner = serializers.CharField(source='created_by.username', read_only=True)

    class Meta:
        model = Domain
        fields = [
            'url',
            'name',
            'owner',
            'public',
            'available',
            'comment',
            'created',
            'last_update',
        ]
        extra_kwargs = {
            'url': {
                'view_name': 'domain-detail',
                'lookup_field': 'name'
            }
        }


class DomainOwnerSerializer(DomainSerializer):
    class Meta(DomainSerializer.Meta):
        fields = DomainSerializer.Meta.fields + [
            'nameserver_update_secret'
        ]


class DomainCreateSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = Domain
        fields = CreateDomainForm.Meta.fields


class HostSerializer(serializers.HyperlinkedModelSerializer):
    domain_name = serializers.CharField(source='domain.name', read_only=True)
    fqdn = serializers.CharField(read_only=True)

    class Meta:
        model = Host
        fields = [
            'url',
            'fqdn',
            'name',
            'domain_name',
            'wildcard',
            'comment',
            'available',
            'client_faults',
            'server_faults',
            'abuse_blocked',
            'abuse',
            'created',
            'last_update_ipv4',
            'tls_update_ipv4',
            'last_update_ipv6',
            'tls_update_ipv6',
        ]
        extra_kwargs = {
            'url': {
                'view_name': 'host-detail',
                'lookup_field': 'fqdn',
            }
        }


class CSRTextUploadSerializer(serializers.Serializer):
    csr = serializers.CharField(
        help_text="PEM-encoded Certificate Signing Request (CSR)",
        style={"base_template": "textarea.html"},
    )


class CSRFileUploadSerializer(serializers.Serializer):
    file = serializers.FileField(
        help_text="Upload a PEM-encoded CSR file"
    )
