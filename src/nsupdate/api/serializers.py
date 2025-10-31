from nsupdate.main.models import Host
from rest_framework import serializers


class HostSerializer(serializers.HyperlinkedModelSerializer):
  class Meta:
    model = Host
    fields = [
      'name', 'comment', 'available', 'client_faults', 'server_faults', 'abuse_blocked', 'abuse',
      'last_update_ipv4', 'tls_update_ipv4', 'last_update_ipv6', 'tls_update_ipv6', 'wildcard'
    ]
