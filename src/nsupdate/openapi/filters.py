import django_filters
from django.db.models import Q
from django_filters import OrderingFilter

from nsupdate.main.models import Domain, Host


class DomainFilter(django_filters.FilterSet):
    visibility = django_filters.ChoiceFilter(
        choices=[
            ('public', 'public'),
            ('private', 'private')
        ],
        method="filter_visibility",
        label="Filter domains by their visibility.",
    )

    ordering = OrderingFilter(
        fields=(
            ('name', 'name'),
            ('created_by__username', 'owner'),
            ('created', 'created'),
            ('last_update', 'last_update')
        ),
        field_labels={
            'name': 'name',
            'owner': 'owner',
            'created': 'created',
            'last_update': 'last update',
        },
        field_name='name'
    )

    search = django_filters.CharFilter(
        method='filter_search',
        label='Search domains by name'
    )

    class Meta:
        model = Domain
        fields = []

    def filter_visibility(self, queryset, name, value):
        if value == "public":
            return queryset.filter(public=True)
        if value == "private":
            return queryset.filter(public=False)
        return queryset

    def filter_search(self, queryset, name, value):
        if value:
            return queryset.filter(
                Q(name__icontains=value)
            )
        return queryset


class HostFilter(django_filters.FilterSet):

    ordering = OrderingFilter(
        fields=(
            ('name', 'name'),
            ('domain__name', 'domain__name'),
            ('created', 'created'),
            ('last_update', 'last_update')
        ),
        field_labels={
            'name': 'name',
            'domain__name': 'domain',
            'created': 'created',
            'last_update': 'last update',
        },
        field_name='name'
    )

    search = django_filters.CharFilter(
        method='filter_search',
        label='Search host by FQDN'
    )

    class Meta:
        model = Host
        fields = []

    def filter_search(self, queryset, name, value):
        if value:
            return queryset.filter(
                Q(name__icontains=value) |
                Q(domain__name__icontains=value)
            )
        return queryset
