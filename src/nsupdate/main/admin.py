"""
register our models for Django's admin
"""

from django.contrib import admin
from django.urls import reverse
from django.utils.safestring import mark_safe

from .models import Host, RelatedHost, Domain, BlacklistedHost, ServiceUpdater, ServiceUpdaterHostConfig


@admin.register(Domain)
class DomainAdmin(admin.ModelAdmin):
    list_display = ("name", "public", "available", "certificates_enabled", "created_by")
    list_filter = ("created", "public", "available", "certificates_enabled")
    search_fields = ("name", "created_by__username", "created_by__email")


@admin.register(Host)
class HostAdmin(admin.ModelAdmin):
    list_display = ("name", "domain", "created_by_link", "client_faults", "api_auth_faults", "abuse", "abuse_blocked",
                    "certificates_requested", "certificates_approved")
    list_filter = ("created", "abuse", "abuse_blocked", "certificates_requested", "certificates_approved", "domain")
    read_only_fields = ('created_by_link',)
    actions = ('approve_certificates', 'revoke_certificates')

    search_fields = ("name", "created_by__username", "created_by__email")

    def created_by_link(self, obj):
        return mark_safe('<a href="{}">{}</a>'.format(
            reverse("admin:auth_user_change", args=(obj.created_by.pk,)),
            obj.created_by.username
        ))
    created_by_link.short_description = 'created by'

    @admin.action(description='Approve certificates for selected hosts')
    def approve_certificates(self, request, queryset):
        queryset.update(certificates_requested=True, certificates_approved=True)

    @admin.action(description='Revoke certificate approval for selected hosts')
    def revoke_certificates(self, request, queryset):
        queryset.update(certificates_approved=False)


@admin.register(RelatedHost)
class RelatedHostAdmin(admin.ModelAdmin):
    list_display = ("name", "main_host", "available", "comment")
    search_fields = ("name", "main_host__created_by__username", "main_host__created_by__email")


@admin.register(BlacklistedHost)
class BlacklistedHostAdmin(admin.ModelAdmin):
    list_display = ("name_re", "created_by")
    list_filter = ("created", )


@admin.register(ServiceUpdater)
class ServiceUpdaterAdmin(admin.ModelAdmin):
    list_display = ("name", "comment", "created_by")
    list_filter = ("created", )


@admin.register(ServiceUpdaterHostConfig)
class ServiceUpdaterHostConfigAdmin(admin.ModelAdmin):
    list_display = ("host", "service", "hostname", "comment", "created_by")
    list_filter = ("created", )
