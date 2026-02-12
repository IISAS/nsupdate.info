from django.db import models

from .queryset import DomainQuerySet, VirtualOrganizationQuerySet


class DomainManager(models.Manager):
    def get_queryset(self) -> DomainQuerySet:
        return DomainQuerySet(self.model, using=self._db)

    def visible_to(self, user):
        return self.get_queryset().visible_to(user)


class VirtualOrganizationManager(models.Manager):
    def get_queryset(self) -> VirtualOrganizationQuerySet:
        return VirtualOrganizationQuerySet(self.model, using=self._db)

    def visible_to(self, user):
        return self.get_queryset().visible_to(user)
