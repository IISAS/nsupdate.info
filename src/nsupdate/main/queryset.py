from django.db import models
from django.db.models import Q


class DomainQuerySet(models.QuerySet):
    def visible_to(self, user):
        """
        Return domains visible to the given user.
        """
        if user.is_staff:
            # Staff can see everything
            return self.all()

        # Normal user: VO filtering + public/created_by
        return self.filter(
            (
                Q(vo__isnull=True) &
                (
                    Q(created_by=user) |
                    Q(public=True)
                )
            ) |
            Q(vo__in=user.vos.all())
        )


class VirtualOrganizationQuerySet(models.QuerySet):
    def visible_to(self, user):
        if user.is_staff:
            return self.all()
        return user.vos.all()
