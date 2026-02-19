from django.db import models
from django.db.models import Q


class DomainQuerySet(models.QuerySet):
    def visible_to(self, user):
        """
        Return domains visible to the given user.
        """
        if user:
            if user.is_staff:
                # Staff can see all the domains
                return self.all()

            # Normal user: filtering by ownership, domain publicity and VO
            # show domain if:
            # 1) user is an owner of the domain
            # 2) domain is public and does not belong to any VO
            # 3) domain is public and is in the same VO as the user
            return self.filter(
                Q(created_by=user) |
                (
                    Q(public=True) & (
                        Q(vo__isnull=True) |
                        Q(vo__in=user.vos.all())
                    )
                )
            )
        return self.none()


class VirtualOrganizationQuerySet(models.QuerySet):
    def visible_to(self, user):
        if user:
            if user.is_staff:
                return self.all()
            return user.vos.all()
        return self.none()
