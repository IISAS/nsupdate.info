from rest_framework.permissions import BasePermission


class CreatedByUser(BasePermission):

    def has_object_permission(self, request, view, obj):
        return request.user.is_staff or hasattr(obj, 'created_by') and obj.created_by == request.user
