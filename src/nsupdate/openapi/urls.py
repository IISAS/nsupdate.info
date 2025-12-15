from django.urls import path
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularRedocView,
    SpectacularSwaggerView,
)
from rest_framework.routers import DefaultRouter

from .views import (
    DomainsViewSet,
    HostsViewSet,
)

router = DefaultRouter()
router.register(r'domains', DomainsViewSet, basename='domain')
router.register(r'hosts', HostsViewSet, basename='host')

urlpatterns = (
    # OpenAPI
    *router.urls,
    # OpenAPI schema endpoint
    path("schema/", SpectacularAPIView.as_view(), name="schema"),
    # Swagger UI
    path("docs/", SpectacularSwaggerView.as_view(url_name="schema"), name="swagger-ui"),
    # Redoc UI
    path("redoc/", SpectacularRedocView.as_view(url_name="schema"), name="redoc"),
)
