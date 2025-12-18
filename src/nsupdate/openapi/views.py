from django.db.models import F, Q, Value
from django.db.models.functions import Concat
from django.http import HttpResponse, Http404
from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import (
    extend_schema,
    OpenApiResponse,
    OpenApiExample,
    OpenApiParameter,
)
from rest_framework import generics, status, viewsets, mixins
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from rest_framework.response import Response

from nsupdate.main.models import (
    Domain,
    Host,
)
from .filters import DomainFilter, HostFilter
from .permissions import CreatedByUser
from .serializers import (
    DomainSerializer,
    HostSerializer,
    CSRTextUploadSerializer,
    CSRFileUploadSerializer, )
from ..utils.cert import issue_certificate


def raise_Http404(view: generics.GenericAPIView):
    raise Http404(
        "No %s matches the given query." % view.serializer_class.Meta.model._meta.object_name
    )


class DomainsViewSet(viewsets.ModelViewSet):
    http_method_names = ['get']

    serializer_class = DomainSerializer

    permission_classes = [
        IsAuthenticated,
        (CreatedByUser | IsAdminUser)
    ]

    filter_backends = [DjangoFilterBackend]
    filterset_class = DomainFilter

    search_fields = ['name']

    lookup_field = 'name'
    lookup_value_regex = '[^/]+'

    def get_queryset(self):
        if getattr(self, "swagger_fake_view", False):
            return Domain.objects.none()

        qs = (
            Domain.objects
            .filter(
                Q(public=True) |
                Q(public=False, created_by=self.request.user),
            )
        )

        qs = (
            qs
            .select_related('created_by')
            .annotate(owner=F('created_by__username'))
        )

        qs = self.filter_queryset(qs)

        return qs

    @extend_schema(
        summary="List all domains visible to the authenticated user.",
        description="Returns a paginated list of domains visible to the authenticated user. Supports filtering and ordering.",
        parameters=[
            OpenApiParameter(
                name="ordering",
                type=OpenApiTypes.STR,
                location=OpenApiParameter.QUERY,
                description="Order results by one of the allowed fields.",
                enum=['name', 'owner', 'created', 'last_update', '-name', '-owner', '-created', '-last_update'],
                required=False,
            ),
        ],
        responses={
            200: OpenApiResponse(
                response=DomainSerializer(many=True),
                description="List of domains filtered and ordered as requested.",
            ),
        },
        examples=[
            OpenApiExample(
                name="Example response",
                description=(
                    "Private domains are not public and belong to the authenticated user. "
                    "Public domains are visible to everyone."
                ),
                value=[
                    {
                        "url": "https://nsupdate.fedcloud.eu/api/domains/mydomain.com/",
                        "name": "mydomain.com",
                        "owner": "johndoe",
                        "public": False,
                        "available": True,
                        "comment": "My personal domain",
                        "created": "2025-12-11T10:30:05.212014+01:00",
                        "last_update": "2025-12-11T10:30:48.783250+01:00",
                    },
                    {
                        "url": "https://nsupdate.fedcloud.eu/api/domains/example.org/",
                        "name": "example.org",
                        "owner": "alice",
                        "public": True,
                        "available": True,
                        "comment": "Shared demo domain",
                        "created": "2017-10-16T08:24:12.410004+02:00",
                        "last_update": "2021-02-21T02:12:15.403230+01:00",
                    },
                ],
            ),
        ],
    )
    def list(self, request, *args, **kwargs):
        # queryset = self.get_queryset()
        # return Response(self.get_serializer(queryset, many=True).data)
        return super().list(request, *args, **kwargs)

    @extend_schema(summary="View domain details.")
    def retrieve(self, request, *args, **kwargs):
        return super().retrieve(request, *args, **kwargs)

    @extend_schema(exclude=True)
    def create(self, request, *args, **kwargs):
        return super().create(request, *args, **kwargs)

    @extend_schema(exclude=True)
    def update(self, request, *args, **kwargs):
        return super().update(request, *args, **kwargs)

    @extend_schema(exclude=True)
    def destroy(self, request, *args, **kwargs):
        return super().destroy(request, *args, **kwargs)

    @extend_schema(exclude=True)
    def partial_update(self, request, *args, **kwargs):
        return super().partial_update(request, *args, **kwargs)

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)


class HostsViewSet(
    mixins.ListModelMixin,
    mixins.RetrieveModelMixin,
    viewsets.GenericViewSet
):
    http_method_names = ['get', 'post']

    serializer_class = HostSerializer

    permission_classes = [
        IsAuthenticated,
        (CreatedByUser | IsAdminUser)
    ]

    filter_backends = [DjangoFilterBackend]
    filterset_class = HostFilter

    lookup_field = 'fqdn'
    # lookup_url_kwarg = 'fqdn'
    lookup_value_regex = '[^/]+'

    def get_object(self):
        fqdn = self.kwargs.get(self.lookup_url_kwarg or self.lookup_field)

        try:
            obj = self.get_queryset().get(fqdn=fqdn)
        except Host.DoesNotExist:
            raise_Http404(self)

        self.check_object_permissions(self.request, obj)
        return obj

    def get_queryset(self):
        if getattr(self, "swagger_fake_view", False):
            return Host.objects.none()

        qs = (
            Host.objects
            .filter(
                Q(created_by=self.request.user)
            )
        )

        qs = (
            qs
            .select_related(
                'created_by',
                'domain',
            )
            .annotate(owner=F('created_by__username'))
            .annotate(domain_name=F('domain__name'))
            .annotate(
                fqdn=Concat(
                    F('name'),
                    Value('.'),
                    F('domain__name')
                )
            )
        )

        qs = self.filter_queryset(qs)

        return qs

    @extend_schema(exclude=True)
    def create(self, request, *args, **kwargs):
        return Response(
            {"detail": "POST not allowed on this endpoint"},
            status=status.HTTP_405_METHOD_NOT_ALLOWED,
        )

    @extend_schema(
        summary="List all hosts owned by the authenticated user.",
        description="Returns a paginated list of hosts created by the authenticated user. Supports search, filtering and ordering.",
        responses={200: HostSerializer(many=True)},
        parameters=[
            OpenApiParameter(
                name="search",
                description="Search by hostname or domain name",
                location=OpenApiParameter.QUERY,
                type=OpenApiTypes.STR,
                required=False,
            ),
            OpenApiParameter(
                name="ordering",
                description="Order results by one of the allowed fields.",
                location=OpenApiParameter.QUERY,
                type=OpenApiTypes.STR,
                enum=['name', '-name', 'created', '-created'],
                required=False,
            ),
        ],
    )
    def list(self, request, *args, **kwargs):
        return super().list(request, *args, **kwargs)

    @extend_schema(
        summary="View host details.",
        parameters=[
            OpenApiParameter(
                name="fqdn",
                location=OpenApiParameter.PATH,
                description="The FQDN of the host.",
                required=True,
                type=str,
            ),
        ],
    )
    def retrieve(self, request, *args, **kwargs):
        return super().retrieve(request, *args, **kwargs)

    def _upload_csr_and_issue_cert(self, request, host):
        # --- CSR as file ---
        if "file" in request.FILES:
            serializer = CSRFileUploadSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            csr_pem = serializer.validated_data["file"].read().decode("utf-8")

        # --- CSR as text ---
        else:
            serializer = CSRTextUploadSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            csr_pem = serializer.validated_data["csr"]

        # Parse & validate CSR
        is_csr_valid, csr_validation_message = host.validate_csr(csr_pem=csr_pem)
        if not is_csr_valid:
            return False, Response(
                {"detail": csr_validation_message},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Issue a new certificate for the host
        result = issue_certificate(csr_pem)
        if result['status'] == 'OK':
            host.ssl_certificate = result['certs']['fullchain.pem']
            host.save(update_fields=['ssl_certificate'])
            return True, None

        return False, Response(
            {"detail": (msg for msg in result['messages'])},
            status=status.HTTP_400_BAD_REQUEST,
        )

    @extend_schema(
        methods=["get"],
        summary="Download SSL certificate",
        description="Downloads the stored SSL certificate for the given host identified by its FQDN.",
        parameters=[
            OpenApiParameter(
                name="fqdn",
                location=OpenApiParameter.PATH,
                description="Fully Qualified Domain Name of the host",
                required=True,
                type=OpenApiTypes.STR,
            ),
        ],
        responses={200: OpenApiTypes.BINARY},
    )
    @extend_schema(
        methods=["post"],
        summary="Upload CSR and issue a new SSL certificate",
        description="Uploads a CSR (text or file) and issues a new SSL certificate.",
        parameters=[
            OpenApiParameter(
                name="fqdn",
                location=OpenApiParameter.PATH,
                description="Fully Qualified Domain Name of the host",
                required=True,
                type=OpenApiTypes.STR,
            ),
        ],
        request={
            "application/json": CSRTextUploadSerializer,
            "multipart/form-data": CSRFileUploadSerializer,
        },
        responses={
            200: OpenApiTypes.BINARY,
            400: OpenApiTypes.STR,
            403: OpenApiTypes.STR,
            404: OpenApiTypes.STR,
        },
    )
    @action(
        detail=True,
        methods=["get", "post"],
        url_path="certificate",
    )
    def get_certificate(self, request, fqdn=None):
        """
        HTTP GET -> Download the certificate
        HTTP POST -> Upload CSR (file or text), issue certificate, and download the certificate
        """
        host = self.get_object()

        if request.method.lower() == "post":
            success, response = self._upload_csr_and_issue_cert(request, host)
            if not success:
                return response

        cert = host.ssl_certificate
        if not cert:
            return Response({"detail": "Certificate not available"}, status=404)

        # Convert string to bytes if needed
        if isinstance(cert, str):
            cert = cert.encode("utf-8")

        # Create response
        response = HttpResponse(cert, content_type="application/x-pem-file")
        filename = f"{host.get_fqdn()}.pem"
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        return response
