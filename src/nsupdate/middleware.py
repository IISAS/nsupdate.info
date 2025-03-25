from django.contrib.auth import get_backends
from social_core.backends.oauth import BaseOAuth2
from social_django.models import UserSocialAuth

from nsupdate.api.views import Response


def bearer_challenge(realm, content='Authorization Required'):
    """
    Construct a 401 response requesting http bearer auth.

    :param realm: realm string (displayed by the browser)
    :param content: request body content
    :return: HttpResponse object
    """
    response = Response(content)
    response['WWW-Authenticate'] = 'Bearer realm="%s"' % (realm, )
    response.status_code = 401
    return response


class BearerTokenMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Attempt to extract and validate Bearer token from the Authorization header.
        auth_header = request.META.get('HTTP_AUTHORIZATION')
        if auth_header and auth_header.lower().startswith('bearer '):
            access_token = auth_header.split(' ')[1]
            if not access_token or access_token == '':
                bearer_challenge("authenticate to update DNS", 'badauth')
            is_authenticated = False
            for backend in get_backends():
                if isinstance(backend, BaseOAuth2):
                    try:
                        user_data = backend.user_data(access_token)
                        social_auth = UserSocialAuth.objects.get(
                            provider=backend.name,
                            uid=user_data.get(backend.ID_KEY)
                        )
                        user = social_auth.user
                        request.user = user
                        is_authenticated = user.is_authenticated
                        break
                    except Exception as e:
                        pass
            if not is_authenticated:
                return bearer_challenge("authenticate to update DNS", 'badauth')
        # Proceed with the request processing.
        response = self.get_response(request)
        return response
