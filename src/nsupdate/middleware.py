from django.contrib.auth import get_backends
from django.http import HttpResponse, JsonResponse
from social_core.backends.oauth import BaseOAuth2
from social_django.models import UserSocialAuth


def unsupported_media_type():
  return HttpResponse(
    "Unsupported Media Type",
    status=415,
    content_type="text/plain"
  )


class BearerTokenMiddleware:
  def __init__(self, get_response):
    self.get_response = get_response
  
  def __call__(self, request):
    # Attempt to extract and validate Bearer token from the Authorization header.
    auth_header = request.META.get('HTTP_AUTHORIZATION')
    if auth_header and auth_header.lower().startswith('bearer '):
      access_token = auth_header.split(' ')[1]
      if not access_token or access_token == '':
        msg = 'Invalid access token'
        status = 401
        return JsonResponse({'error': msg}, status=status)
      for backend in get_backends():
        if isinstance(backend, BaseOAuth2):
          try:
            user_data = backend.user_data(access_token)
          except Exception as e:
            msg = 'Unauthorized access'
            status = 401
            return JsonResponse({'error': msg}, status=status)
          try:
            social_auth = UserSocialAuth.objects.get(provider=backend.name, uid=user_data.get(backend.ID_KEY))
            user = social_auth.user
            request.user = user
            break
          except UserSocialAuth.DoesNotExist:
            msg = 'User not found'
            status = 401
            return JsonResponse({'error': msg}, status=status)
    # Proceed with the request processing.
    response = self.get_response(request)
    return response
