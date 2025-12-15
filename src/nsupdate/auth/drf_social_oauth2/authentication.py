from typing import Optional

import jwt
from rest_framework import authentication, exceptions
from social_core.backends.oauth import BaseOAuth2
from social_core.exceptions import AuthException, MissingBackend
from social_django.utils import load_strategy, load_backend

from nsupdate.settings.base import SOCIAL_AUTH_ISSUER_BACKEND_MAP


def get_token_issuer(token: str) -> Optional[str]:
    try:
        unverified = jwt.decode(token, options={"verify_signature": False})
        return unverified.get("iss")
    except Exception:
        return None


class SocialOAuth2Authentication(authentication.BaseAuthentication):
    """
    Authenticate users via OAuth2 access tokens (from Google, GitHub, etc.)
    using social_django / social_core.
    """

    www_authenticate_realm = 'api'

    def authenticate(self, request):
        auth = authentication.get_authorization_header(request).split()
        if not auth or auth[0].lower() != b'bearer':
            return None

        if len(auth) == 1:
            raise exceptions.AuthenticationFailed('Invalid token header. No credentials provided.')
        elif len(auth) > 2:
            raise exceptions.AuthenticationFailed('Invalid token header. Token string should not contain spaces.')

        strategy = load_strategy(request)
        try:
            token = auth[1].decode()
            issuer = get_token_issuer(token)
            if not issuer:
                raise exceptions.AuthenticationFailed('Could not resolve issuer of the token.')
            backend_name = SOCIAL_AUTH_ISSUER_BACKEND_MAP.get(issuer)
            if not backend_name:
                raise exceptions.AuthenticationFailed('Unsupported issuer: %s.' % issuer)
            backend = load_backend(strategy=strategy, name=backend_name, redirect_uri=None)
        except MissingBackend:
            raise exceptions.AuthenticationFailed('Invalid social backend')

        if not isinstance(backend, BaseOAuth2):
            raise exceptions.AuthenticationFailed('Backend does not support OAuth2 authentication')

        try:
            token = auth[1].decode()
            user = backend.do_auth(token)
        except AuthException:
            raise exceptions.AuthenticationFailed('Invalid social authentication token')

        if not user or not user.is_active:
            raise exceptions.AuthenticationFailed('User inactive or invalid')

        return (user, None)
