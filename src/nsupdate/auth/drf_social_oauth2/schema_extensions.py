from drf_spectacular.extensions import OpenApiAuthenticationExtension


class SocialOAuth2AuthenticationScheme(OpenApiAuthenticationExtension):
    priority = 0
    match_subclasses = True
    target_class = 'nsupdate.auth.drf_social_oauth2.authentication.SocialOAuth2Authentication'
    name = 'Access Token'

    def get_security_definition(self, auto_schema):
        return {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "OAuth2",
            "description": (
                "Use an OAuth2 access token to authenticate.\n\n"
                "Example: `Authorization: Bearer <token>`"
            ),
        }
