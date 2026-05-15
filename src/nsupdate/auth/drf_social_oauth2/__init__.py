import logging

from django.apps import AppConfig

logger = logging.getLogger(__name__)


class SocialOauth2AppConfig(AppConfig):
    name = "nsupdate.auth.drf_social_oauth2"
    verbose_name = "Social OAuth2 Authentication for Django REST Framework"

    dependencies = ['social_django', 'rest_framework', 'social_core']

    def ready(self):
        try:
            from . import authentication
            logger.info(f'Loaded authentication for {self.name}')
        except Exception as e:
            logger.warning(f'{self.name} failed to load authentication: {e}')
        try:
            from . import schema_extensions
            logger.info(f'Loaded schema_extensions for {self.name}')
        except Exception as e:
            logger.warning(f'{self.name} failed to load schema_extensions: {e}')
