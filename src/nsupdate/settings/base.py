"""
Django settings for nsupdate project

Note: do not directly use these settings, rather use "dev" or "prod".
"""

# Note: django internally first loads its own defaults and then loads the
# project's settings on top of that. Due to this, no import * is required here.

import os

# To make this work, put a unique, long, random, secret string into your environment.
# E.g. in ~/.bashrc: export SECRET_KEY="..."
try:
    SECRET_KEY = os.environ['SECRET_KEY']
except KeyError:
    # if there is no SECRET_KEY in the environment, it will be just undefined and
    # Django will refuse running - except if you define it somehow else later (e.g. in
    # a local_settings.py file that imports this file).
    pass

# service contact for showing on the "about" page:
SERVICE_CONTACT = 'your_email AT example DOT com'

# sender address for e.g. user activation emails
DEFAULT_FROM_EMAIL = "your_email@example.com"

# admins will get traceback emails
ADMINS = (
    # ('Your Name', 'your_email@example.com'),
)
MANAGERS = ADMINS

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',  # Add 'postgresql_psycopg2', 'mysql', 'sqlite3' or 'oracle'.
        'NAME': 'nsupdate.sqlite',               # Or path to database file if using sqlite3.
        # The following settings are not used with sqlite3:
        'USER': '',
        'PASSWORD': '',
        'HOST': '',             # Empty for localhost through domain sockets or '127.0.0.1' for localhost through TCP.
        'PORT': ''              # Set to empty string for default.
    }
}

DEFAULT_AUTO_FIELD = 'django.db.models.AutoField'  # == 32bit integer

# these useragents are unacceptable for /nic/update service
BAD_AGENTS = set([])  # list can have str elements

# these IPAdresses and/or IPNetworks are unacceptable for /nic/update service
# like e.g. IPs of servers related to illegal activities
from netaddr import IPSet

BAD_IPS_HOST = IPSet([])  # inner list can have IPAddress and IPNetwork elements

# when encountering these hostnames (fqdn), block them early/silently from
# api usage. avoid any database access, so if someone tries to update
# every 5s, the database won't be locked all the time and we can at least
# delete the host from django admin.
BAD_HOSTS = set([])

# nameservers used e.g. for MX lookups in the registration email validation.
# google / cloudflare DNS IPs are only given as example / fallback -
# please configure your own nameservers in your local settings file.
NAMESERVERS = ['8.8.8.8', '1.1.1.1', ]

# registration email validation: disallow specific email patterns,
# e.g. domains that have a non-working mx / that are frequently abused.
# we use a multiline string here with one regex per line (used with re.search).
# the patterns given below are just examples, please configure your own
# regexes in your local settings file.
EMAIL_BLACKLIST = r"""
foobar@example\.org$
mailcatch\.com$
mailspam\.xyz$
"""

# Local time zone for this installation. Choices can be found here:
# http://en.wikipedia.org/wiki/List_of_tz_zones_by_name
# although not all choices may be available on all operating systems.
# In a Windows environment this must be set to your system time zone.
TIME_ZONE = 'Europe/Berlin'

# Language code for this installation. All choices can be found here:
# http://www.i18nguy.com/unicode/language-identifiers.html
LANGUAGE_CODE = 'en-us'

SITE_ID = 1

# If you set this to False, Django will make some optimizations so as not
# to load the internationalization machinery.
USE_I18N = True

# If you set this to False, Django will not use timezone-aware datetimes.
USE_TZ = True

# Absolute filesystem path to the directory that will hold user-uploaded files.
# Example: "/var/www/example.com/media/"
MEDIA_ROOT = ''

# URL that handles the media served from MEDIA_ROOT. Make sure to use a
# trailing slash.
# Examples: "http://example.com/media/", "http://media.example.com/"
MEDIA_URL = ''

# URL prefix for static files.
# Example: "http://example.com/static/", "http://static.example.com/"
STATIC_URL = '/static/'

# Absolute path to the directory static files should be collected to.
# Don't put anything in this directory yourself; store your static files
# in apps' "static/" subdirectories and in STATICFILES_DIRS.
# Example: "/var/www/example.com/static/"
# STATIC_ROOT = "/srv/nsupdate.info/htdocs/static"

# Additional locations of static files
STATICFILES_DIRS = (
    # Put strings here, like "/home/html/static" or "C:/www/django/static".
    # Always use forward slashes, even on Windows.
    # Don't forget to use absolute paths, not relative paths.
)

# List of finder classes that know how to find static files in
# various locations.
STATICFILES_FINDERS = (
    'django.contrib.staticfiles.finders.FileSystemFinder',
    'django.contrib.staticfiles.finders.AppDirectoriesFinder',
    # 'django.contrib.staticfiles.finders.DefaultStorageFinder',
)

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [
            # '/where/you/have/additional/templates',
            os.path.abspath(
                os.path.join(os.path.dirname(__file__), "..", "templates")
            )
        ],
        'OPTIONS': {
            'context_processors': [
                # Insert your TEMPLATE_CONTEXT_PROCESSORS here or use this
                # list if you haven't customized them:
                # 'django.contrib.auth.context_processors.auth',
                # 'django.template.context_processors.debug',
                'django.template.context_processors.i18n',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'social_django.context_processors.backends',
                'social_django.context_processors.login_redirect',
                'nsupdate.context_processors.add_settings',
                'nsupdate.context_processors.update_ips',
                # 'django.template.context_processors.media',
                # 'django.template.context_processors.static',
                # 'django.template.context_processors.tz',
                'django.contrib.messages.context_processors.messages',

            ],
            'loaders': [
                'django.template.loaders.filesystem.Loader',
                'django.template.loaders.app_directories.Loader',
            ],
        },
    },
]

MIDDLEWARE = (
    'django.middleware.common.CommonMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.locale.LocaleMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django_referrer_policy.middleware.ReferrerPolicyMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'social_django.middleware.SocialAuthExceptionMiddleware',
    'nsupdate.middleware.BearerTokenMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'django.middleware.security.SecurityMiddleware',
)

ROOT_URLCONF = 'nsupdate.urls'

# Python dotted path to the WSGI application used by Django's runserver.
WSGI_APPLICATION = 'nsupdate.wsgi.application'

INSTALLED_APPS = (
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.sites',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.humanize',
    'social_django',
    'nsupdate.login',
    'nsupdate',
    'nsupdate.accounts',
    'nsupdate.api',
    'nsupdate.main',
    'bootstrapform',
    'django.contrib.admin',
    'registration',
    'django_extensions',
    'django_filters',
    'rest_framework',
    'drf_spectacular',
    'drf_spectacular_sidecar',
    'nsupdate.auth.drf_social_oauth2.SocialOauth2AppConfig',
)

# A sample logging configuration.
# Sends an email to the site admins on every HTTP 500 error when DEBUG=False.
# Do some stderr logging for some views.
# See http://docs.djangoproject.com/en/dev/topics/logging for
# more details on how to customize your logging configuration.
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'filters': {
        'require_debug_false': {
            '()': 'django.utils.log.RequireDebugFalse'
        }
    },
    'handlers': {
        'mail_admins': {
            'level': 'ERROR',
            'filters': ['require_debug_false'],
            'class': 'django.utils.log.AdminEmailHandler'
        },
        'stderr': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'stderr'
        },
        'stderr_request': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'stderr_request'
        }
    },
    'loggers': {
        'nsupdate.api.views': {
            'handlers': ['stderr_request', ],
            'level': 'DEBUG',
            'propagate': True,
        },
        'nsupdate.main.views': {
            'handlers': ['stderr_request', ],
            'level': 'DEBUG',
            'propagate': True,
        },
        'nsupdate.main.dnstools': {
            'handlers': ['stderr', ],
            'level': 'DEBUG',
            'propagate': True,
        },
        # this is the toplevel handler for all request processing:
        'django.request': {
            'handlers': ['mail_admins', 'stderr'],
            'level': 'ERROR',
            'propagate': True,
        },
    },
    'formatters': {
        'stderr': {
            'format': '[%(asctime)s] %(levelname)s %(message)s',
        },
        'stderr_request': {
            'format': '[%(asctime)s] %(levelname)s %(message)s '
                      '[ip: %(request.META.REMOTE_ADDR)s, ua: "%(request.META.HTTP_USER_AGENT)s"]',
        },
    },
}

SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

ACCOUNT_ACTIVATION_DAYS = 7
REGISTRATION_EMAIL_HTML = False  # we override the text, but not the html email template
REGISTRATION_FORM = 'nsupdate.accounts.registration_form.RegistrationFormValidateEmail'

LOGIN_REDIRECT_URL = '/overview/'
LOGOUT_REDIRECT_URL = '/'

X_FRAME_OPTIONS = 'DENY'  # for clickjacking middleware
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
REFERRER_POLICY = 'same-origin'

CSRF_FAILURE_VIEW = 'nsupdate.main.views.csrf_failure_view'

# Settings for CSRF cookie.
CSRF_COOKIE_NAME = 'csrftoken'
CSRF_COOKIE_PATH = '/'
CSRF_COOKIE_HTTPONLY = True

# Settings for session cookie.
SESSION_COOKIE_NAME = 'sessionid'
SESSION_COOKIE_PATH = '/'
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_AGE = 10 * 60 * 60  # 10 hours, in seconds (remember_me is True), see #381
SESSION_EXPIRE_AT_BROWSER_CLOSE = True  # more safe (remember_me is False)

# Allow SHA1 for host update secrets
PASSWORD_HASHERS = [
    'django.contrib.auth.hashers.PBKDF2PasswordHasher',
    'django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher',
    'django.contrib.auth.hashers.Argon2PasswordHasher',
    'django.contrib.auth.hashers.BCryptSHA256PasswordHasher',
    'django.contrib.auth.hashers.BCryptPasswordHasher',
    'django.contrib.auth.hashers.SHA1PasswordHasher',
]

# python-social-auth settings
AUTHENTICATION_BACKENDS = (
    'social_core.backends.amazon.AmazonOAuth2',
    'social_core.backends.bitbucket.BitbucketOAuth2',
    'social_core.backends.disqus.DisqusOAuth2',
    'social_core.backends.dropbox.DropboxOAuth2V2',
    'social_core.backends.github.GithubOAuth2',
    'social_core.backends.google.GoogleOAuth2',
    'social_core.backends.reddit.RedditOAuth2',
    'social_core.backends.soundcloud.SoundcloudOAuth2',
    'social_core.backends.stackoverflow.StackoverflowOAuth2',
    'social_core.backends.twitter.TwitterOAuth',
    'django.contrib.auth.backends.ModelBackend',
)

SOCIAL_AUTH_ISSUER_BACKEND_MAP = {
    'https://aai.egi.eu/oidc': 'egi',
    'https://aai-dev.egi.eu/auth/realms/egi': 'egi',
}

SOCIAL_AUTH_LOGIN_REDIRECT_URL = '/'
#    Used to redirect the user once the auth process ended successfully.
#    The value of ?next=/foo is used if it was present

SOCIAL_AUTH_LOGIN_ERROR_URL = '/accounts/login/'
#    URL where the user will be redirected in case of an error

SOCIAL_AUTH_LOGIN_URL = '/accounts/login/'
#    Is used as a fallback for LOGIN_ERROR_URL (if it is not defined).

# SOCIAL_AUTH_NEW_USER_REDIRECT_URL = '/new-users-redirect-url/'
#    Used to redirect new registered users, will be used in place of SOCIAL_AUTH_LOGIN_REDIRECT_URL if defined.

SOCIAL_AUTH_NEW_ASSOCIATION_REDIRECT_URL = '/account/profile/'
#    Like SOCIAL_AUTH_NEW_USER_REDIRECT_URL but for new associated accounts (user is already logged in).
#    Used in place of SOCIAL_AUTH_LOGIN_REDIRECT_URL.

SOCIAL_AUTH_DISCONNECT_REDIRECT_URL = '/account/profile'
#    The user will be redirected to this URL when a social account is disconnected

SOCIAL_AUTH_INACTIVE_USER_URL = '/'
#    Inactive users can be redirected to this URL when trying to authenticate.

# SOCIAL_AUTH_USER_MODEL = 'foo.bar.User'
#    User model must have a username and email field, these are required.
#    Also an is_authenticated and is_active boolean flags are recommended, these can be methods if necessary (must
#    return True or False). If the model lacks them a True value is assumed.

# SOCIAL_AUTH_UID_LENGTH = <int>
#    Used to define the max length of the field uid. A value of 223 should work when using MySQL InnoDB which impose
#    a 767 bytes limit (assuming UTF-8 encoding).

# SOCIAL_AUTH_NONCE_SERVER_URL_LENGTH = <int>
#    Nonce model has a unique constraint over ('server_url', 'timestamp', 'salt'), salt has a max length of 40, so
#    server_url length must be tweaked using this setting.

# SOCIAL_AUTH_ASSOCIATION_SERVER_URL_LENGTH = <int> or SOCIAL_AUTH_ASSOCIATION_HANDLE_LENGTH = <int>
#    Association model has a unique constraint over ('server_url', 'handle'), both fields lengths can be tweaked by
#    these settings.

SOCIAL_AUTH_DEFAULT_USERNAME = 'user'
#    Default value to use as username, can be a callable. An UUID will be appended in case of duplicate entries.

SOCIAL_AUTH_UUID_LENGTH = 16
#    This controls the length of the UUID appended to usernames.

SOCIAL_AUTH_USERNAME_IS_FULL_EMAIL = True
#    If you want to use the full email address as the username, define this setting.

# SOCIAL_AUTH_SLUGIFY_USERNAMES = False
#    For those that prefer slugged usernames, the get_username pipeline can apply a slug transformation (code borrowed
#    from Django project) by defining this setting to True. The feature is disabled by default to to not force this
#    option to all projects.

# SOCIAL_AUTH_CLEAN_USERNAMES = True
#    By default the regex r'[^\w.@+-_]+' is applied over usernames to clean them from usual undesired characters like
#    spaces. Set this setting to False to disable this behavior.

# SOCIAL_AUTH_SANITIZE_REDIRECTS = False
#    The auth process finishes with a redirect, by default it's done to the value of SOCIAL_AUTH_LOGIN_REDIRECT_URL
#    but can be overridden with next GET argument. If this settings is True, this application will verify the domain of
#    the final URL and only redirect to it if it's on the same domain.

# SOCIAL_AUTH_REDIRECT_IS_HTTPS = False
#    On projects behind a reverse proxy that uses HTTPS, the redirect URIs can became with the wrong schema
#    (http:// instead of https://) when the request lacks some headers, and might cause errors with the auth process,
#    to force HTTPS in the final URIs set this setting to True

# SOCIAL_AUTH_URLOPEN_TIMEOUT = 30
#    Any urllib2.urlopen call will be performed with the default timeout value, to change it without affecting the
#    global socket timeout define this setting (the value specifies timeout seconds).
#    urllib2.urlopen uses socket.getdefaulttimeout() value by default, so setting socket.setdefaulttimeout(...) will
#    affect urlopen when this setting is not defined, otherwise this setting takes precedence. Also this might affect
#    other places in Django.
#    timeout argument was introduced in python 2.6 according to urllib2 documentation

# SOCIAL_AUTH_<BACKEND_NAME>_WHITELISTED_DOMAINS = ['foo.com', 'bar.com']
#    Supply a list of domain names to be white-listed. Any user with an email address on any of the allowed domains will
#    login successfully, otherwise AuthForbidden is raised.

# SOCIAL_AUTH_<BACKEND_NAME>_WHITELISTED_EMAILS = ['me@foo.com', 'you@bar.com']
#    Supply a list of email addresses to be white-listed. Any user with an email address in this list will login
#    successfully, otherwise AuthForbidden is raised.

# SOCIAL_AUTH_PROTECTED_USER_FIELDS = ['email', ]
#    The user_details pipeline processor will set certain fields on user objects, such as email. Set this to a list of
#    fields you only want to set for newly created users and avoid updating on further logins.

# SOCIAL_AUTH_SESSION_EXPIRATION = True
#    Some providers return the time that the access token will live, the value is stored in UserSocialAuth.extra_data
#    under the key expires. By default the current user session is set to expire if this value is present, this
#    behavior can be disabled by setting.

# SOCIAL_AUTH_OPENID_PAPE_MAX_AUTH_AGE = <int value>
#    Enable OpenID PAPE extension support by defining this setting.

# SOCIAL_AUTH_FIELDS_STORED_IN_SESSION = ['foo', ]
#    If you want to store extra parameters from POST or GET in session, like it was made for next parameter, define
#    this setting with the parameter names.
#    In this case foo field's value will be stored when user follows this link
#    <a href="{% url socialauth_begin 'github' %}?foo=bar">...</a>.

SOCIAL_AUTH_PIPELINE = (
    # Get the information we can about the user and return it in a simple
    # format to create the user instance later. In some cases the details are
    # already part of the auth response from the provider, but sometimes this
    # could hit a provider API.
    'social_core.pipeline.social_auth.social_details',

    # Get the social uid from whichever service we're authing thru. The uid is
    # the unique identifier of the given user in the provider.
    'social_core.pipeline.social_auth.social_uid',

    # Verifies that the current auth process is valid within the current
    # project, this is where emails and domains whitelists are applied (if
    # defined).
    'social_core.pipeline.social_auth.auth_allowed',

    # Checks if the current social-account is already associated in the site.
    'social_core.pipeline.social_auth.social_user',

    # Make up a username for this person, appends a random string at the end if
    # there's any collision.
    'social_core.pipeline.user.get_username',

    # Send a validation email to the user to verify its email address.
    # Disabled by default.
    # 'social_core.pipeline.mail.mail_validation',

    # Associates the current social details with another user account with
    # a similar email address. Disabled by default.
    # 'social_core.pipeline.social_auth.associate_by_email',

    # Create a user account if we haven't found one yet.
    'social_core.pipeline.user.create_user',

    # Create the record that associates the social account with the user.
    'social_core.pipeline.social_auth.associate_user',

    # Populate the extra_data field in the social record with the values
    # specified by settings (and the default ones like access_token, etc).
    'social_core.pipeline.social_auth.load_extra_data',

    # resolve user's membership in virtual organizations defined
    # in the eduperson_entitlement field of the extra_data
    'nsupdate.main.pipeline.sync_virtual_organizations',

    # Update the user record with any changed info from the auth service.
    'social_core.pipeline.user.user_details',
)

# we need slightly different classes for bootstrap3 than the default ones
from django.contrib.messages import constants
MESSAGE_TAGS = {
    constants.DEBUG: '',
    constants.INFO: 'alert-info',
    constants.SUCCESS: 'alert-success',
    constants.WARNING: 'alert-warning',
    constants.ERROR: 'alert-danger',
}

# translations - for details, see:
# https://docs.djangoproject.com/en/dev/topics/i18n/translation/#message-files and
# https://docs.djangoproject.com/en/dev/topics/i18n/translation/#how-django-discovers-language-preference
# By default language is set to english - modify settings.py to set list of languages
gettext_noop = lambda s: s
LANGUAGES = (
    ('en', gettext_noop('English')),
    ('de', gettext_noop('German')),
    ('el', gettext_noop('Greek')),
    ('fr', gettext_noop('French')),
    ('it', gettext_noop('Italian')),
    # ('es', gettext_noop('Spanish')),
    # ('zh-cn', gettext_noop('Chinese (China)')),
)

# silences 1_6.W001 warning you get without this:
TEST_RUNNER = 'django.test.runner.DiscoverRunner'

ACME_DIRECTORY_URL = os.getenv('DJANGO_ACME_DIRECTORY_URL')
EAB_KID = os.getenv('DJANGO_EAB_KID')
EAB_HMAC_KEY = os.getenv('DJANGO_EAB_HMAC_KEY')

REST_FRAMEWORK = {
    'DEFAULT_SCHEMA_CLASS': 'drf_spectacular.openapi.AutoSchema',
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'nsupdate.auth.drf_social_oauth2.authentication.SocialOAuth2Authentication',
        'rest_framework.authentication.SessionAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
        'rest_framework.renderers.BrowsableAPIRenderer',
    ],
    'DEFAULT_FILTER_BACKENDS': [
        'django_filters.rest_framework.DjangoFilterBackend',
        'rest_framework.filters.SearchFilter',
        'rest_framework.filters.OrderingFilter',
    ],
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 10,
}

SPECTACULAR_SETTINGS = {
    'TITLE': 'Dynamic DNS API',
    'DESCRIPTION': 'Schema for Dynamic DNS API',
    'VERSION': '1.0.0',
    'SERVE_INCLUDE_SCHEMA': False,
    'COMPONENT_SPLIT_REQUEST': True,
    'SECURITY': [{'SocialOAuth2Auth': []}],
    'SWAGGER_UI_SETTINGS': {
        'persistAuthorization': True,
        'withCredentials': True,
    },
    'AUTHENTICATION_WHITELIST': [
        'nsupdate.auth.drf_social_oauth2.authentication.SocialOAuth2Authentication'
    ]
}
