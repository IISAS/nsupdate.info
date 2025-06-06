# -*- coding: utf-8 -*-
"""
views for the (usually non-interactive, automated) web api
"""

import logging
logger = logging.getLogger(__name__)

import json
import base64
from importlib import import_module

from netaddr import IPAddress, IPNetwork
from netaddr.core import AddrFormatError

from django.http import HttpResponse, JsonResponse
from django.conf import settings
from django.db.models import F, Q
from django.views.generic.base import View
from django.contrib.auth.hashers import check_password
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from django.utils.timezone import now

from ..utils import log, ddns_client
from ..main import dnstools
from ..main.models import Domain, Host
from ..main.forms import CreateHostForm
from ..main.dnstools import (FQDN, update, delete, check_ip, put_ip_into_session,
                             SameIpError, DnsUpdateError, NameServerNotAvailable)
from ..main.iptools import normalize_ip


def Response(content, status=200):
    """
    shortcut for text/plain HttpResponse

    :param content: plain text content for the response
    :return: HttpResponse object
    """
    return HttpResponse(content, status=status, content_type='text/plain')


@log.logger(__name__)
def myip_view(request, logger=None):
    """
    return the IP address (can be v4 or v6) of the client requesting this view.

    :param request: django request object
    :return: HttpResponse object
    """
    # Note: keeping this as a function-based view, as it is frequently used -
    # maybe it is slightly more efficient than class-based.
    ipaddr = normalize_ip(request.META['REMOTE_ADDR'])
    logger.debug("detected remote ip address: %s" % ipaddr)
    return Response(ipaddr)


class DetectIpView(View):
    @log.logger(__name__)
    def get(self, request, sessionid, logger=None):
        """
        Put the IP address (can be v4 or v6) of the client requesting this view
        into the client's session.

        :param request: django request object
        :param sessionid: sessionid from url used to find the correct session w/o session cookie
        :return: HttpResponse object
        """
        engine = import_module(settings.SESSION_ENGINE)
        # we do not have the session as usual, as this is a different host,
        # so the session cookie is not received here - thus we access it via
        # the sessionid:
        s = engine.SessionStore(session_key=sessionid)
        ipaddr = normalize_ip(request.META['REMOTE_ADDR'])
        # as this is NOT the session automatically established and
        # also saved by the framework, we need to use save=True here
        put_ip_into_session(s, ipaddr, save=True)
        logger.debug("detected remote address: %s for session %s" % (ipaddr, sessionid))
        return HttpResponse(status=204)


class AjaxGetIps(View):
    @log.logger(__name__)
    def get(self, request, logger=None):
        """
        Get the IP addresses of the client from the session via AJAX
        (so we don't need to reload the view in case we just invalidated stale IPs
        and triggered new detection).

        :param request: django request object
        :return: HttpResponse object
        """
        response = dict(
            ipv4=request.session.get('ipv4', ''),
            ipv4_rdns=request.session.get('ipv4_rdns', ''),
            ipv6=request.session.get('ipv6', ''),
            ipv6_rdns=request.session.get('ipv6_rdns', ''),
        )
        logger.debug("ajax_get_ips response: %r" % (response,))
        return HttpResponse(json.dumps(response), content_type='application/json')


def basic_challenge(realm, content='Authorization Required'):
    """
    Construct a 401 response requesting http basic auth.

    :param realm: realm string (displayed by the browser)
    :param content: request body content
    :return: HttpResponse object
    """
    response = Response(content)
    response['WWW-Authenticate'] = 'Basic realm="%s"' % (realm,)
    response.status_code = 401
    return response


def basic_authenticate(auth):
    """
    Get username and password from http basic auth string.

    :param auth: http basic auth string [str on py2, str on py3]
    :return: username, password [unicode on py2, str on py3]
    """
    assert isinstance(auth, str)
    try:
        authmeth, auth = auth.split(' ', 1)
    except ValueError:
        # splitting failed, invalid auth string
        return
    if authmeth.lower() != 'basic':
        return
    # we ignore bytes that do not decode. username (hostname) and password
    # (update secret) both have to be ascii, everything else is a configuration
    # error on user side.
    auth = base64.b64decode(auth.strip()).decode('utf-8', errors='ignore')
    username, password = auth.split(':', 1)
    return username, password


@log.logger(__name__)
def check_api_auth(username, password, logger=None):
    """
    Check username and password against our database.

    :param username: http basic auth username (== fqdn)
    :param password: update password
    :return: host object if authenticated, None otherwise.
    """
    fqdn = username
    try:
        host = Host.get_by_fqdn(fqdn)
    except ValueError:
        # logging this at debug level because otherwise it fills our logs...
        logger.debug('%s - received bad credentials (auth username == dyndns hostname not in our hosts DB)' % (fqdn,))
        return None
    if host is not None:
        ok = check_password(password, host.update_secret)
        success_msg = ('failure', 'success')[ok]
        msg = "api authentication %s. [hostname: %s (given in basic auth)]" % (success_msg, fqdn,)
        host.register_api_auth_result(msg, fault=not ok)
        if ok:
            return host
        # in case this fills our logs and we never see valid credentials, we can just kill
        # the DB entry and this will fail earlier and get logged at debug level, see above.
        logger.warning('%s - received bad credentials (password does not match)' % (fqdn,))
    return None


def check_session_auth(user, hostname):
    """
    Check our database whether the hostname is owned by the user.

    :param user: django user object
    :param hostname: fqdn
    :return: host object if hostname is owned by this user, None otherwise.
    """
    fqdn = hostname
    try:
        host = Host.get_by_fqdn(fqdn, created_by=user)
    except ValueError:
        return None
    # we have specifically looked for a host of the logged in user,
    # we either have one now and return it, or we have None and return that.
    return host


def create_json_resp(status='ok', message=None, http_status=200, **kwargs):
    r = {'status': status}
    if message is not None and message != '':
        r['message'] = message
    if kwargs is not None and isinstance(kwargs, dict) and len(kwargs) > 0:
        r.update(**kwargs)
    return JsonResponse(r, status=http_status)


def json_resp_error(message, http_status=502, **kwargs):
    return create_json_resp(
        status='error',
        message=message,
        http_status=http_status,
        **kwargs
    )


def domain_exists(domain):
    return Domain.objects.filter(name=domain).exists()


class NicRegisterView(View):
    @log.logger(__name__)
    def get(self, request, logger=None):
        """
          API for hostname registration

          Examples:
          curl --request GET \
            --url https:/nsupdate.fedcloud.eu/nic/register?fqdn=${NAME}.${DOMAIN}&ip=${IP}&wildcard=${WILDCARD}&comment=${COMMENT} \
            --header 'Authorization: Bearer $ACCESS_TOKEN'

          curl --request GET \
            --url https:/nsupdate.fedcloud.eu/nic/register?name=${NAME}&domain=${DOMAIN}&ip=${IP}&wildcard=${WILDCARD}&comment=${COMMENT} \
            --header 'Authorization: Bearer $ACCESS_TOKEN'

          :param request: django request object
          :return: JsonResponse object
        """
        if not hasattr(request, 'user') \
            or request.user is None \
            or not request.user.is_authenticated:
            logger.warning('Unauthorized access')
            return json_resp_error('badauth', http_status=401)

        # read parameters from the request
        if 'fqdn' in request.GET:
            fqdn = request.GET.get('fqdn')
            name, domain_name = fqdn.split('.', 1)
        else:
            if 'name' not in request.GET:
                return json_resp_error('Missing parameter: name', http_status=400)
            if 'domain' not in request.GET:
                return json_resp_error('Missing parameter: domain', http_status=400)
            name = request.GET.get('name')
            domain_name = request.GET.get('domain')

        try:
            ip = request.GET.get('ip', request.META['REMOTE_ADDR'])
            ip = normalize_ip(ip)
            ip_rdtype = dnstools.check_ip(ip)
        except Exception:
            return json_resp_error('Invalid IP address: %s' % (ip,), http_status=400)

        wildcard = request.GET.get('wildcard', 'false').lower() in ['true', '1', 'yes']
        comment = request.GET.get('comment')

        # retrieve domain with constraints:
        #   a) domain is public
        #   b) domain is owned by the user
        domain = Domain.objects.filter(
            Q(name=domain_name) & (Q(created_by=request.user) | Q(public=True))
        )

        # check if the domain exists and if it is unique,
        # because we will need an id of an existing domain
        # for the CreateHostForm
        info = '[username: %s]' % (request.user.username,)
        if not domain.exists():
            msg = 'Unknown domain: %s' % (domain_name,)
            logger.warning(f'{msg} {info}')
            return json_resp_error('nxdomain', http_status=400)
        if domain.count() > 1:
            # should not occur
            msg = 'Domain name is not unique: %s' % (domain_name,)
            logger.error(f'{msg} {info}')
            return json_resp_error('dnserr', http_status=500)

        form = CreateHostForm({
            'name': name,
            'domain': domain.first().id,
            'wildcard': wildcard,
            'comment': comment
        })

        if not form.is_valid():
            return json_resp_error('formerr', http_status=400, errors=form.errors)

        host = form.save(commit=False)
        try:
            dnstools.add(host.get_fqdn(), ip)
            if host.wildcard:
                dnstools.add(host.get_fqdn_wildcard(), ip)
        except dnstools.Timeout:
            return json_resp_error('Timeout - communicating to name server failed.')
        except dnstools.NameServerNotAvailable:
            return json_resp_error('Name server unavailable.')
        except dnstools.NoNameservers:
            return json_resp_error('Resolving failed: No name servers.')
        except dnstools.DnsUpdateError as e:
            return json_resp_error('DNS update error [%s].' % str(e))
        except Domain.DoesNotExist:
            # should not happen: POST data had invalid (base)domain
            return json_resp_error('Base domain does not exist.')
        except dnstools.SameIpError:
            return json_resp_error('Host already exists in DNS.')
        except dnstools.DNSException as e:
            return json_resp_error('DNSException [%s]' % str(e))
        except OSError as err:  # was: socket.error (deprecated)
            return json_resp_error('Communication to name server failed [%s]' % str(err))
        else:
            host.created_by = request.user
            dt_now = now()
            host.last_update_ipv4 = dt_now
            host.last_update_ipv6 = dt_now if settings.WWW_IPV6_HOST else None
            host.save()
            update_secret = host.generate_secret()

            response = create_json_resp(
                status='ok',
                message='Host registered.',
                host=dict(
                    fqdn=f'{host.get_fqdn()}',
                    name=host.name,
                    domain=host.domain.name,
                    wildcard=host.wildcard,
                    comment=host.comment,
                    available=host.available,
                    client_faults=host.client_faults,
                    server_faults=host.server_faults,
                    abuse_blocked=host.abuse_blocked,
                    abuse=host.abuse,
                    last_update_ipv4=f'{host.last_update_ipv4.isoformat()}',
                    tls_update_ipv4=host.tls_update_ipv4,
                    ipv4=ip if ip_rdtype == 'ipv4' else None,   # host.get_ipv4() cannot be used because it takes some time to update the DNS record
                    last_update_ipv6=f'{host.last_update_ipv6.isoformat()}' if host.last_update_ipv6 else None,
                    tls_update_ipv6=host.tls_update_ipv6,
                    ipv6=ip if ip_rdtype == 'ipv6' else None,   # same as for ipv4
                    update_secret=update_secret,
                    IPv4_update_url_basic_auth=f'https://{host.get_fqdn()}:{update_secret}@{settings.WWW_IPV4_HOST}/nic/update',
                    IPv4_update_url_bearer_auth=f'https://{settings.WWW_IPV4_HOST}/nic/update?hostname={host.get_fqdn()}&myip=${{myip}}',
                    **(
                        dict(
                            IPv6_update_url_basic_auth=f'https://{host.get_fqdn()}:{update_secret}@{settings.WWW_IPV6_HOST}/nic/update',
                            IPv6_update_url_bearer_auth=f'https://{settings.WWW_IPV6_HOST}/nic/update?hostname={host.get_fqdn()}&myip=${{myip}}',
                        )
                        if settings.WWW_IPV6_HOST else dict()
                    )
                )
            )
            return response


class NicUnregisterView(View):
    @log.logger(__name__)
    def get(self, request, logger=None):
        """
          API for hostname unregistration

          Examples:
          curl --request GET \
            --url https:/nsupdate.fedcloud.eu/nic/unregister?fqdn=${NAME}.${DOMAIN}&wildcard=${WILDCARD} \
            --header 'Authorization: Bearer $ACCESS_TOKEN'

          curl --request GET \
            --url https:/nsupdate.fedcloud.eu/nic/unregister?name=${NAME}&domain=${DOMAIN}&wildcard=${WILDCARD} \
            --header 'Authorization: Bearer $ACCESS_TOKEN'

          :param request: django request object
          :return: JsonResponse object
        """
        if not hasattr(request, 'user') \
            or request.user is None \
            or not request.user.is_authenticated:
            logger.warning('Unauthorized access')
            return json_resp_error('badauth', http_status=401)

        info = '[username: %s]' % (request.user.username,)

        # read parameters from the request
        if 'fqdn' in request.GET:
            fqdn = request.GET.get('fqdn')
        else:
            if 'domain' in request.GET and 'name' not in request.GET:
                msg = 'Missing parameter: name'
                logger.warning(f'{msg} {info}')
                return json_resp_error(msg, http_status=400)
            elif 'name' in request.GET and 'domain' not in request.GET:
                msg = 'Missing parameter: domain'
                logger.warning(f'{msg} {info}')
                return json_resp_error(msg, http_status=400)
            elif 'name' not in request.GET and 'domain' not in request.GET:
                msg = 'Missing parameter: fqdn or name, domain'
                logger.warning(f'{msg} {info}')
                return json_resp_error(msg, http_status=400)

            name = request.GET.get('name')
            domain = request.GET.get('domain')
            fqdn = str(FQDN(name, domain))

        host = Host.get_by_fqdn(fqdn)

        if host is None:
            logger.warning('Host not found: %s [username: %s]' % (fqdn, request.user.username,))
            return json_resp_error('nohost', http_status=404)
        if host.created_by != request.user:
            logger.warning('Host is not owned by the user [host: %s, username: %s]' % (host.get_fqdn(), request.user.username,))
            host.register_client_result('Unauthorized access', fault=True)
            return json_resp_error('badauth', http_status=401)
        if host.abuse or host.abuse_blocked:
            msg = '%s - received unregister for host with abuse / abuse_blocked flag set' % (host.get_fqdn(),)
            logger.warning(f'{msg} {info}')
            host.register_client_result(f'{msg} {info}', fault=False)
            return json_resp_error('abuse', http_status=403)
        try:
            host.delete()
            response = create_json_resp(
                status='ok',
                message='Host unregistered.',
                host=dict(
                    fqdn=f'{host.get_fqdn()}',
                    name=host.name,
                    domain=host.domain.name,
                    wildcard=host.wildcard,
                    comment=host.comment
                )
            )
            return response
        except Exception as e:
            msg = 'Error during host unregistration: %s' % (str(e),)
            logger.exception(f'{msg} {info}')
            return json_resp_error('dnserr')


class NicDomainsView(View):
    @log.logger(__name__)
    def get(self, request, logger=None):
        """
          API for hostname unregistration

          Examples:
          curl --request GET \
            --url https:/nsupdate.fedcloud.eu/nic/domains \
            --header 'Authorization: Bearer $ACCESS_TOKEN'

          :param request: django request object
          :return: JsonResponse object
        """
        if not hasattr(request, 'user') \
            or request.user is None \
            or not request.user.is_authenticated:
            logger.warning('Unauthorized access')
            return json_resp_error('badauth', http_status=401)

        private_fields = ['name', 'public', 'available', 'comment', 'created_by__username']
        private_domains = (
            Domain.objects.filter(
                created_by=request.user
            )
            .select_related('created_by__profile')
            .annotate(
                owner=F('created_by__username'),
            )
            .only(*private_fields)
        )

        public_fields = ['name', 'public', 'available', 'comment', 'created_by__username']
        public_domains = (
            Domain.objects
            .filter(public=True)
            .exclude(created_by=request.user)
            .select_related('created_by')
            .annotate(
                owner=F('created_by__username'),
            )
            .only(*public_fields)
            .order_by(F('name'))
        )

        del public_fields[public_fields.index('created_by__username')]
        public_fields += ['owner']

        del private_fields[private_fields.index('created_by__username')]
        private_fields += ['owner']

        response = create_json_resp(
            status='ok',
            private=list(private_domains.values(*private_fields)),
            public=list(public_domains.values(*public_fields))
        )
        return response


class NicHostsView(View):
    @log.logger(__name__)
    def get(self, request, logger=None):
        """
          API for hostname unregistration

          Examples:
          curl --request GET \
            --url https:/nsupdate.fedcloud.eu/nic/hosts?domain=${DOMAIN} \
            --header 'Authorization: Bearer $ACCESS_TOKEN'

          :param request: django request object
          :return: JsonResponse object
        """
        if not hasattr(request, 'user') \
            or request.user is None \
            or not request.user.is_authenticated:
            logger.warning('Unauthorized access')
            return json_resp_error('badauth', http_status=401)

        # to retrieve hosts for a particular domain
        domain_name = request.GET.get('domain')
        if domain_name is not None:
            if not domain_exists(domain_name):
                msg = 'Unknown domain: %s' % (domain_name,)
                logger.warning(f'{msg} [domain: {domain_name}]')
                return json_resp_error(msg, http_status=400)

        # retrieve hosts created by the user
        fields = ['name', 'comment', 'available', 'client_faults', 'server_faults', 'abuse_blocked', 'abuse',
                  'last_update_ipv4', 'tls_update_ipv4', 'last_update_ipv6', 'tls_update_ipv6', 'domain__name',
                  'wildcard']
        hosts = (
            Host.objects
            .filter(Q(created_by=request.user))
        )
        if domain_name is not None:
            hosts = hosts.filter(
                Q(domain__name=domain_name)
            )
        hosts = (
            hosts
            .select_related('domain')
            .only(*fields)
        )
        hosts = hosts.order_by(F('domain__name'), F('name'))

        hosts_json = []
        for host in hosts:
            host_json = dict(
                fqdn=f'{host.get_fqdn()}',
                name=host.name,
                domain=host.domain.name,
                wildcard=host.wildcard,
                comment=host.comment,
                available=host.available,
                client_faults=host.client_faults,
                server_faults=host.server_faults,
                abuse_blocked=host.abuse_blocked,
                abuse=host.abuse,
                last_update_ipv4=f'{host.last_update_ipv4.isoformat()}' if host.last_update_ipv4 else None,
                tls_update_ipv4=host.tls_update_ipv4,
                ipv4=host.get_ipv4(),
                last_update_ipv6=f'{host.last_update_ipv6.isoformat()}' if host.last_update_ipv6 else None,
                tls_update_ipv6=host.tls_update_ipv6,
                ipv6=host.get_ipv6()
            )
            hosts_json.append(host_json)

        response = create_json_resp(
            status='ok',
            hosts=hosts_json
        )
        return response


class NicGenerateSecretView(View):
    @log.logger(__name__)
    def get(self, request, logger=None):
        """
          API for hostname unregistration

          Examples:
          curl --request GET \
            --url https:/nsupdate.fedcloud.eu/nic/generate_secret?fqdn=${DOMAIN} \
            --header 'Authorization: Bearer $ACCESS_TOKEN'

          :param request: django request object
          :return: JsonResponse object
        """
        if not hasattr(request, 'user') \
            or request.user is None \
            or not request.user.is_authenticated:
            logger.warning('Unauthorized access')
            return json_resp_error('badauth', http_status=401)

        # read parameters from the request
        if 'fqdn' in request.GET:
            fqdn = request.GET.get('fqdn')
        else:
            info = '[username: %s]' % (request.user.username,)
            if 'domain' in request.GET and 'name' not in request.GET:
                msg = 'Missing parameter: name'
                logger.warning(f'{msg} {info}')
                return json_resp_error(msg, http_status=400)
            elif 'name' in request.GET and 'domain' not in request.GET:
                msg = 'Missing parameter: domain'
                logger.warning(f'{msg} {info}')
                return json_resp_error(msg, http_status=400)
            elif 'name' not in request.GET and 'domain' not in request.GET:
                msg = 'Missing parameter: fqdn or name, domain'
                logger.warning(f'{msg} {info}')
                return json_resp_error(msg, http_status=400)

            name = request.GET.get('name')
            domain = request.GET.get('domain')
            fqdn = FQDN(name, domain)

        host = Host.get_by_fqdn(fqdn)
        if host is None:
            msg = 'Host does not exist'
            logger.warning(f'{msg} [fqdn: {fqdn}]')
            return json_resp_error(msg, http_status=400)

        response = create_json_resp(
            status='ok',
            secret=host.generate_secret()
        )
        return response


class NicUpdateView(View):
    @log.logger(__name__)
    def get(self, request, logger=None, delete=False):
        """
        dyndns2 compatible /nic/update API.

        Example URLs:

        Will request username (fqdn) and password (secret) from user,
        for interactive testing / updating:
        https://nsupdate.info/nic/update

        You can put it also into the url, so the browser will automatically
        send the http basic auth with the request:
        https://fqdn:secret@nsupdate.info/nic/update

        If the request does not come from the correct IP, you can give it as
        a query parameter.
        You can also give the hostname/fqdn as a query parameter (this is
        supported for api compatibility only), but then it MUST match the fqdn
        used for http basic auth's username part, because the secret only
        allows you to update this single fqdn).
        https://fqdn:secret@nsupdate.info/nic/update?hostname=fqdn&myip=1.2.3.4

        :param request: django request object
        :param delete: False means update, True means delete - used by NicDeleteView
        :return: HttpResponse object
        """
        hostname = request.GET.get('hostname')
        if hostname in settings.BAD_HOSTS:
            return Response('abuse', status=403)
        auth = request.META.get('HTTP_AUTHORIZATION')
        if auth is not None \
            and auth.lower().startswith('bearer ') \
            and hasattr(request, 'user') \
            and request.user is not None \
            and request.user.is_authenticated:
            # user is authenticated with a bearer token
            if hostname is None:
                logger.warning('Missing parameter: hostname [username: %s]' % (request.user.username,))
                return Response('nohost')
            if '.' not in hostname:
                logger.warning('Hostname is not a FQDN: %s [username: %s]' % (hostname, request.user.username,))
                return Response('notfqdn')
            host = Host.get_by_fqdn(hostname, created_by=request.user.id)
            if host is None:
                logger.warning('Host not found or unauthorized to update host: %s [username: %s]' % (hostname, request.user.username,))
                return Response('nohost')
            msg = "api authentication success. [hostname: %s (given in hostname parameter), username: %s]" % (hostname, request.user.username,)
            host.register_api_auth_result(msg, fault=False)
            logger.info("authenticated by bearer token for host %s [username: %s]" % (hostname, request.user.username,))
        else:
            # basic auth needed
            if auth is None:
                # logging this at debug level because otherwise it fills our logs...
                logger.debug('%s - received no auth' % (hostname, ))
                return basic_challenge("authenticate to update DNS", 'badauth')
            username, password = basic_authenticate(auth)
            if '.' not in username:  # username MUST be the fqdn
                # specifically point to configuration errors on client side
                return Response('notfqdn')
            if username in settings.BAD_HOSTS:
                return Response('abuse', status=403)
            host = check_api_auth(username, password)
            if host is None:
                return basic_challenge("authenticate to update DNS", 'badauth')
            logger.info("authenticated by update secret for host %s" % username)
            if hostname is None:
                # as we use update_username == hostname, we can fall back to that:
                hostname = username
            elif hostname != username:
                if '.' not in hostname:
                    # specifically point to configuration errors on client side
                    result = 'notfqdn'
                else:
                    # maybe this host is owned by same person, but we can't know.
                    result = 'nohost'  # or 'badauth'?
                msg = ("rejecting to update wrong host %s (given in query string) "
                       "[instead of %s (given in basic auth)]" % (hostname, username))
                logger.warning(msg)
                host.register_client_result(msg, fault=True)
                return Response(result)
        agent = request.META.get('HTTP_USER_AGENT', 'unknown')
        if agent in settings.BAD_AGENTS:
            msg = '%s - received update from bad user agent %r' % (hostname, agent)
            logger.warning(msg)
            host.register_client_result(msg, fault=True)
            return Response('badagent')
        ipaddr = request.GET.get('myip')
        if not ipaddr:  # None or ''
            ipaddr = normalize_ip(request.META.get('REMOTE_ADDR'))
        secure = request.is_secure()
        return _update_or_delete(host, ipaddr, secure, logger=logger, _delete=delete)


class NicDeleteView(NicUpdateView):
    @log.logger(__name__)
    def get(self, request, logger=None, delete=True):
        """
        /nic/delete API - delete a A or AAAA record.

        API is pretty much the same as for /nic/update, but it does not update
        the A or AAAA record, but deletes it.
        The ip address given via myip= param (or determined via REMOTE_ADDR)
        is used to determine the record type for deletion, but is otherwise
        ignored (so you can e.g. give myip=0.0.0.0 for A and myip=:: for AAAA).

        :param request: django request object
        :return: HttpResponse object
        """
        return super(NicDeleteView, self).get(request, logger=logger, delete=delete)


class AuthorizedNicUpdateView(View):

    @method_decorator(login_required)
    def dispatch(self, *args, **kwargs):
        return super(AuthorizedNicUpdateView, self).dispatch(*args, **kwargs)

    @log.logger(__name__)
    def get(self, request, logger=None, delete=False):
        """
        similar to NicUpdateView, but the client is not a router or other dyndns client,
        but the admin browser who is currently logged into the nsupdate.info site.

        Example URLs:

        https://nsupdate.info/nic/update?hostname=fqdn&myip=1.2.3.4

        :param request: django request object
        :param delete: False means update, True means delete - used by AuthorizedNicDeleteView
        :return: HttpResponse object
        """
        hostname = request.GET.get('hostname')
        if hostname is None:
            return Response('nohost')
        host = check_session_auth(request.user, hostname)
        if host is None:
            logger.warning('%s - is not owned by user: %s' % (hostname, request.user.username,))
            return Response('nohost')
        logger.info("authenticated by session as user %s, creator of host %s" % (request.user.username, hostname))
        # note: we do not check the user agent here as this is interactive
        # and logged-in usage - thus misbehaved user agents are no problem.
        ipaddr = request.GET.get('myip')
        if not ipaddr:  # None or empty string
            ipaddr = normalize_ip(request.META.get('REMOTE_ADDR'))
        secure = request.is_secure()
        return _update_or_delete(host, ipaddr, secure, logger=logger, _delete=delete)


class AuthorizedNicDeleteView(AuthorizedNicUpdateView):

    @log.logger(__name__)
    def get(self, request, logger=None, delete=True):
        """
        /nic/delete API - for logged-in admin browser.

        :param request: django request object
        :return: HttpResponse object
        """
        return super(AuthorizedNicDeleteView, self).get(request, logger=logger, delete=delete)


def _update_or_delete(host, ipaddr, secure=False, logger=None, _delete=False):
    """
    common code shared by the 2 update/delete views

    :param host: host object
    :param ipaddr: ip addr (v4 or v6)
    :param secure: True if we use TLS/https
    :param logger: a logger object
    :param _delete: True for delete, False for update
    :return: Response object with dyndns2 response
    """
    mode = ('update', 'delete')[_delete]
    # we are doing abuse / available checks rather late, so the client might
    # get more specific responses (like 'badagent' or 'notfqdn') by earlier
    # checks. it also avoids some code duplication if done here:
    fqdn = host.get_fqdn()
    if host.abuse or host.abuse_blocked:
        msg = '%s - received %s for host with abuse / abuse_blocked flag set' % (fqdn, mode,)
        logger.warning(msg)
        host.register_client_result(msg, fault=False)
        return Response('abuse')
    if not host.available:
        # not available is like it doesn't exist
        msg = '%s - received %s for unavailable host' % (fqdn, mode,)
        logger.warning(msg)
        host.register_client_result(msg, fault=False)
        return Response('nohost')
    try:
        # bug in dnspython: crashes if ipaddr is unicode, wants a str!
        # https://github.com/rthalley/dnspython/issues/41
        # TODO: reproduce and submit traceback to issue 41
        ipaddr = str(ipaddr)
        if '/' in ipaddr:
            # looks like there is a trailing /xx prefix length / netmask - get rid of it.
            # by doing this we support myip=<ip6lanprefix> of FritzBox.
            ipaddr = ipaddr.rsplit('/')[0]
        kind = check_ip(ipaddr, ('ipv4', 'ipv6'))
        rdtype = 'A' if kind == 'ipv4' else 'AAAA'
        IPNetwork(ipaddr)  # raise AddrFormatError here if there is an issue with ipaddr, see #394
    except (ValueError, UnicodeError, AddrFormatError):
        # invalid ip address string
        # some people manage to even give a non-ascii string instead of an ip addr
        msg = '%s - received bad ip address: %r' % (fqdn, ipaddr)
        logger.warning(msg)
        host.register_client_result(msg, fault=True)
        return Response('dnserr')  # there should be a better response code for this
    if mode == 'update' and ipaddr in settings.BAD_IPS_HOST:
        msg = '%s - received %s to blacklisted ip address: %r' % (fqdn, mode, ipaddr)
        logger.warning(msg)
        host.abuse = True
        host.abuse_blocked = True
        host.register_client_result(msg, fault=True)
        return Response('abuse')
    host.poke(kind, secure)
    try:
        if _delete:
            delete(fqdn, rdtype)
            if host.wildcard:
                delete(host.get_fqdn_wildcard(), rdtype)
        else:
            update(fqdn, ipaddr)
            if host.wildcard:
                update(host.get_fqdn_wildcard(), ipaddr)
    except SameIpError:
        msg = '%s - received no-change update, ip: %s tls: %r' % (fqdn, ipaddr, secure)
        logger.warning(msg)
        host.register_client_result(msg, fault=True)
        return Response('nochg %s' % ipaddr)
    except (DnsUpdateError, NameServerNotAvailable) as e:
        msg = str(e)
        msg = '%s - received %s that resulted in a dns error [%s], ip: %s tls: %r' % (
            fqdn, mode, msg, ipaddr, secure)
        logger.error(msg)
        host.register_server_result(msg, fault=True)
        return Response('dnserr')
    else:
        if _delete:
            msg = '%s - received delete for record %s, tls: %r' % (fqdn, rdtype, secure)
        else:
            msg = '%s - received good update -> ip: %s tls: %r' % (fqdn, ipaddr, secure)
        logger.info(msg)
        host.register_client_result(msg, fault=False)
        if _delete:
            # XXX unclear what to do for "other services" we relay updates to
            return Response('deleted %s' % rdtype)
        else:  # update
            _on_update_success(host, fqdn, kind, ipaddr, secure, logger)
            return Response('good %s' % ipaddr)


def _on_update_success(host, fqdn, kind, ipaddr, secure, logger):
    """after updating the host in dns, do related other updates"""
    # update related hosts
    rdtype = 'A' if kind == 'ipv4' else 'AAAA'
    for rh in host.relatedhosts.all():
        if rh.available:
            if kind == 'ipv4':
                ifid = rh.interface_id_ipv4
                netmask = host.netmask_ipv4
            else:  # kind == 'ipv6':
                ifid = rh.interface_id_ipv6
                netmask = host.netmask_ipv6
            ifid = ifid.strip() if ifid else ifid
            _delete = not ifid  # leave ifid empty if you don't want this rh record
            try:
                rh_fqdn = FQDN(rh.name + '.' + fqdn.host, fqdn.domain)
                if not _delete:
                    ifid = IPAddress(ifid)
                    network = IPNetwork("%s/%d" % (ipaddr, netmask))
                    rh_ipaddr = str(IPAddress(network.network) + int(ifid))
            except (IndexError, AddrFormatError, ValueError) as e:
                logger.warning("trouble computing address of related host %s [%s]" % (rh, e))
            else:
                if not _delete:
                    logger.info("updating related host %s -> %s" % (rh_fqdn, rh_ipaddr))
                else:
                    logger.info("deleting related host %s" % (rh_fqdn,))
                try:
                    if not _delete:
                        update(rh_fqdn, rh_ipaddr)
                    else:
                        delete(rh_fqdn, rdtype)
                except SameIpError:
                    msg = '%s - related hosts no-change update, ip: %s tls: %r' % (rh_fqdn, rh_ipaddr, secure)
                    logger.warning(msg)
                    host.register_client_result(msg, fault=True)
                except (DnsUpdateError, NameServerNotAvailable) as e:
                    msg = str(e)
                    if not _delete:
                        msg = '%s - related hosts update that resulted in a dns error [%s], ip: %s tls: %r' % (
                            rh_fqdn, msg, rh_ipaddr, secure)
                    else:
                        msg = '%s - related hosts deletion that resulted in a dns error [%s], tls: %r' % (
                            rh_fqdn, msg, secure)
                    logger.error(msg)
                    host.register_server_result(msg, fault=True)

    # now check if there are other services we shall relay updates to:
    for hc in host.serviceupdaterhostconfigs.all():
        if (kind == 'ipv4' and hc.give_ipv4 and hc.service.accept_ipv4
            or
            kind == 'ipv6' and hc.give_ipv6 and hc.service.accept_ipv6):
            kwargs = dict(
                name=hc.name, password=hc.password,
                hostname=hc.hostname, myip=ipaddr,
                server=hc.service.server, path=hc.service.path, secure=hc.service.secure,
            )
            try:
                ddns_client.dyndns2_update(**kwargs)
            except Exception:
                # we never want to crash here
                kwargs.pop('password')
                logger.exception("the dyndns2 updater raised an exception [%r]" % kwargs)
