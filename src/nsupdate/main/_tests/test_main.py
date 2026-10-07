"""
Tests for main views module.
"""

from __future__ import print_function

import pytest

from django.urls import reverse


USERNAME = 'test'
PASSWORD = 'pass'


def test_views_anon(client):
    for view, kwargs, status_code in [
        ('home', dict(), 200),
        ('about', dict(), 200),
        ('robots', dict(), 200),
        # stuff that requires being logged-in redirects to the login view:
        ('status', dict(), 302),
        ('overview', dict(), 302),
        ('generate_secret_view', dict(pk=1), 302),
        ('generate_ns_secret_view', dict(pk=1), 302),
        ('host_view', dict(pk=1), 302),
        ('host_view', dict(pk=2), 302),
        ('host_view', dict(pk=100), 302),
        ('add_host', dict(), 302),
        ('delete_host', dict(pk=1), 302),
        ('related_host_overview', dict(mpk=1), 302),
        ('related_host_overview', dict(mpk=100), 302),
        ('related_host_view', dict(mpk=1, pk=1), 302),
        ('add_related_host', dict(mpk=1), 302),
        ('add_related_host', dict(mpk=2), 302),
        ('add_related_host', dict(mpk=100), 302),
        ('delete_related_host', dict(mpk=1, pk=1), 302),
        ('domain_view', dict(pk=1), 302),
        ('domain_view', dict(pk=2), 302),
        ('domain_view', dict(pk=100), 302),
        ('add_domain', dict(), 302),
        ('delete_domain', dict(pk=1), 302),
        ('delete_domain', dict(pk=2), 302),
        ('updater_hostconfig_overview', dict(pk=1), 302),
        ('updater_hostconfig', dict(pk=1), 302),
        ('delete_updater_hostconfig', dict(pk=1), 302),
        # interactive updater shows http basic auth popup
        ('update', dict(), 401),
    ]:
        print("%s, %s, %s" % (view, kwargs, status_code))
        response = client.get(reverse(view, kwargs=kwargs))
        assert response.status_code == status_code


def test_views_logged_in(client):
    client.login(username=USERNAME, password=PASSWORD)
    for view, kwargs, status_code in [
        ('home', dict(), 200),
        ('about', dict(), 200),
        ('robots', dict(), 200),
        ('status', dict(), 200),
        ('overview', dict(), 200),
        ('generate_secret_view', dict(pk=1), 200),
        ('generate_secret_view', dict(pk=2), 404),
        ('generate_secret_view', dict(pk=100), 404),
        ('generate_ns_secret_view', dict(pk=1), 200),
        ('generate_ns_secret_view', dict(pk=2), 404),
        ('generate_ns_secret_view', dict(pk=100), 404),
        ('host_view', dict(pk=1), 200),
        ('host_view', dict(pk=2), 404),
        ('host_view', dict(pk=100), 404),
        ('add_host', dict(), 200),
        ('delete_host', dict(pk=1), 200),
        ('delete_host', dict(pk=2), 404),
        ('delete_host', dict(pk=100), 404),
        ('related_host_overview', dict(mpk=1), 200),
        ('related_host_overview', dict(mpk=2), 404),
        ('related_host_overview', dict(mpk=100), 404),
        ('related_host_view', dict(mpk=1, pk=1), 200),
        ('related_host_view', dict(mpk=2, pk=1), 404),
        ('related_host_view', dict(mpk=100, pk=1), 404),
        ('related_host_view', dict(mpk=1, pk=2), 404),
        ('related_host_view', dict(mpk=1, pk=100), 404),
        ('add_related_host', dict(mpk=1), 200),
        ('add_related_host', dict(mpk=2), 404),
        ('add_related_host', dict(mpk=100), 404),
        ('delete_related_host', dict(mpk=1, pk=1), 200),
        ('delete_related_host', dict(mpk=2, pk=1), 404),
        ('delete_related_host', dict(mpk=100, pk=1), 404),
        ('delete_related_host', dict(mpk=1, pk=2), 404),
        ('delete_related_host', dict(mpk=1, pk=100), 404),
        ('domain_view', dict(pk=1), 200),
        ('domain_view', dict(pk=2), 404),
        ('domain_view', dict(pk=100), 404),
        ('add_domain', dict(), 403),
        ('delete_domain', dict(pk=1), 200),
        ('delete_domain', dict(pk=2), 404),
        ('delete_domain', dict(pk=100), 404),
        ('updater_hostconfig_overview', dict(pk=1), 200),
        ('updater_hostconfig_overview', dict(pk=2), 404),
        ('updater_hostconfig_overview', dict(pk=100), 404),
        ('updater_hostconfig', dict(pk=1), 200),
        ('updater_hostconfig', dict(pk=2), 404),
        ('updater_hostconfig', dict(pk=100), 404),
        ('delete_updater_hostconfig', dict(pk=1), 200),
        ('delete_updater_hostconfig', dict(pk=2), 404),
        ('delete_updater_hostconfig', dict(pk=100), 404),
        ('update', dict(), 401),
    ]:
        print("%s, %s, %s" % (view, kwargs, status_code))
        response = client.get(reverse(view, kwargs=kwargs))
        assert response.status_code == status_code


def test_add_domain_staff(client, django_user_model):
    user = django_user_model.objects.get(username=USERNAME)
    user.is_staff = True
    user.save()
    client.login(username=USERNAME, password=PASSWORD)
    response = client.get(reverse('add_domain'))
    assert response.status_code == 200


CERTIFICATE_VIEWS = [
    ('host_upload_csr', dict(pk=1)),
    ('host_certificate', dict(pk=1)),
    ('host_certificate_download', dict(host_id=1)),
]


def test_certificates_not_enabled(client):
    client.login(username=USERNAME, password=PASSWORD)
    for view, kwargs in CERTIFICATE_VIEWS:
        response = client.get(reverse(view, kwargs=kwargs))
        assert response.status_code == 403, view


def test_certificates_approved_for_host(client):
    from nsupdate.main.models import Host
    Host.objects.filter(pk=1).update(certificates_requested=True, certificates_approved=True)
    client.login(username=USERNAME, password=PASSWORD)
    response = client.get(reverse('host_upload_csr', kwargs=dict(pk=1)))
    assert response.status_code == 200


def test_certificates_enabled_for_domain(client):
    from nsupdate.main.models import Host
    host = Host.objects.get(pk=1)
    host.domain.certificates_enabled = True
    host.domain.save()
    assert not host.certificates_approved
    client.login(username=USERNAME, password=PASSWORD)
    response = client.get(reverse('host_upload_csr', kwargs=dict(pk=1)))
    assert response.status_code == 200


def test_request_certificates_button(client):
    from nsupdate.main.models import Host
    client.login(username=USERNAME, password=PASSWORD)
    response = client.get(reverse('host_view', kwargs=dict(pk=1)))
    assert b'Request certificates' in response.content
    response = client.post(reverse('host_certificate_approval', kwargs=dict(pk=1)), dict(action='request'))
    assert response.status_code == 302
    host = Host.objects.get(pk=1)
    assert host.certificates_requested
    assert not host.certificates_approved
    response = client.get(reverse('host_view', kwargs=dict(pk=1)))
    assert b'awaiting approval' in response.content
    assert b'Request certificates' not in response.content
    assert b'name="certificates_requested"' not in response.content


def test_cancel_certificate_request(client):
    from nsupdate.main.models import Host
    Host.objects.filter(pk=1).update(certificates_requested=True, certificates_approved=True)
    client.login(username=USERNAME, password=PASSWORD)
    response = client.post(reverse('host_certificate_approval', kwargs=dict(pk=1)), dict(action='cancel'))
    assert response.status_code == 302
    host = Host.objects.get(pk=1)
    assert not host.certificates_requested
    assert not host.certificates_approved


def test_request_certificates_invalid(client):
    client.login(username=USERNAME, password=PASSWORD)
    # host owned by another user
    response = client.post(reverse('host_certificate_approval', kwargs=dict(pk=2)), dict(action='request'))
    assert response.status_code == 404
    response = client.post(reverse('host_certificate_approval', kwargs=dict(pk=1)), dict(action='bogus'))
    assert response.status_code == 400
    response = client.get(reverse('host_certificate_approval', kwargs=dict(pk=1)))
    assert response.status_code == 405


def test_certificate_requests_view(client, django_user_model):
    from nsupdate.main.models import Host
    client.login(username=USERNAME, password=PASSWORD)
    assert client.get(reverse('certificate_requests')).status_code == 403
    assert client.post(reverse('certificate_requests'), dict(host_id=1, action='approve')).status_code == 403
    assert not Host.objects.get(pk=1).certificates_approved

    django_user_model.objects.filter(username=USERNAME).update(is_staff=True)
    Host.objects.filter(pk=1).update(certificates_requested=True)
    response = client.get(reverse('certificate_requests'))
    assert response.status_code == 200
    assert list(response.context['pending_hosts'].values_list('pk', flat=True)) == [1]

    response = client.post(reverse('certificate_requests'), dict(host_id=1, action='approve'))
    assert response.status_code == 302
    assert Host.objects.get(pk=1).certificates_approved

    response = client.post(reverse('certificate_requests'), dict(host_id=1, action='revoke'))
    assert response.status_code == 302
    assert not Host.objects.get(pk=1).certificates_approved


def _post_edit_domain(client):
    from conftest import NAMESERVER_IP, NAMESERVER_UPDATE_ALGORITHM, NAMESERVER_UPDATE_SECRET
    return client.post(reverse('domain_view', kwargs=dict(pk=1)), dict(
        comment='', nameserver_ip=NAMESERVER_IP, nameserver_update_algorithm=NAMESERVER_UPDATE_ALGORITHM,
        nameserver_update_secret=NAMESERVER_UPDATE_SECRET, certificates_enabled='on'))


def test_non_staff_cannot_enable_domain_certificates(client):
    from nsupdate.main.models import Domain
    client.login(username=USERNAME, password=PASSWORD)
    assert _post_edit_domain(client).status_code == 302
    assert not Domain.objects.get(pk=1).certificates_enabled


def test_staff_can_enable_domain_certificates(client, django_user_model):
    from nsupdate.main.models import Domain
    django_user_model.objects.filter(username=USERNAME).update(is_staff=True)
    client.login(username=USERNAME, password=PASSWORD)
    assert _post_edit_domain(client).status_code == 302
    assert Domain.objects.get(pk=1).certificates_enabled


def test_api_certificate_approval(client):
    from conftest import TEST_HOST
    from nsupdate.main.models import Host
    client.login(username=USERNAME, password=PASSWORD)
    url = reverse('host-certificate-approval', kwargs=dict(fqdn=str(TEST_HOST)))

    response = client.get(url)
    assert response.status_code == 200
    assert response.json() == dict(
        fqdn=str(TEST_HOST), certificates_requested=False, certificates_approved=False,
        domain_certificates_enabled=False, certificates_enabled=False)
    assert not Host.objects.get(pk=1).certificates_requested

    response = client.post(url)
    assert response.status_code == 200
    assert response.json()['certificates_requested'] is True
    assert response.json()['certificates_enabled'] is False
    assert Host.objects.get(pk=1).certificates_requested
    assert client.get(url).json()['certificates_requested'] is True

    Host.objects.filter(pk=1).update(certificates_approved=True)
    response = client.delete(url)
    assert response.status_code == 200
    assert response.json()['certificates_requested'] is False
    host = Host.objects.get(pk=1)
    assert not host.certificates_requested
    assert not host.certificates_approved


def test_api_certificate_approval_other_users_host(client):
    from conftest import TEST_HOST2
    client.login(username=USERNAME, password=PASSWORD)
    url = reverse('host-certificate-approval', kwargs=dict(fqdn=str(TEST_HOST2)))
    assert client.get(url).status_code == 404
    assert client.post(url).status_code == 404


def test_api_certificate_approval_domain_enabled(client):
    from conftest import TEST_HOST
    from nsupdate.main.models import Domain
    Domain.objects.filter(pk=1).update(certificates_enabled=True)
    client.login(username=USERNAME, password=PASSWORD)
    response = client.get(reverse('host-certificate-approval', kwargs=dict(fqdn=str(TEST_HOST))))
    assert response.status_code == 200
    assert response.json()['domain_certificates_enabled'] is True
    assert response.json()['certificates_enabled'] is True
    assert response.json()['certificates_approved'] is False


def test_api_certificate_not_enabled(client):
    from conftest import TEST_HOST
    client.login(username=USERNAME, password=PASSWORD)
    response = client.get(reverse('host-get-certificate', kwargs=dict(fqdn=str(TEST_HOST))))
    assert response.status_code == 403
    assert '/certificate/approval' in response.json()['detail']


def test_api_certificate_approval_session_csrf():
    """
    swagger ui (session auth) sends the CSRF token it embeds in the page as a header
    """
    import re
    from django.test import Client
    from conftest import TEST_HOST
    client = Client(enforce_csrf_checks=True)
    client.login(username=USERNAME, password=PASSWORD)
    url = reverse('host-certificate-approval', kwargs=dict(fqdn=str(TEST_HOST)))
    assert client.post(url).status_code == 403  # no token

    page = client.get(reverse('swagger-ui')).content.decode()
    assert 'withCredentials' not in page
    header, token = re.search(
        r'"same-origin"\) \{\s*request\.headers\["([^"]+)"\] = "([^"]+)"', page).groups()
    response = client.post(url, **{'HTTP_' + header.upper().replace('-', '_'): token})
    assert response.status_code == 200
    assert response.json()['certificates_requested'] is True


def test_domains_owner_details(client, django_user_model):
    django_user_model.objects.filter(username=USERNAME).update(first_name='John', last_name='Doe')
    client.login(username=USERNAME, password=PASSWORD)
    rows = {row['name']: row for row in client.get(reverse('domains')).json()['data']}
    from conftest import TESTDOMAIN
    assert rows[TESTDOMAIN]['owner'] == USERNAME
    assert rows[TESTDOMAIN]['owner_name'] == 'John Doe'
    # e-mail addresses are shown to staff only
    assert all('owner_email' not in row for row in rows.values())

    django_user_model.objects.filter(username=USERNAME).update(is_staff=True)
    rows = client.get(reverse('domains')).json()['data']
    assert all('owner_email' in row for row in rows)
