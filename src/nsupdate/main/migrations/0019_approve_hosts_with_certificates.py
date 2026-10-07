from django.db import migrations


def approve_hosts_with_certificates(apps, schema_editor):
    # keep certificates issued before the approval workflow accessible
    Host = apps.get_model('main', 'Host')
    Host.objects.exclude(ssl_certificate__isnull=True).exclude(ssl_certificate='').update(
        certificates_requested=True,
        certificates_approved=True,
    )


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0018_certificates'),
    ]

    operations = [
        migrations.RunPython(approve_hosts_with_certificates, migrations.RunPython.noop),
    ]
