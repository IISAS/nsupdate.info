def get_vo_name(ent: str):
    name = None
    if not ent or len(ent) == 0:
        return name
    if ":" in ent:
        # strip last part after `:`
        return ent[:ent.rindex(":")]
    return ent


def sync_virtual_organizations(backend, user, response, *args, **kwargs):
    entitlements = response.get("eduperson_entitlement", [])

    if isinstance(entitlements, str):
        entitlements = [entitlements]

    # clear only external virtual organizations; i.e., those that were not created within the DynDNS service
    vos_to_remove = user.vos.filter(created_by__isnull=True)
    user.vos.remove(*vos_to_remove)

    from .models import VirtualOrganization

    for ent in entitlements:
        name = get_vo_name(ent)
        vo, _ = VirtualOrganization.objects.get_or_create(
            name=name,
            defaults={
                "name": name,
                "created_by": None,
            },
        )
        user.vos.add(vo)
