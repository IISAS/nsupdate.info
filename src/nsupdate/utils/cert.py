import os
import subprocess
import tempfile
from typing import Tuple

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
from django.conf import settings
from django.contrib import messages


def parse_csr(csr_pem: str) -> dict:
    """
    Parse a PEM-encoded Certificate Signing Request (CSR) and extract:
    - Common Name (CN)
    - SANs
    - Subject string
    - Wildcard detection
    - Key type & key size
    - Signature algorithm
    """
    csr = x509.load_pem_x509_csr(csr_pem.encode("utf-8"), default_backend())

    # ---- Common Name ----
    try:
        cn = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except IndexError:
        cn = None

    # ---- SANs ----
    san_list = []
    try:
        san_ext = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_list = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass

    # ---- Wildcard detection ----
    is_wildcard = False
    if (cn and cn.startswith("*.")) or any(san.startswith("*.") for san in san_list):
        is_wildcard = True

    # ---- Public key information ----
    public_key = csr.public_key()
    key_type = public_key.__class__.__name__

    key_size = getattr(public_key, "key_size", None)

    # ---- Signature algorithm ----
    signature_algorithm = None
    try:
        signature_algorithm = csr.signature_algorithm_oid._name
    except Exception:
        pass

    # ---- Return structured result ----
    return {
        "common_name": cn,
        "subject": csr.subject.rfc4514_string(),
        "sans": san_list,
        "is_wildcard": is_wildcard,
        "key_type": key_type,
        "key_size": key_size,
        "signature_algorithm": signature_algorithm,
    }


def parse_certificate(pem_str: str) -> dict:
    cert = x509.load_pem_x509_certificate(pem_str.encode("utf-8"))

    def name_to_dict(name):
        return {attr.oid._name: attr.value for attr in name}

    # SANs
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []

    public_key = cert.public_key()

    return {
        "subject": name_to_dict(cert.subject),
        "issuer": name_to_dict(cert.issuer),
        "not_before": cert.not_valid_before_utc,
        "not_after": cert.not_valid_after_utc,
        "serial_number": hex(cert.serial_number),
        "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
        "fingerprint_sha1": cert.fingerprint(hashes.SHA1()).hex(),
        "public_key_type": public_key.__class__.__name__,
        "public_key_bits": public_key.key_size,
        "sans": sans,
        "pem": pem_str,
    }


def issue_certificate(
    csr: str,
    server: str = settings.ACME_DIRECTORY_URL,
    eab_kid: str = settings.EAB_KID,
    eab_hmac_key: str = settings.EAB_HMAC_KEY,
):
    result = {
        'status': 'ERROR',
        'messages': [],
    }
    with tempfile.TemporaryDirectory() as tmp_dir:

        csr_path = os.path.join(tmp_dir, 'csr.pem')
        with open(csr_path, 'w', encoding='utf-8') as f:
            f.write(csr)

        cert_path = os.path.join(tmp_dir, 'cert.pem')
        fullchain_path = os.path.join(tmp_dir, 'fullchain.pem')
        chain_path = os.path.join(tmp_dir, 'chain.pem')

        # issue certificate with certbot tool
        cmd = [
            "certbot", "certonly",
            "--agree-tos",
            "--manual",
            "--register-unsafely-without-email",
            "--server", server,
            "--eab-kid", eab_kid,
            "--eab-hmac-key", eab_hmac_key,
            "--csr", csr_path,
            "--work-dir", tmp_dir,
            "--logs-dir", tmp_dir,
            "--config-dir", tmp_dir,
            "--cert-path", cert_path,
            "--fullchain-path", fullchain_path,
            "--chain-path", chain_path,
        ]
        cm_result = subprocess.run(
            cmd,
            cwd=tmp_dir,
            capture_output=True,
            text=True,
        )

        if cm_result.returncode == 0:
            result['status'] = 'OK'
            result['messages'].append([messages.SUCCESS, 'Certificate successfully issued.'])
            result['certs'] = {}
            for path in [cert_path, fullchain_path, chain_path]:
                with open(path, 'r', encoding='utf-8') as f:
                    filename: str = os.path.basename(path)
                    result['certs'][filename] = f.read()
        else:
            result['messages'].append(
                [
                    messages.ERROR,
                    'Failed to issue certificate. Please, try again. If the problem perists, contact support for assistance.',
                ],
            )
    return result


def validate_csr(self, csr_pem: str) -> Tuple[bool, str]:
    """
    Validate whether the given CSR matches this host's FQDN.

    Returns:
        (is_valid, message)
    """

    fqdn = self.get_fqdn()
    csr_info = parse_csr(csr_pem)

    cn = csr_info.get("common_name")
    sans = csr_info.get("sans", [])
    is_wildcard = csr_info.get("is_wildcard", False)

    # --- Missing CN ---
    if not cn:
        return False, "CSR is missing a Common Name (CN)."

    # --- Exact CN match ---
    if cn == fqdn:
        return True, "CSR CN matches host FQDN."

    # --- SAN match ---
    if fqdn in sans:
        return True, "CSR SAN list contains the host FQDN."

    # --- Wildcard match ---
    if is_wildcard:
        # remove "*."
        zone = cn[2:]
        if fqdn.endswith(zone):
            return True, "CSR wildcard CN covers the host FQDN."
        else:
            return (
                False,
                f"Wildcard CN '{cn}' does not cover host '{fqdn}'.",
            )

    # --- No match ---
    return (
        False,
        f"CSR CN '{cn}' does not match host '{fqdn}', "
        "and no SAN entry matches either.",
    )
