import os
import socket
import ssl
import sys

import certifi
from cryptography import x509
from OpenSSL import SSL
from OpenSSL.crypto import X509Name

import aia


def main():
    if len(sys.argv) != 2 or sys.argv[1] == "-h" or sys.argv[1] == "--help":
        print("Usage: python3 fetch.py <domain>")
        sys.exit(1)

    domain = sys.argv[1]

    # What certificates are sent along by the server?
    peer_chain = get_peer_cert_chain_subjects(domain)

    # Try to get certificates via AIA
    aia_session = aia.AIASession()
    der_certs = aia_session.aia_chase(domain)

    # mkdir -p certs
    os.makedirs("certs", exist_ok=True)

    for i, cert in enumerate(der_certs):
        decoded_cert = x509.load_der_x509_certificate(cert)

        subject = get_dn(decoded_cert.subject)
        is_trusted = subject in aia_session._trusted
        is_supplied = subject in peer_chain

        if False:
            print()
            print("subject:", decoded_cert.subject)
            print("issuer:", decoded_cert.issuer)
            print("subject:", subject)
            print("is_trusted?", is_trusted)
            print("is_supplied?", is_supplied)

        if i == 0 or is_trusted:
            continue

        # generate file name
        common_name = decoded_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        filename = "certs/" + common_name.replace(" ", "_") + ".crt"
        print("Writing to filename:", filename)

        with open(filename, "w") as f:
            pem = ssl.DER_cert_to_PEM_cert(cert)
            f.write(pem)

def get_dn(name: x509.Name) -> str:
    """
    Displays a DN like rfc4514, but in reverse order, starting with C, ending with CN.
    Works on cryptography x509.Name objects.
    """
    return ",".join(attr.rfc4514_string() for attr in name.rdns)

def get_dn_from_pyopenssl_name(subj: X509Name) -> str:
    """
    Displays a DN like rfc4514, but in reverse order, starting with C, ending with CN.
    This one works on pyopenssl X509Name objects.
    """
    return ','.join(
        n.decode() + "=" + v.decode() for n,v in subj.get_components()
    )

def get_peer_cert_chain_subjects(domain: str) -> list[str]:
    """
    Returns the subjects of the certificates that are sent along by the server.
    """
    context = SSL.Context(method=SSL.TLS_CLIENT_METHOD)
    context.load_verify_locations(cafile=certifi.where())
    result = []
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        conn = SSL.Connection(context, sock)
        conn.settimeout(5)
        conn.connect((domain, 443))
        conn.setblocking(1)
        conn.do_handshake()
        conn.set_tlsext_host_name(domain.encode())
        chain = conn.get_peer_cert_chain() or []
        for cert in chain:
            subject_dn = get_dn_from_pyopenssl_name(cert.get_subject())
            result.append(subject_dn)
        conn.close()

    return result

if __name__ == "__main__":
    main()
