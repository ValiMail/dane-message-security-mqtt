#!/usr/bin/env python3
"""Create a private key and CSR."""
import os
import sys

from idlib import Bootstrap


def main():
    """Top-level logic."""
    env_required = ["IDENTITY_NAME", "APP_UID", "CRYPTO_PATH"]
    env_optional = ["STATE", "COUNTRY", "LOCALITY", "ORGANIZATION"]
    for x in env_required:
        if not os.getenv(x):
            print("Missing environment variable: {}".format(x))
            sys.exit(1)
    kwargs = {x.lower: os.getenv(x) for x in env_optional if os.getenv(x)}
    bootstrapper = Bootstrap(os.getenv("IDENTITY_NAME"), os.getenv("CRYPTO_PATH"),
                             os.getenv("APP_UID"), **kwargs)
    print("Generating private key...")
    bootstrapper.generate_private_key()
    print("Generating CSR...")
    bootstrapper.generate_csr()
    csr_path = bootstrapper.get_path_for_pki_asset("csr")
    cert_path = bootstrapper.get_path_for_pki_asset("cert")
    print("CSR created at {}.".format(csr_path))
    print("Use the CSR to obtain a certificate, "
          "and place the certificate PEM at {}".format(cert_path))
    print("Once the certificate is in place, run generate_tlsa.py")


if __name__ == "__main__":
    main()
