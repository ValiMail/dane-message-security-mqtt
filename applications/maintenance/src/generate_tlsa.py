#!/usr/bin/env python3
"""Generate and print a TLSA record to screen."""
import os
import sys

from idlib import Bootstrap


def main():
    """Top-level logic."""
    env_required = ["IDENTITY_NAME", "APP_UID", "CRYPTO_PATH"]
    for x in env_required:
        if not os.getenv(x):
            print("Missing environment variable: {}".format(x))
            sys.exit(1)
    bootstrapper = Bootstrap(os.getenv("IDENTITY_NAME"), os.getenv("CRYPTO_PATH"),
                             os.getenv("APP_UID"))
    cert_obj = bootstrapper.get_local_cert_obj()
    if not bootstrapper.cert_matches_private_key(cert_obj):
        print("Public key in certificate does not match private key!")
    tlsa_record = bootstrapper.render_tlsa_record()
    print("TLSA record for {}: {}".format(os.getenv("IDENTITY_NAME"), tlsa_record))


if __name__ == "__main__":
    main()
