#!/usr/bin/env python3
"""Send encrypted messages over MQTT."""
import argparse
import os
import sys

from dane_jwe_jws.authentication import Authentication
from dane_jwe_jws.encryption import Encryption
from dane_discovery.exceptions import TLSAError
import paho.mqtt.publish as publish

from idlib import Bootstrap


def main():
    """Wrap all."""
    parser = argparse.ArgumentParser()
    parser.add_argument("recipient", help="Recipient DNS name")
    parser.add_argument("message", help="Message for recipient")
    args = parser.parse_args()
    env_config = get_config()
    try:
        payload = sign_and_encrypt(env_config["identity_name"], env_config["crypto_path"],
                                   env_config["app_uid"], args.message, args.recipient)
    except TLSAError as err:
        print("Trouble retrieving certificate from DNS: {}".format(err))
        sys.exit(2)
    topic_name = "/".join([env_config["group_name"], args.recipient])
    publish.single(topic_name, payload, hostname=env_config["mqtt_host"],
                   port=int(env_config["mqtt_port"]))


def sign_and_encrypt(source_name, crypto_path, app_uid, message, recipient):
    """Return a signed and encrypted JSON object."""
    crypto = Bootstrap(source_name, crypto_path, app_uid)
    signed = Authentication.sign(message, crypto.get_path_for_pki_asset("key"), source_name)
    return Encryption.encrypt(signed, recipient)


def get_config():
    """Get config from environment variables."""
    var_names = ["identity_name", "crypto_path", "mqtt_host",
                 "mqtt_port", "group_name", "app_uid"]
    config = {}
    for x in var_names:
        config[x] = os.getenv(x.upper())
    for k, v in config.items():
        if v is None:
            print("Missing essential configuration env var: {}".format(k.upper()))
    if None in config.values():
        sys.exit(1)
    return config

if __name__ == "__main__":
    main()
