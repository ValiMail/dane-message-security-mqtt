# dane-message-security-mqtt

E2E encrypted and source-signed messaging using PKI and DNS.

This is a proof-of-concept using JWS/JWE for message signing and encryption, with the certificates being discoverable via DNS. The transport used between messaging entities is the public broker provided by HiveMQ.

Disclaimer: Ultimately, it is the user's responsibility to evaluate the code in this and other referenced projects/libraries/repositories. This proof-of-concept sends messages over a public message broker, meaning that anyone with internet access can read the messages passing through the message broker. When message encryption is in place, the recipient's identity is still revealed via the message topic- that's how the recipient knows which messages it should download, decrypt, and authenticate.

## Prerequisites

*   For Balena, you will need at least one Raspberry Pi device and an account at Balena.io.
*   For local use, you will need to install Docker engine and docker-compose.
*   No matter your deployment, you will need administrative access to a DNS zone on a DNS server that supports the TLSA record type.
    *   There are a number of DNS-as-a-service providers who support the TLSA record type.
    *   PowerDNS supports this record type as well, if you prefer hosting your own DNS.

## Setup (Balena)

[![](https://balena.io/deploy.png)](https://dashboard.balena-cloud.com/deploy?repoUrl=https://github.com/ValiMail/secure-messager&configUrl=https://raw.githubusercontent.com/ValiMail/secure-messager/main/.balena/balena.yml&tarballUrl=https://github.com/ValiMail/secure-messager/archive/main.tar.gz)

*   Log into Balena.io
*   Click on the "Deploy with Balena" button above.
    *   Click on "Create and Deploy"
    *   Click on "Add Device"
    *   Make sure the information is correct (device type, WiFi vs Ethernet, etc...) and download the image.
    *   Burn the image to a device's SD card (https://balena.io/etcher is a great tool for this)
    *   Install the SD card in the Pi and connect power (network too, if you're not using WiFi)
    *   Select the device in the Balena dashboard and navigate to "Environment Variables"
    *   Create a new environment variable: `IDENTITY_NAME`.
        *   This will be the universal name of your device.
        *   This name should be in a DNS zone you control.
        *   The DNS zone should be hosted by a server or service that supports the TLSA DNS record type.
    *   Once the image has built and downloaded to your Pi, you can use the Balena console to bootstrap the device's identity.
        *   In the Balena dashboard, open a terminal session into the `maintenance` container.
        *   Run `./create_selfsigned_id.py`
        *   Run `./generate_tlsa.py`
        *   Take the output from the last command, beginning at `3 0 0 `, and create the TLSA record in your DNS zone. Many DNS providers will require the first 3 numbers to be entered into separate boxes in the UI, and the last box will contain the very long final string from the output. The very long string is the certificate, DER-encoded and represented in hex.
        *   Watch the logs in the `messaging_receiver` container for a message like `Reading /identity/${IDENTITY_NAME}.key.pem`. This indicates that your local identity is in sync with DNS and you're ready to accept and send messages.
    
## Send a message (Balena)

*   Use the Balena console to start a terminal session in the `messaging_sender` container.
*   run `./send_message "${RECIPIENT_NAME}" "HELLO THERE"`, replacing `${RECIPIENT_NAME}` with the DNS name of the intended recipient.

## Setup (docker-compose)

*   Install docker-compose and Docker engine
*   Clone this repo locally
*   Open two terminal sessions, navigate in both both to the root directory of this repo
*   In both shells, set an environment variable `IDENTITY_NAME` to your device's DNS name. This should be a new name in a DNS zone you have administrative access to, which supports the TLSA resource record.
*   In the first shell, run `docker-compose up --build`. Leave this shell alone until you're ready to kill the app.
*   In the second shell, run `docker-compose run  maintenance ./create_selfsigned_id.py`
*   In the second shell, run `docker-compose run  maintenance ./generate_tlsa.py`
*   Take the output from the last command, beginning at `3 0 0 `, and create the TLSA record in your DNS zone. Many DNS providers will require the first 3 numbers to be entered into separate boxes in the UI, and the last box will contain the very long final string from the output. The very long string is the certificate, DER-encoded and represented in hex.
*   After creating the DNS record, watch the first terminal for a log message like this: `messaging_receiver_1  | Reading /identity/${IDENTITY_NAME}.key.pem`. This indicates that your local identity is in sync with DNS and you're ready to accept and send messages.


## Send a message (docker-compose)

*   In the second terminal, run: `docker-compose run  messaging_sender ./send_message "${RECIPIENT_NAME}" "HELLO THERE"`, replacing `${RECIPIENT_NAME}` with the DNS name of the intended recipient.


## DNS-based identity libraries:

*   [dane-discovery](https://github.com/ValiMail/dane-discovery): DANE (TLSA records) for certificate discovery via DNS.
*   [dane-jwe-jws](https://github.com/ValiMail/dane-jwe-jws): DANE for identity-secured messaging, using JOSE (JWE/JWS) for object signing and encryption.