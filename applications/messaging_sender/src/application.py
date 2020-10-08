"""This just holds the container open."""
import os
import time


def main():
    """Wrap all."""
    service_name = os.getenv("BALENA_SERVICE_NAME")
    while True:
        print("Get console access to the {} "
              "container and run send_message.py".format(service_name))
        time.sleep(120)


if __name__ == "__main__":
    main()
