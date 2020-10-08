"""This just holds the container open."""
import os
import time


def main():
    """Wrap all."""
    service_name = os.getenv("BALENA_SERVICE_NAME")
    while True:
        print("{} waiting".format(service_name))
        time.sleep(600)


if __name__ == "__main__":
    main()
