ARG IMAGE_ARCH=amd64
FROM balenalib/${IMAGE_ARCH}-ubuntu:bionic

ENV DEBIAN_FRONTEND noninteractive
ENV APP_NAME messaging_receiver
ENV APP_USER messaging
ENV APP_UID 1001

ENV SRC_BASE_PATH ./applications/${APP_NAME}

COPY ${SRC_BASE_PATH}/depends/os_packages os_packages
COPY ${SRC_BASE_PATH}/depends/requirements.txt requirements.txt

RUN apt-get update && \
    cat ./os_packages | xargs apt-get install -y

RUN pip3 install -r requirements.txt

WORKDIR /application/${APP_NAME}/src
COPY ${SRC_BASE_PATH}/src .
COPY ./shared_libs/idlib ./idlib

CMD unbuffer ./application.py