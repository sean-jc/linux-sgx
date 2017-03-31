#!/bin/bash
set -e

docker build -t sample .

# This script takes an optional argument that can be used to
# specify whether the AESM is running in the host or in docker
# container.  By default the AESM is assumed to be running in
# the host.
if [[ "$#" -ne 1 || "$1" == "host" ]]; then
    docker run --device=/dev/isgx -v /var/run/aesmd:/var/run/aesmd -it sample
elif [ "$1" == "docker" ]; then
    docker run --device=/dev/isgx -v /tmp/aesmd:/var/run/aesmd -it sample
else
    printf "Invalid argument '$1', expected 'host' or 'docker'\n"
fi
