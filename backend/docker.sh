#!/bin/ash

# This is the Dockerfile's entrypoint script.
# https://docs.docker.com/config/containers/multi-service_container/
#
# Chrome is only required for headless Yahoo and Hotmail checks. Leave it off
# unless that browser is installed and the instance has enough memory.

if [ "${RCH_ENABLE_CHROMEDRIVER:-false}" = "true" ]; then
	chromedriver &
fi

exec ./reacher_backend
