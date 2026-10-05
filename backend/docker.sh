#!/bin/ash

# This is the Dockerfile's entrypoint script.
# https://docs.docker.com/config/containers/multi-service_container/
#
# Chrome is only required for headless Yahoo and Hotmail checks. SMTP mailbox
# checks do not need it, and skipping it keeps the process small enough for
# Render. Set RCH_ENABLE_CHROMEDRIVER=false to skip it.

if [ "${RCH_ENABLE_CHROMEDRIVER:-true}" = "true" ]; then
	chromedriver &
fi

./reacher_backend
