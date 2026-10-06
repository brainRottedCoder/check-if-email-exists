# From https://shaneutt.com/blog/rust-fast-small-docker-image-builds/

# ------------------------------------------------------------------------------
# Cargo Build Stage
# ------------------------------------------------------------------------------

FROM messense/rust-musl-cross:x86_64-musl as cargo-build

WORKDIR /usr/src/reacher

RUN rm -f target/x86_64-unknown-linux-musl/release/deps/reacher*

COPY . .

ENV SQLX_OFFLINE=true

RUN cargo build --bin reacher_backend --release --target=x86_64-unknown-linux-musl

# ------------------------------------------------------------------------------
# Final Stage
# ------------------------------------------------------------------------------

FROM zenika/alpine-chrome:123

WORKDIR /home/reacher/

USER root

# Install chromedriver
# https://github.com/Zenika/alpine-chrome/blob/master/with-chromedriver/Dockerfile
RUN apk add --no-cache chromium-chromedriver

COPY --from=cargo-build /usr/src/reacher/target/x86_64-unknown-linux-musl/release/reacher_backend .
COPY --from=cargo-build /usr/src/reacher/backend/docker.sh .
COPY --from=cargo-build /usr/src/reacher/backend/backend_config.toml .

# Git checkouts on Windows can commit shell scripts with CRLF. Alpine then
# looks for /bin/ash<CR> and the container exits before the server listens.
RUN sed -i 's/\r$//' docker.sh && chmod +x docker.sh reacher_backend && chown chrome:chrome reacher_backend docker.sh

# User chrome was created in zenika/alpine-chrome
USER chrome

ENV RUST_LOG=reacher=info
ENV RCH__HTTP_HOST=0.0.0.0
ENV RCH__BACKEND_NAME=render
# Single-shot checks only. RabbitMQ and Postgres are not required to boot.
ENV RCH__WORKER__ENABLE=false
# Stop a mailbox probe from hanging until Render kills the request.
ENV RCH__SMTP_TIMEOUT=15
# Chrome does not fit in Render's 512 MB instance. SMTP checks do not need it.
ENV RCH_ENABLE_CHROMEDRIVER=false

EXPOSE 8080

# Remove entrypoint from parent Docker file
# https://stackoverflow.com/questions/40122152/how-to-remove-entrypoint-from-parent-image-on-dockerfile
ENTRYPOINT []

CMD ["./docker.sh"]
