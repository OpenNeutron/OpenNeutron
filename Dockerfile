FROM rust:trixie

# Install required libs for musl build (Debian/Ubuntu style)
RUN apt-get update \
    && apt-get install -y --no-install-recommends musl-tools build-essential pkg-config ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Ensure musl target is available
RUN rustup target add x86_64-unknown-linux-musl

# Create app directory and set working dir
WORKDIR /usr/src/app

# Copy source for local build context; build can be on-demand from entrypoint
COPY . /usr/src/app

# Keep a lightweight default entrypoint that ensures the binary is built
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Expose configured ports
EXPOSE 2525
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["/usr/src/app/config.yml"]
