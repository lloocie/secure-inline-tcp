# Linux build environment. Full namespace experiments still need suitable
# privileges; this image's build verifies compilation and unit tests only.
FROM debian:bookworm-slim
# Install the compiler, OpenSSL headers/libraries and lab tools.
# Remove package indexes afterwards to reduce image size.
RUN apt-get update && apt-get install -y --no-install-recommends build-essential libssl-dev openssl iproute2 ethtool tcpdump python3 ca-certificates && rm -rf /var/lib/apt/lists/*
# All subsequent relative paths refer to /project inside the image.
WORKDIR /project
# Copy project files, then build both the device and packet tests.
COPY . .
# A failed compile or unit test fails the image build.
RUN make && make test
# Start an interactive shell when requested; device processes are started
# explicitly with the namespace commands from the README.
CMD ["bash"]
