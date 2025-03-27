# Use Debian as the base image
FROM debian:12-slim

# Install necessary packages: OpenSSL and build-essential tools
RUN apt-get update && \
    apt-get install -y \
    build-essential \
    libssl-dev \
    curl \
    && apt-get clean

# Set the working directory
WORKDIR /app

# Copy the C++ source code and certificate/key files into the container
COPY ktls_server.cpp /app/
COPY server_cert.pem /app/
COPY server_key.pem /app/

# Compile the C++ application using g++
RUN g++ -o ktls_server ktls_server.cpp -lssl -lcrypto

# Expose the port the server will listen on (changed to 5000)
EXPOSE 5000

# Command to run the server
CMD ["./ktls_server"]