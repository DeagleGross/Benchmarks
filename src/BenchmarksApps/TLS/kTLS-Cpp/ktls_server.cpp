#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include <cstdlib>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 5000
#define CERT_FILE "server_cert.pem"
#define KEY_FILE "server_key.pem"

void log(const std::string& message) {
    std::cout << "[LOG] " << message << std::endl;
}

// Callback for passphrase
int password_cb(char *buf, int size, int rwflag, void *userdata) {
    std::string passphrase = "test"; 
    if (size < passphrase.length() + 1)
        return 0;
    std::strcpy(buf, passphrase.c_str());
    return passphrase.length();
}

void configure_context(SSL_CTX* ctx) {
    log("Configuring SSL context...");

    // Set passphrase callback
    SSL_CTX_set_default_passwd_cb(ctx, password_cb);

    if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
        log("Error loading server certificate");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
        log("Error loading server private key");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        log("Private key does not match the certificate");
        exit(EXIT_FAILURE);
    }

    log("SSL context configured successfully.");
}

void handle_client(SSL* ssl) {
    log("Handling new client connection...");
    
    if (SSL_accept(ssl) <= 0) {
        log("TLS handshake failed.");
        ERR_print_errors_fp(stderr);
        return;
    }
    
    log("TLS handshake successful.");

    const char response[] = "HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nHello World";
    SSL_write(ssl, response, strlen(response));
    
    log("Response sent to client.");

    SSL_shutdown(ssl);
    SSL_free(ssl);
}

int main() {
    log("Starting kTLS server...");

    SSL_library_init();
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();

    const SSL_METHOD* method = TLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    
    if (!ctx) {
        log("Failed to create SSL context.");
        ERR_print_errors_fp(stderr);
        return EXIT_FAILURE;
    }

    configure_context(ctx);

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        log("Failed to create socket.");
        return EXIT_FAILURE;
    }

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        log("Failed to bind socket.");
        return EXIT_FAILURE;
    }

    if (listen(server_fd, 5) < 0) {
        log("Failed to listen on socket.");
        return EXIT_FAILURE;
    }

    log("Server listening on port " + std::to_string(PORT));

    while (true) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
        
        if (client_fd < 0) {
            log("Failed to accept client connection.");
            continue;
        }

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
        log("Accepted connection from " + std::string(client_ip));

        SSL* ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_fd);
        handle_client(ssl);
        
        close(client_fd);
        log("Closed client connection.");
    }

    close(server_fd);
    SSL_CTX_free(ctx);
    EVP_cleanup();
    
    log("Server shutting down.");
    return 0;
}