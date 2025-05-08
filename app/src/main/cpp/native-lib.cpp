#include <jni.h>
#include <string>
#include <android/log.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/sha.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#define LOG_TAG "native-lib"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

static const unsigned char EXPECTED_CERT_HASH[SHA256_DIGEST_LENGTH] = {
        0xec, 0xcb, 0xd2, 0xe7, 0xbc, 0x78, 0x07, 0xae,
        0x13, 0xc0, 0x3d, 0x09, 0x35, 0xd3, 0xf8, 0x43,
        0xf0, 0xb1, 0xe1, 0x63, 0x40, 0x36, 0xff, 0x99,
        0xf7, 0x25, 0x01, 0x10, 0x9e, 0xd3, 0x2e, 0x9f
};

extern "C"
JNIEXPORT jstring JNICALL
Java_com_nativessl_MainActivity_nativeVerifyServer(JNIEnv *env, jobject /* this */, jstring domain_, jint port) {
    const char *domain = env->GetStringUTFChars(domain_, nullptr);
    if (!domain) {
        return env->NewStringUTF("Invalid domain string");
    }

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        env->ReleaseStringUTFChars(domain_, domain);
        return env->NewStringUTF("SSL_CTX creation failed");
    }

    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        SSL_CTX_free(ctx);
        env->ReleaseStringUTFChars(domain_, domain);
        return env->NewStringUTF("SSL object creation failed");
    }

    struct hostent *host = gethostbyname(domain);
    if (!host) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        env->ReleaseStringUTFChars(domain_, domain);
        return env->NewStringUTF("DNS resolution failed");
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        env->ReleaseStringUTFChars(domain_, domain);
        return env->NewStringUTF("Socket creation failed");
    }

    struct sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr = *(struct in_addr *) host->h_addr;

    if (connect(sock, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        close(sock);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        env->ReleaseStringUTFChars(domain_, domain);
        return env->NewStringUTF("Connection failed");
    }

    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) <= 0) {
        close(sock);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        env->ReleaseStringUTFChars(domain_, domain);
        return env->NewStringUTF("SSL handshake failed");
    }

    X509 *cert = SSL_get_peer_certificate(ssl);
    if (!cert) {
        SSL_shutdown(ssl);
        close(sock);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        env->ReleaseStringUTFChars(domain_, domain);
        return env->NewStringUTF("Failed to get certificate");
    }

    int len = i2d_X509(cert, nullptr);
    if (len < 0) {
        X509_free(cert);
        SSL_shutdown(ssl);
        close(sock);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        env->ReleaseStringUTFChars(domain_, domain);
        return env->NewStringUTF("Certificate conversion error");
    }

    unsigned char *der = (unsigned char *) malloc(len);
    unsigned char *p = der;
    i2d_X509(cert, &p);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(der, len, hash);
    free(der);
    X509_free(cert);

    if (memcmp(hash, EXPECTED_CERT_HASH, SHA256_DIGEST_LENGTH) != 0) {
        SSL_shutdown(ssl);
        close(sock);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        env->ReleaseStringUTFChars(domain_, domain);
        return env->NewStringUTF("SSL Pinning Failed");
    }

    std::string request = "GET /check HTTP/1.1\r\nHost: ";
    request += domain;
    request += "\r\nConnection: close\r\n\r\n";

    SSL_write(ssl, request.c_str(), static_cast<int>(request.length()));

    char buffer[2048];
    std::string response;
    int bytesRead;
    while ((bytesRead = SSL_read(ssl, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[bytesRead] = 0;
        response += buffer;
    }

    std::string body;
    size_t pos = response.find("\r\n\r\n");
    if (pos != std::string::npos) {
        body = response.substr(pos + 4);
    } else {
        body = response;
    }

    LOGI("Body: %s", body.c_str());

    SSL_shutdown(ssl);
    close(sock);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    env->ReleaseStringUTFChars(domain_, domain);

    return env->NewStringUTF(body.c_str());
}
