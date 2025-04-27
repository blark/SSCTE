/*
 * tcp_server.c
 *
 * Provides a TCP server implementation with optional mutual TLS (mTLS) support.
 * Features:
 * - Single client handling at a time
 * - Non-blocking accept/receive operations
 * - Runtime selection between secure (TLS) and plain TCP modes
 * - Client certificate verification option (for mTLS)
 * - Proper resource management and error handling
 *
 * Thread safety: None. All functions must be called from the same thread.
 */

#include "tcp_server.h"
#include "esp_log.h"
#include "esp_tls_errors.h"
#include "esp_tls.h"
#include "lwip/sockets.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <unistd.h>        // close(), shutdown()
#include <stdlib.h>        // strdup(), free()
#include <netinet/tcp.h>   // TCP_NODELAY
#include <arpa/inet.h>     // inet_ntoa_r()
#include <string.h>
#include <errno.h>
#include "sdkconfig.h"

static const char *TAG = "TCPServer";

/* Listening socket FD, -1 if not initialized */
static int  g_server_sock = -1;
/* True if TLS mode is enabled */
static bool g_secure_mode = false;

/* Copy of TLS config (owns its PEM buffers) */
static tcp_server_tls_config_t g_tls_config;
/* ESP-TLS server config structure */
static esp_tls_cfg_server_t    g_esp_tls_cfg;

/*
 * Per-client connection context.
 * This unified structure handles both secure and non-secure connections:
 * - For TLS connections: secure=true, tls_handle=valid pointer, sockfd=-1
 * - For plain TCP:        secure=false, tls_handle=NULL,      sockfd=valid socket
 * - For no connection:    secure=false, tls_handle=NULL,      sockfd=-1
 */
typedef struct {
    bool       secure;     /* Whether this is a secure (TLS) connection */
    esp_tls_t *tls_handle; /* ESP-TLS handle (NULL for non-secure) */
    int        sockfd;     /* Raw socket FD for non-secure mode */
} tcp_client_conn_t;

/* Sentinel state: no client connected */
static tcp_client_conn_t g_client_conn = {
    .secure     = false,
    .tls_handle = NULL,
    .sockfd     = -1
};

/**
 * @brief Free any internally-duplicated PEM buffers.
 */
static void free_tls_config(void)
{
    free((void*)g_tls_config.ca_cert_pem);
    free((void*)g_tls_config.server_cert_pem);
    free((void*)g_tls_config.server_key_pem);
    memset(&g_tls_config, 0, sizeof(g_tls_config));
}

/**
 * @brief Clean up current client connection resources.
 */
static void cleanup_client(void)
{
    if (g_client_conn.secure && g_client_conn.tls_handle) {
        esp_tls_conn_destroy(g_client_conn.tls_handle);
        //esp_tls_server_session_delete(g_client_conn.tls_handle);
    }
    if (!g_client_conn.secure && g_client_conn.sockfd >= 0) {
        shutdown(g_client_conn.sockfd, SHUT_RDWR);
        close(g_client_conn.sockfd);
    }
    g_client_conn.secure     = false;
    g_client_conn.tls_handle = NULL;
    g_client_conn.sockfd     = -1;
}

/**
 * @brief Shut down server and free all resources.
 */
void tcp_cleanup(void)
{
    cleanup_client();

    if (g_server_sock >= 0) {
        close(g_server_sock);
        g_server_sock = -1;
    }
    if (g_secure_mode) {
        free_tls_config();
        g_secure_mode = false;
    }
    ESP_LOGI(TAG, "Server shutdown complete");
}

/**
 * @brief Initialize TCP server, with optional TLS support.
 */
esp_err_t tcp_server_init(const tcp_server_tls_config_t *tls_config)
{
    ESP_LOGI(TAG, "Initializing on port %d", CONFIG_BRIDGE_PORT);

    if (tls_config) {
        /* Enable TLS mode and copy PEM strings */
        g_secure_mode = true;
        g_tls_config.verify_client   = tls_config->verify_client;
        g_tls_config.ca_cert_pem     = tls_config->ca_cert_pem     ? strdup(tls_config->ca_cert_pem)     : NULL;
        g_tls_config.server_cert_pem = tls_config->server_cert_pem ? strdup(tls_config->server_cert_pem) : NULL;
        g_tls_config.server_key_pem  = tls_config->server_key_pem  ? strdup(tls_config->server_key_pem)  : NULL;

        memset(&g_esp_tls_cfg, 0, sizeof(g_esp_tls_cfg));
        g_esp_tls_cfg.cacert_buf    = (const unsigned char*)g_tls_config.ca_cert_pem;
        g_esp_tls_cfg.cacert_bytes  = g_tls_config.ca_cert_pem
                                        ? strlen(g_tls_config.ca_cert_pem) + 1
                                        : 0;
        g_esp_tls_cfg.servercert_buf   = (const unsigned char*)g_tls_config.server_cert_pem;
        g_esp_tls_cfg.servercert_bytes = g_tls_config.server_cert_pem
                                        ? strlen(g_tls_config.server_cert_pem) + 1
                                        : 0;
        g_esp_tls_cfg.serverkey_buf   = (const unsigned char*)g_tls_config.server_key_pem;
        g_esp_tls_cfg.serverkey_bytes = g_tls_config.server_key_pem
                                        ? strlen(g_tls_config.server_key_pem) + 1
                                        : 0;

        ESP_LOGI(TAG, "TLS enabled (client verify: %s)",
                 g_tls_config.verify_client ? "yes" : "no");
    } else {
        /* Plain TCP mode */
        g_secure_mode = false;
        ESP_LOGI(TAG, "TLS disabled");
    }

    /* Create listening socket */
    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        ESP_LOGE(TAG, "socket(): errno %d", errno);
        goto err;
    }

    /* Allow reuse of local address */
    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    /* Set 5-second send/recv timeouts */
    struct timeval t = { .tv_sec = 5, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &t, sizeof(t));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &t, sizeof(t));

    /* Bind to all interfaces */
    struct sockaddr_in addr = {
        .sin_family      = AF_INET,
        .sin_port        = htons(CONFIG_BRIDGE_PORT),
        .sin_addr.s_addr = htonl(INADDR_ANY),
    };
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        ESP_LOGE(TAG, "bind(): errno %d", errno);
        close(sock);
        goto err;
    }

    /* Listen for one connection */
    if (listen(sock, 1) < 0) {
        ESP_LOGE(TAG, "listen(): errno %d", errno);
        close(sock);
        goto err;
    }

    g_server_sock = sock;
    return ESP_OK;

err:
    g_secure_mode = false;
    free_tls_config();
    return ESP_FAIL;
}

/**
 * @brief Accept a new client if none is connected.
 */
bool tcp_handle_new_connection(void)
{
    if (g_client_conn.sockfd >= 0 || g_client_conn.secure || g_server_sock < 0) {
        return false;
    }

    /* Poll listening socket without blocking */
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(g_server_sock, &fds);
    struct timeval to = {
        .tv_sec  = 0,
        .tv_usec = CONFIG_SELECT_TIMEOUT_MS * 1000
    };
    if (select(g_server_sock + 1, &fds, NULL, NULL, &to) != 1) {
        return false;
    }

    /* Accept connection */
    struct sockaddr_in caddr;
    socklen_t len = sizeof(caddr);
    int csock = accept(g_server_sock, (struct sockaddr*)&caddr, &len);
    if (csock < 0) {
        ESP_LOGW(TAG, "accept(): errno %d", errno);
        return false;
    }

    /* Log client IP */
    char client_ip[16];
    inet_ntoa_r(caddr.sin_addr, client_ip, sizeof(client_ip));
    ESP_LOGI(TAG, "Client connected from %s:%u",
             client_ip, ntohs(caddr.sin_port));

    /* Disable Nagle */
    int flag = 1;
    setsockopt(csock, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));

    if (g_secure_mode) {
        /* TLS handshake */
        esp_tls_t *h = esp_tls_init();
        if (!h) {
            close(csock);
            return false;
        }
        int ret = esp_tls_server_session_create(&g_esp_tls_cfg, csock, h);
        if (ret != 0) {
            ESP_LOGE(TAG, "TLS handshake failed: %d", ret);
            esp_tls_server_session_delete(h);
            close(csock);
            return false;
        }
        ESP_LOGI(TAG, "TLS handshake completed");
        g_client_conn.secure     = true;
        g_client_conn.tls_handle = h;
        g_client_conn.sockfd     = -1;
    } else {
        /* Plain TCP */
        g_client_conn.secure     = false;
        g_client_conn.tls_handle = NULL;
        g_client_conn.sockfd     = csock;
    }

    return true;
}

/**
 * Receives data from either a TCP or TLS connection with non-blocking behavior
 *
 * @param buffer   Buffer to store received data
 * @param max_len  Maximum length of data to receive
 * @return         Number of bytes read, 0 for timeout, or negative for error
 */
int tcp_receive_data(uint8_t *buffer, size_t max_len)
{
    // Validate input parameters and connection state
    if (!buffer || max_len == 0 ||
        ((!g_client_conn.secure && g_client_conn.sockfd < 0) ||
         (g_client_conn.secure && g_client_conn.tls_handle == NULL))) {
        return -1;
    }

    int sockfd;

    if (g_client_conn.secure) {
        // Get the socket descriptor from the TLS handle
        if (esp_tls_get_conn_sockfd(g_client_conn.tls_handle, &sockfd) != ESP_OK) {
            ESP_LOGW(TAG, "Failed to get TLS socket descriptor");
            return -1;
        }
    } else {
        sockfd = g_client_conn.sockfd;
    }

    // Verify we have a valid socket descriptor
    if (sockfd < 0) {
        ESP_LOGW(TAG, "Invalid socket descriptor");
        return -1;
    }

    // Set up select() to poll the socket for available data
    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(sockfd, &read_fds);

    struct timeval timeout = {
        .tv_sec  = 0,
        .tv_usec = CONFIG_SELECT_TIMEOUT_MS * 1000
    };

    int select_result = select(sockfd + 1, &read_fds, NULL, NULL, &timeout);

    // Check for select errors or timeout
    if (select_result < 0) {
        ESP_LOGW(TAG, "Select error: %d", errno);
        return -1;
    } else if (select_result == 0) {
        // Timeout occurred, no data available
        return 0;
    }

    // Data is available, read it using the appropriate method
    int bytes_read = g_client_conn.secure
                  ? esp_tls_conn_read(g_client_conn.tls_handle, buffer, max_len)
                  : recv(g_client_conn.sockfd, buffer, max_len, 0);

    if (bytes_read <= 0) {
        if (bytes_read == 0) {
            ESP_LOGI(TAG, "Client disconnected");
        } else {
            ESP_LOGW(TAG, "%s read error: %d",
                     g_client_conn.secure ? "TLS" : "TCP",
                     g_client_conn.secure ? bytes_read : errno);
        }
        cleanup_client();
    }

    return bytes_read;
}

/**
 * @brief Send data to the connected client.
 */
int tcp_send_data(const uint8_t *data, size_t len)
{
    if (!data || len == 0 ||
        (!g_client_conn.secure && g_client_conn.sockfd < 0)) {
        return -1;
    }

    int ret = g_client_conn.secure
              ? esp_tls_conn_write(g_client_conn.tls_handle, data, len)
              : send(g_client_conn.sockfd, data, len, 0);

    if (ret <= 0) {
        ESP_LOGW(TAG, "%s write error: %d",
                 g_client_conn.secure ? "TLS" : "TCP",
                 g_client_conn.secure ? ret : errno);
        cleanup_client();
        return -1;
    }
    return ret;
}

/**
 * @brief Check if a client is currently connected.
 */
bool tcp_is_client_connected(void)
{
    if (g_client_conn.secure) {
        return g_client_conn.tls_handle != NULL;
    }
    return g_client_conn.sockfd >= 0;
}

