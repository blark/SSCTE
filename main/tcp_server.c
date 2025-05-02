/*
 * tcp_server.c
 *
 * Provides a TCP server implementation with optional mutual TLS (mTLS) support
 * for multiple UART-TCP bridges.
 *
 * Features:
 * - Multiple server instances, one per UART bridge
 * - Single client handling per server at a time
 * - Non-blocking accept/receive operations
 * - Runtime selection between secure (TLS) and plain TCP modes
 * - Client certificate verification option (for mTLS)
 * - Proper resource management and error handling
 *
 * Thread safety: None. All functions must be called from the same thread.
 */

#include "tcp_server.h"
#include "uart_manager.h"
#include "esp_log.h"
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

#if defined(CONFIG_SSCTE_TLS_ENABLE)
#include "esp_tls.h"
#include "esp_tls_errors.h"
#endif

static const char *TAG = "TCPServer";

/**
 * Global flag indicating whether TLS mode is enabled for all servers.
 * When true, all TCP servers use TLS; when false, they use plain TCP.
 */
static bool g_secure_mode = false;

#if defined(CONFIG_SSCTE_TLS_ENABLE)
/**
 * Global TLS configuration copied from user input.
 * Contains certificates and keys needed for TLS operation.
 * Memory for certificates is owned by this struct and must be freed.
 */
static tcp_server_tls_config_t g_tls_config;

/**
 * ESP-TLS server configuration structure built from our TLS config.
 * This is passed to ESP-TLS APIs for secure connection handling.
 */
static esp_tls_cfg_server_t g_esp_tls_cfg;
#endif

/**
 * @brief Load certificate or key file from filesystem
 *
 * Opens, reads, and returns the content of a certificate or key file.
 * Caller must free the returned buffer when done.
 *
 * @param file_path Path to the certificate or key file
 * @return Pointer to null-terminated string with file contents, or NULL on error
 */
//static char* load_cert_file(const char* file_path) {
//    FILE* file = fopen(file_path, "r");
//    if (file == NULL) {
//        ESP_LOGE(TAG, "Failed to open %s", file_path);
//        return NULL;
//    }
//
//    // Get file size
//    fseek(file, 0, SEEK_END);
//    long file_size = ftell(file);
//    fseek(file, 0, SEEK_SET);
//
//    // Allocate memory for file contents plus null terminator
//    char* buffer = malloc(file_size + 1);
//    if (buffer == NULL) {
//        ESP_LOGE(TAG, "Failed to allocate memory for certificate");
//        fclose(file);
//        return NULL;
//    }
//
//    // Read the file
//    size_t read_size = fread(buffer, 1, file_size, file);
//    fclose(file);
//
//    if (read_size != file_size) {
//        ESP_LOGE(TAG, "Failed to read certificate file");
//        free(buffer);
//        return NULL;
//    }
//
//    // Null terminate the buffer
//    buffer[file_size] = '\0';
//    return buffer;
//}

/**
 * @brief Free any internally-duplicated PEM buffers
 *
 * Releases memory allocated for certificate and key strings.
 * Sets all pointers to NULL to prevent use-after-free.
 */
#if defined(CONFIG_SSCTE_TLS_ENABLE)
static void free_tls_config(void)
{
    free((void*)g_tls_config.ca_cert_pem);
    free((void*)g_tls_config.server_cert_pem);
    free((void*)g_tls_config.server_key_pem);
    memset(&g_tls_config, 0, sizeof(g_tls_config));
}

/**
 * @brief Clean up TLS client connection
 *
 * Closes and frees resources associated with a TLS connection.
 *
 * @param bridge Pointer to the bridge whose TLS connection should be cleaned up
 */
static void cleanup_client_tls(uart_bridge_t *bridge)
{
    if (bridge->tls_handle) {
        esp_tls_conn_destroy(bridge->tls_handle);
        bridge->tls_handle = NULL;
    }
}
#endif /* CONFIG_SSCTE_TLS_ENABLE */

/**
 * @brief Clean up client connection resources
 *
 * Closes the client connection (TLS or plain TCP) and resets
 * associated fields in the bridge structure.
 *
 * @param bridge Pointer to the bridge whose client should be cleaned up
 */
static void cleanup_client(uart_bridge_t *bridge)
{
#if defined(CONFIG_SSCTE_TLS_ENABLE)
    if (g_secure_mode && bridge->tls_handle) {
        cleanup_client_tls(bridge);
    }
#endif
    if (!g_secure_mode && bridge->client_sock >= 0) {
        shutdown(bridge->client_sock, SHUT_RDWR);
        close(bridge->client_sock);
    }

    bridge->client_sock = -1;
}

/**
 * @brief Shut down all TCP servers and free all resources
 *
 * Disconnects clients, closes listening sockets, and frees TLS resources.
 * After calling this, servers must be reinitialized before use.
 */
void tcp_cleanup(void)
{
    // Get all bridge instances
    uart_bridge_t *bridges = uart_manager_get_instances();
    int num_bridges = uart_manager_get_active_count();

    // Clean up each bridge's TCP/TLS resources
    for (int i = 0; i < num_bridges; i++) {
        uart_bridge_t *bridge = &bridges[i];

        if (!bridge->enabled) {
            continue;
        }

        // Clean up client connection
        cleanup_client(bridge);

        // Close server socket
        if (bridge->server_sock >= 0) {
            close(bridge->server_sock);
            bridge->server_sock = -1;
        }
    }

#if defined(CONFIG_SSCTE_TLS_ENABLE)
    // Clean up global TLS resources
    if (g_secure_mode) {
        free_tls_config();
        g_secure_mode = false;
    }
#endif

    ESP_LOGI(TAG, "TCP servers shutdown complete");
}

/**
 * @brief Initialize TCP servers for all active bridges
 *
 * Sets up listening sockets for each bridge. If TLS is enabled,
 * configures all servers for secure mode with the provided certificates.
 *
 * @param tls_config TLS configuration (NULL for plain TCP mode)
 * @return ESP_OK on success, ESP_FAIL on error
 */
esp_err_t tcp_server_init(const tcp_server_tls_config_t *tls_config)
{
    // Get all bridge instances
    uart_bridge_t *bridges = uart_manager_get_instances();
    int num_bridges = uart_manager_get_active_count();

    if (num_bridges == 0) {
        ESP_LOGE(TAG, "No active bridges available");
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "Initializing TCP servers for %d bridges", num_bridges);

#if defined(CONFIG_SSCTE_TLS_ENABLE)
    if (tls_config) {
        /* Enable TLS mode and copy PEM strings */
        g_secure_mode = true;
        g_tls_config.verify_client = tls_config->verify_client;
        g_tls_config.ca_cert_pem = tls_config->ca_cert_pem ? strdup(tls_config->ca_cert_pem) : NULL;
        g_tls_config.server_cert_pem = tls_config->server_cert_pem ? strdup(tls_config->server_cert_pem) : NULL;
        g_tls_config.server_key_pem = tls_config->server_key_pem ? strdup(tls_config->server_key_pem) : NULL;

        /* Set up ESP-TLS configuration structure */
        memset(&g_esp_tls_cfg, 0, sizeof(g_esp_tls_cfg));
        g_esp_tls_cfg.cacert_buf = (const unsigned char*)g_tls_config.ca_cert_pem;
        g_esp_tls_cfg.cacert_bytes = g_tls_config.ca_cert_pem
                                    ? strlen(g_tls_config.ca_cert_pem) + 1
                                    : 0;
        g_esp_tls_cfg.servercert_buf = (const unsigned char*)g_tls_config.server_cert_pem;
        g_esp_tls_cfg.servercert_bytes = g_tls_config.server_cert_pem
                                    ? strlen(g_tls_config.server_cert_pem) + 1
                                    : 0;
        g_esp_tls_cfg.serverkey_buf = (const unsigned char*)g_tls_config.server_key_pem;
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
#else
    /* TLS not available in this build */
    g_secure_mode = false;
    ESP_LOGI(TAG, "TLS disabled (not configured in build)");
#endif

    // Initialize TCP server for each active bridge
    for (int i = 0; i < num_bridges; i++) {
        uart_bridge_t *bridge = &bridges[i];

        if (!bridge->enabled) {
            continue;
        }

        ESP_LOGI(TAG, "Initializing TCP server for bridge %d on port %d",
                i, bridge->tcp_port);

        // Create listening socket
        int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock < 0) {
            ESP_LOGE(TAG, "socket(): errno %d", errno);
            goto err;
        }

        // Allow reuse of local address
        int opt = 1;
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        // Set 5-second send/recv timeouts
        struct timeval t = { .tv_sec = 5, .tv_usec = 0 };
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &t, sizeof(t));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &t, sizeof(t));

        // Bind to all interfaces on the configured port
        struct sockaddr_in addr = {
            .sin_family      = AF_INET,
            .sin_port        = htons(bridge->tcp_port),
            .sin_addr.s_addr = htonl(INADDR_ANY),
        };
        if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            ESP_LOGE(TAG, "bind(): errno %d", errno);
            close(sock);
            goto err;
        }

        // Listen for one connection
        if (listen(sock, 1) < 0) {
            ESP_LOGE(TAG, "listen(): errno %d", errno);
            close(sock);
            goto err;
        }

        bridge->server_sock = sock;
        bridge->client_sock = -1;
#if defined(CONFIG_SSCTE_TLS_ENABLE)
        bridge->tls_handle = NULL;
#endif
    }

    return ESP_OK;

err:
    // Clean up on error
    tcp_cleanup();
    return ESP_FAIL;
}

/**
 * @brief Accept a new client for a bridge if none is connected
 *
 * Non-blocking function that checks for and accepts new connections
 * for the specified bridge. Uses select() with a short timeout to
 * poll the listening socket.
 *
 * @param bridge Pointer to the bridge to handle
 * @return true if a new client was accepted, false otherwise
 */
static bool tcp_handle_new_connection(uart_bridge_t *bridge)
{
    // Skip if already connected or socket not valid
    if (!bridge->enabled || bridge->server_sock < 0 ||
        bridge->client_sock >= 0
#if defined(CONFIG_SSCTE_TLS_ENABLE)
        || bridge->tls_handle != NULL
#endif
    ) {
        return false;
    }

    // Poll listening socket without blocking
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(bridge->server_sock, &fds);
    struct timeval to = {
        .tv_sec  = 0,
        .tv_usec = CONFIG_SELECT_TIMEOUT_MS * 1000
    };
    if (select(bridge->server_sock + 1, &fds, NULL, NULL, &to) != 1) {
        return false;
    }

    // Accept connection
    struct sockaddr_in caddr;
    socklen_t len = sizeof(caddr);
    int csock = accept(bridge->server_sock, (struct sockaddr*)&caddr, &len);
    if (csock < 0) {
        ESP_LOGW(TAG, "accept(): errno %d", errno);
        return false;
    }

    // Log client IP
    char client_ip[16];
    inet_ntoa_r(caddr.sin_addr, client_ip, sizeof(client_ip));
    ESP_LOGI(TAG, "Client connected to UART%d (port %d) from %s:%u",
             bridge->uart_port, bridge->tcp_port, client_ip, ntohs(caddr.sin_port));

    // Disable Nagle algorithm to reduce latency
    int flag = 1;
    setsockopt(csock, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));

#if defined(CONFIG_SSCTE_TLS_ENABLE)
    if (g_secure_mode) {
        // Set up TLS connection
        esp_tls_t *h = esp_tls_init();
        if (!h) {
            close(csock);
            ESP_LOGE(TAG, "Failed to initialize TLS");
            return false;
        }

        // Perform TLS handshake
        int ret = esp_tls_server_session_create(&g_esp_tls_cfg, csock, h);
        if (ret != 0) {
            ESP_LOGE(TAG, "TLS handshake failed for UART%d: %d", bridge->uart_port, ret);
            esp_tls_server_session_delete(h);
            close(csock);
            return false;
        }

        ESP_LOGI(TAG, "TLS handshake completed for UART%d", bridge->uart_port);
        bridge->tls_handle = h;
        bridge->client_sock = -1;  // Not used in TLS mode
    } else {
#endif
        // Plain TCP connection
        bridge->client_sock = csock;
#if defined(CONFIG_SSCTE_TLS_ENABLE)
    }
#endif

    return true;
}

/**
 * @brief Accept new clients for all bridges that don't have a connection
 *
 * Iterates through all active bridges and tries to accept new connections.
 */
void tcp_handle_new_connections(void)
{
    // Get all bridge instances
    uart_bridge_t *bridges = uart_manager_get_instances();
    int num_bridges = uart_manager_get_active_count();

    // Try to accept new connections for each bridge
    for (int i = 0; i < num_bridges; i++) {
        if (bridges[i].enabled) {
            tcp_handle_new_connection(&bridges[i]);
        }
    }
}

/**
 * @brief Receive data from either a TCP or TLS connection with non-blocking behavior
 *
 * Reads available data from the client connection (TCP or TLS).
 * Uses select() to check for data availability before reading.
 * Handles client disconnection and cleanup.
 *
 * @param bridge Pointer to the bridge structure
 * @param buffer Buffer to store received data (must not be NULL)
 * @param max_len Maximum number of bytes to read (must be > 0)
 *
 * @return Positive number of bytes read on success
 *         0 when no data available
 *         -1 on error, invalid parameters, or if client disconnected
 */
static int tcp_receive_data(uart_bridge_t *bridge, uint8_t *buffer, size_t max_len)
{
    // Validate input parameters and connection state
    if (!bridge->enabled || !buffer || max_len == 0 ||
        ((!g_secure_mode && bridge->client_sock < 0) ||
         (g_secure_mode
#if defined(CONFIG_SSCTE_TLS_ENABLE)
          && bridge->tls_handle == NULL
#endif
         ))) {
        return -1;
    }

    int sockfd;

#if defined(CONFIG_SSCTE_TLS_ENABLE)
    if (g_secure_mode) {
        // Get the socket descriptor from the TLS handle
        if (esp_tls_get_conn_sockfd(bridge->tls_handle, &sockfd) != ESP_OK) {
            ESP_LOGW(TAG, "Failed to get TLS socket descriptor");
            return -1;
        }
    } else {
#endif
        sockfd = bridge->client_sock;
#if defined(CONFIG_SSCTE_TLS_ENABLE)
    }
#endif

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
    int bytes_read = 0;

#if defined(CONFIG_SSCTE_TLS_ENABLE)
    if (g_secure_mode) {
        bytes_read = esp_tls_conn_read(bridge->tls_handle, buffer, max_len);
    } else {
#endif
        bytes_read = recv(bridge->client_sock, buffer, max_len, 0);
#if defined(CONFIG_SSCTE_TLS_ENABLE)
    }
#endif

    if (bytes_read <= 0) {
        if (bytes_read == 0) {
            ESP_LOGI(TAG, "Client disconnected from UART%d", bridge->uart_port);
        } else {
            ESP_LOGW(TAG, "%s read error for UART%d: %d",
                     g_secure_mode ? "TLS" : "TCP",
                     bridge->uart_port,
                     g_secure_mode ? bytes_read : errno);
        }
        cleanup_client(bridge);
        return -1;  // Signal disconnection to caller
    }

    return bytes_read;
}

/**
 * @brief Send data to the connected client
 *
 * Sends data to the client using either TLS or plain TCP.
 * Handles disconnection and cleanup if the send fails.
 *
 * @param bridge Pointer to the bridge structure
 * @param data Data to send (must not be NULL)
 * @param len Number of bytes to send (must be > 0)
 *
 * @return Number of bytes sent on success (will equal len if successful)
 *         -1 on error, invalid parameters, or if no client is connected
 */
static int tcp_send_data(uart_bridge_t *bridge, const uint8_t *data, size_t len)
{
    // Validate parameters and connection state
    if (!bridge->enabled || !data || len == 0 ||
        ((!g_secure_mode && bridge->client_sock < 0) ||
         (g_secure_mode
#if defined(CONFIG_SSCTE_TLS_ENABLE)
          && bridge->tls_handle == NULL
#endif
         ))) {
        return -1;
    }

    int ret = -1;

#if defined(CONFIG_SSCTE_TLS_ENABLE)
    if (g_secure_mode) {
        ret = esp_tls_conn_write(bridge->tls_handle, data, len);
    } else {
#endif
        ret = send(bridge->client_sock, data, len, 0);
#if defined(CONFIG_SSCTE_TLS_ENABLE)
    }
#endif

    if (ret <= 0) {
        ESP_LOGW(TAG, "%s write error for UART%d: %d",
                 g_secure_mode ? "TLS" : "TCP",
                 bridge->uart_port,
                 g_secure_mode ? ret : errno);
        cleanup_client(bridge);
        return -1;
    }
    return ret;
}

/**
 * @brief Check if a client is currently connected to a bridge
 *
 * Returns true if a client connection is active for the specified bridge.
 *
 * @param bridge Pointer to the bridge to check
 * @return true if a client is connected, false otherwise
 */
static bool tcp_is_client_connected(uart_bridge_t *bridge)
{
    if (!bridge->enabled) {
        return false;
    }

#if defined(CONFIG_SSCTE_TLS_ENABLE)
    if (g_secure_mode) {
        return bridge->tls_handle != NULL;
    }
#endif
    return bridge->client_sock >= 0;
}

/**
 * @brief Process data for a single bridge
 *
 * Handles bidirectional data transfer for a bridge:
 * 1. TCP to UART direction: reads from TCP and writes to UART
 * 2. UART to TCP direction: reads from UART and writes to TCP
 *
 * @param bridge Pointer to the bridge to process
 */
static void process_bridge_data(uart_bridge_t *bridge)
{
    // Skip if bridge is not enabled or no client is connected
    if (!bridge->enabled || !tcp_is_client_connected(bridge)) {
        return;
    }

    // Process TCP to UART direction
    int bytes_read = tcp_receive_data(bridge, bridge->tcp_buf, CONFIG_UART_BUF_SIZE);

    // If we received data, forward it to UART
    if (bytes_read > 0) {
        int bytes_written = uart_write_data(bridge, bridge->tcp_buf, bytes_read);
        if (bytes_written < 0) {
            ESP_LOGW(TAG, "UART%d write error: %d", bridge->uart_port, bytes_written);
        } else if (bytes_written < bytes_read) {
            ESP_LOGW(TAG, "UART%d write incomplete: %d of %d bytes",
                     bridge->uart_port, bytes_written, bytes_read);
        }
    }

    // Process UART to TCP direction
    size_t available_bytes;
    if (uart_get_available_bytes(bridge, &available_bytes) == ESP_OK && available_bytes > 0) {
        // Read data from UART
        int to_read = (available_bytes > CONFIG_UART_BUF_SIZE) ?
                       CONFIG_UART_BUF_SIZE : available_bytes;

        int uart_bytes = uart_read_data(bridge, bridge->uart_buf, to_read, CONFIG_UART_READ_TIMEOUT_MS);

        if (uart_bytes > 0) {
            // Forward data to TCP client
            int bytes_sent = tcp_send_data(bridge, bridge->uart_buf, uart_bytes);
            if (bytes_sent < uart_bytes) {
                ESP_LOGW(TAG, "TCP send incomplete for UART%d: %d of %d bytes sent",
                         bridge->uart_port, bytes_sent, uart_bytes);
            }
        }
    }
}

/**
 * @brief Process data for all active bridges
 *
 * Iterates through all active bridges and processes data for each one.
 * This is the main function that should be called regularly from the
 * application's main loop.
 */
void tcp_process_data(void)
{
    // Get all bridge instances
    uart_bridge_t *bridges = uart_manager_get_instances();
    int num_bridges = uart_manager_get_active_count();

    // Process data for each active bridge
    for (int i = 0; i < num_bridges; i++) {
        if (bridges[i].enabled) {
            process_bridge_data(&bridges[i]);
        }
    }
}
