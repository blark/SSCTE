/**
 * @file tcp_server.h
 * @brief TCP server with optional mTLS support for multiple UART bridges
 *
 * Provides an interface for TCP servers that can operate in both
 * secure (TLS) and non-secure modes. Supports multiple TCP servers,
 * each connected to a different UART bridge. In secure mode, supports
 * optional client certificate verification (mutual TLS).
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include "esp_err.h"
#include "uart_manager.h" // For uart_bridge_t type

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief TLS configuration structure
 *
 * Contains PEM-format strings for certificates and keys.
 * For server operation, server_cert_pem and server_key_pem are required.
 * For mutual TLS, ca_cert_pem and verify_client must also be set.
 */
typedef struct {
    /** CA certificate for client verification (NULL for no client auth) */
    const char *ca_cert_pem;
    /** Server certificate (required for TLS) */
    const char *server_cert_pem;
    /** Server private key (required for TLS) */
    const char *server_key_pem;
    /** Whether to verify client certificates */
    bool verify_client;
} tcp_server_tls_config_t;

/**
 * @brief Initialize TCP servers for all active UART bridges
 *
 * Sets up listening sockets on the configured ports for each active bridge.
 * When tls_config is provided, configures all servers for secure connections.
 *
 * For TLS mode, this function makes internal copies of the certificate strings,
 * so caller may free their buffers after this call returns.
 *
 * @param tls_config  Pointer to TLS config (NULL for plain TCP mode).
 *                    Must contain valid certificate and key for TLS mode.
 * @return ESP_OK on success, ESP_FAIL on any initialization error.
 */
esp_err_t tcp_server_init(const tcp_server_tls_config_t *tls_config);

/**
 * @brief Accept new clients for all bridges that don't have a connection
 *
 * Non-blocking function that checks for and accepts new connections
 * for all active bridges without a current client.
 * Uses select() with a short timeout to poll the listening sockets.
 */
void tcp_handle_new_connections(void);

/**
 * @brief Process data for all bridges with active clients
 * 
 * Handles data transfer between UART and TCP for all active bridges.
 * Reads from UART and sends to TCP, and vice versa.
 */
void tcp_process_data(void);

/**
 * @brief Shut down all TCP servers and free resources
 *
 * Disconnects any connected clients, closes all listening sockets,
 * and releases all allocated memory including TLS certificates.
 * After calling this function, the servers must be reinitialized
 * before accepting new connections.
 */
void tcp_cleanup(void);

#ifdef __cplusplus
}
#endif
