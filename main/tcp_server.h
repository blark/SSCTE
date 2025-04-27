/**
 * @file tcp_server.h
 * @brief TCP server with optional mTLS support
 *
 * Provides an interface for a TCP server that can operate in both
 * secure (TLS) and non-secure modes. In secure mode, supports
 * optional client certificate verification (mutual TLS).
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include "esp_err.h"

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
 * @brief Initialize TCP server, with optional TLS support
 *
 * Sets up a listening socket on the configured port (CONFIG_BRIDGE_PORT).
 * When tls_config is provided, configures the server for secure connections.
 *
 * For TLS mode, this function makes internal copies of the certificate strings,
 * so caller may free their buffers after this call returns.
 *
 * Note: The server allows only one client at a time.
 *
 * @param tls_config  Pointer to TLS config (NULL for plain TCP mode).
 *                    Must contain valid certificate and key for TLS mode.
 * @return ESP_OK on success, ESP_FAIL on any initialization error.
 */
esp_err_t tcp_server_init(const tcp_server_tls_config_t *tls_config);

/**
 * @brief Accept a new client if none is connected
 *
 * Non-blocking function that checks for and accepts new connections.
 * Uses select() with a short timeout to poll the listening socket.
 *
 * Does nothing if a client is already connected.
 *
 * @return true if a new client was accepted, false otherwise.
 */
bool tcp_handle_new_connection(void);

/**
 * @brief Receive data from the connected client
 *
 * Non-blocking read from the client connection (if any).
 * In non-secure mode, polls the socket with select() before reading.
 * In secure mode, calls esp_tls_conn_read() directly.
 *
 * If the client disconnects or an error occurs, cleans up the connection.
 *
 * @param buffer   Buffer to fill with received data (must not be NULL).
 * @param max_len  Maximum number of bytes to read (must be > 0).
 * 
 * @return Positive number of bytes read on success.
 *         0 when no data available (non-secure mode) or client disconnected.
 *         -1 on error or invalid parameters.
 */
int tcp_receive_data(uint8_t *buffer, size_t max_len);

/**
 * @brief Send data to the connected client
 *
 * Sends data over the current connection, whether TLS or plain TCP.
 * On any error or if no client is connected, returns -1.
 * 
 * Note: This is a blocking call that waits until all data is sent or an error occurs.
 * Partial sends are not handled - either all data is sent or -1 is returned.
 *
 * @param data  Pointer to data to send (must not be NULL).
 * @param len   Number of bytes to send (must be > 0).
 * 
 * @return Number of bytes sent on success (will equal len if successful).
 *         -1 on error, invalid parameters, or if no client is connected.
 */
int tcp_send_data(const uint8_t *data, size_t len);

/**
 * @brief Check if a client is currently connected
 *
 * Fast check to determine if a client connection is active.
 * This only indicates connection status and doesn't guarantee
 * the connection is still viable (may be closed by peer).
 *
 * @return true if a client appears to be connected, false otherwise.
 */
bool tcp_is_client_connected(void);

/**
 * @brief Shut down server and free all resources
 *
 * Disconnects any connected client, closes the listening socket,
 * and releases all allocated memory including TLS certificates.
 * After calling this function, the server must be reinitialized
 * before accepting new connections.
 */
void tcp_cleanup(void);

#ifdef __cplusplus
}
#endif
