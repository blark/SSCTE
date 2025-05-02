/**
 * @file uart_manager.h
 * @brief Multi-UART to TCP bridge manager
 *
 * Manages multiple UART connections to TCP/IP bridges.
 * Each UART (except UART0 which is reserved for debug) can be connected
 * to a TCP port, allowing for multiple serial devices to be accessible
 * over the network simultaneously.
 */

#pragma once

#include "esp_err.h"
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#if defined(CONFIG_SSCTE_TLS_ENABLE)
#include "esp_tls.h"
#endif

/**
 * @brief Structure representing a single UART-TCP bridge
 */
typedef struct {
    // Configuration
    int uart_port;         // UART number (1, 2, etc.)
    int tx_pin;            // TX GPIO pin
    int rx_pin;            // RX GPIO pin
    int baud_rate;         // UART baud rate
    int tcp_port;          // TCP port number
    bool enabled;          // Whether this bridge is active

    // Buffers
    uint8_t *uart_buf;     // Buffer for UART → TCP direction
    uint8_t *tcp_buf;      // Buffer for TCP → UART direction

    // TCP server
    int server_sock;       // Listening socket
    int client_sock;       // Connected client socket (-1 if none)

    // TLS support (if globally enabled in the build)
#if defined(CONFIG_SSCTE_TLS_ENABLE)
    esp_tls_t *tls_handle; // TLS connection handle (NULL if not using TLS)
#endif
} uart_bridge_t;

/**
 * @brief Initialize all configured UART bridges
 *
 * Initializes UART bridges based on Kconfig settings.
 * The number of bridges is determined by CONFIG_ENABLE_UART_BRIDGES.
 *
 * @return ESP_OK on success, error code on failure
 */
esp_err_t uart_manager_init(void);

/**
 * @brief Process data for all active bridges
 *
 * Checks for and handles data transfer in both directions
 * for all enabled UART bridges. Should be called regularly
 * from the main loop.
 */
void uart_manager_process(void);

/**
 * @brief Handle new TCP connections for all bridges
 *
 * Checks for and accepts new TCP connections for all
 * enabled UART bridges. Should be called regularly
 * from the main loop.
 */
void uart_manager_handle_connections(void);

/**
 * @brief Clean up all bridge resources
 *
 * Closes all sockets, disables UARTs, and frees allocated memory.
 */
void uart_manager_cleanup(void);

/**
 * @brief Get number of active bridges
 *
 * @return Number of successfully initialized bridges
 */
int uart_manager_get_active_count(void);

/**
 * @brief Get the array of bridge instances
 *
 * @return Pointer to the array of bridge instances
 */
uart_bridge_t* uart_manager_get_instances(void);

/**
 * @brief Read data from a UART bridge.
 *
 * Attempts to read up to max_len bytes from the UART associated with the given bridge.
 * Blocks for up to timeout_ms milliseconds if no data is immediately available.
 *
 * @param bridge    Pointer to the UART bridge instance.
 * @param buffer    Buffer to store the received data.
 * @param max_len   Maximum number of bytes to read.
 * @param timeout_ms Timeout in milliseconds to wait for data.
 * @return Number of bytes read on success, or -1 on error.
 */
int uart_read_data(uart_bridge_t *bridge, uint8_t *buffer, size_t max_len, uint32_t timeout_ms);

/**
 * @brief Write data to a UART bridge.
 *
 * Sends the specified data to the UART associated with the given bridge.
 *
 * @param bridge    Pointer to the UART bridge instance.
 * @param data      Pointer to the data to send.
 * @param len       Length of the data to send, in bytes.
 * @return Number of bytes written on success, or -1 on error.
 */
int uart_write_data(uart_bridge_t *bridge, const uint8_t *data, size_t len);

/**
 * @brief Get the number of bytes available to read from a UART bridge.
 *
 * Queries how many bytes are currently buffered and available for immediate read
 * from the UART associated with the given bridge.
 *
 * @param bridge     Pointer to the UART bridge instance.
 * @param available  Pointer to store the number of available bytes.
 * @return ESP_OK on success, or an error code on failure.
 */
esp_err_t uart_get_available_bytes(uart_bridge_t *bridge, size_t *available);

