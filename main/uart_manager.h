#pragma once

#include "esp_err.h"
#include <stdint.h>
#include <stddef.h>

/**
 * @brief Initialize UART with specified parameters
 * 
 * @return ESP_OK on success, error code otherwise
 */
esp_err_t uart_init(void);

/**
 * @brief Read data from UART if available
 * 
 * @param buffer Buffer to store read data
 * @param max_len Maximum length to read
 * @param timeout_ms Timeout in milliseconds
 * @return Number of bytes read, or -1 on error
 */
int uart_read_data(uint8_t *buffer, size_t max_len, uint32_t timeout_ms);

/**
 * @brief Write data to UART
 * 
 * @param data Data to write
 * @param len Length of data to write
 * @return Number of bytes written, or -1 on error
 */
int uart_write_data(const uint8_t *data, size_t len);

/**
 * @brief Get number of bytes available in UART RX buffer
 * 
 * @param available Pointer to store the number of available bytes
 * @return ESP_OK on success, error code otherwise
 */
esp_err_t uart_get_available_bytes(size_t *available);

/**
 * @brief Cleanup UART resources
 */
void uart_cleanup(void);
