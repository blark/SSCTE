#pragma once

#include "esp_err.h"
#include <stdbool.h>

/**
 * @brief Initialize network interface (WiFi or Ethernet based on build config)
 *
 * @return ESP_OK on success, error code otherwise
 */
esp_err_t network_init(void);

/**
 * @brief Wait for network connection with timeout
 *
 * @param timeout_seconds Maximum time to wait in seconds
 * @return true if connected, false if timeout reached
 */
bool network_wait_connected(int timeout_seconds);

/**
 * @brief Get current network connection status
 *
 * @return true if connected, false otherwise
 */
bool network_is_connected(void);

/**
 * @brief Cleanup network resources
 */
void network_cleanup(void);
