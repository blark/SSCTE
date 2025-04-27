#pragma once

#include "esp_err.h"
#include <stdbool.h>

/**
 * @brief Initialize WiFi in station mode
 *
 * @return ESP_OK on success, error code otherwise
 */
esp_err_t wifi_init(void);

/**
 * @brief Wait for WiFi connection with timeout
 *
 * @param timeout_seconds Maximum time to wait in seconds
 * @return true if connected, false if timeout reached
 */
bool wifi_wait_connected(int timeout_seconds);

/**
 * @brief Get current WiFi connection status
 *
 * @return true if connected, false otherwise
 */
bool wifi_is_connected(void);

/**
 * @brief Cleanup WiFi resources
 */
void wifi_cleanup(void);
