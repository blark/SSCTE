/**
 * @file network_manager.c
 * @brief Network abstraction layer for WiFi or Ethernet
 *
 * Provides unified network interface regardless of backend (WiFi/Ethernet).
 * The backend is selected at compile-time via menuconfig.
 * Common initialization (TCP/IP stack, event loop) is done here,
 * backend-specific setup is delegated to network_wifi.c or network_ethernet.c.
 */

#include "network_manager.h"
#include "esp_netif.h"
#include "esp_event.h"
#include "esp_log.h"

static const char *TAG = "NetworkManager";

/* Backend-specific functions (implemented in network_wifi.c or network_ethernet.c) */
extern esp_err_t network_backend_init(void);
extern bool network_backend_wait_connected(int timeout_seconds);
extern bool network_backend_is_connected(void);
extern void network_backend_cleanup(void);

esp_err_t network_init(void) {
    esp_err_t ret;

#if defined(CONFIG_NETWORK_INTERFACE_WIFI)
    ESP_LOGI(TAG, "Initializing network (WiFi mode)");
#elif defined(CONFIG_NETWORK_INTERFACE_ETHERNET)
    ESP_LOGI(TAG, "Initializing network (Ethernet mode)");
#else
    #error "No network interface selected in menuconfig"
#endif

    // Initialize TCP/IP stack (common for both WiFi and Ethernet)
    ret = esp_netif_init();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to initialize TCP/IP stack: %s", esp_err_to_name(ret));
        return ret;
    }

    // Create default event loop (common for both WiFi and Ethernet)
    ret = esp_event_loop_create_default();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to create event loop: %s", esp_err_to_name(ret));
        return ret;
    }

    // Call backend-specific initialization
    ret = network_backend_init();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Backend initialization failed: %s", esp_err_to_name(ret));
        return ret;
    }

    ESP_LOGI(TAG, "Network initialization completed");
    return ESP_OK;
}

bool network_wait_connected(int timeout_seconds) {
    return network_backend_wait_connected(timeout_seconds);
}

bool network_is_connected(void) {
    return network_backend_is_connected();
}

void network_cleanup(void) {
    network_backend_cleanup();
    ESP_LOGI(TAG, "Network cleanup complete");
}
