/**
 * @file network_ethernet.c
 * @brief Ethernet network backend for ESP32-P4
 *
 * Implements Ethernet connectivity using the ESP32-P4's internal MAC.
 * Handles PHY initialization, link management, and DHCP.
 * This backend is selected when CONFIG_NETWORK_INTERFACE_ETHERNET is set.
 */

#include "network_manager.h"
#include "esp_eth.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "EthernetBackend";
static bool eth_connected = false;
static esp_eth_handle_t eth_handle = NULL;

/* Forward declaration for event handler */
static void eth_event_handler(void* arg, esp_event_base_t event_base,
                              int32_t event_id, void* event_data);

/**
 * @brief Ethernet event handler for connection management
 */
static void eth_event_handler(void* arg, esp_event_base_t event_base,
                              int32_t event_id, void* event_data) {
    if (event_base == ETH_EVENT) {
        switch (event_id) {
            case ETHERNET_EVENT_CONNECTED:
                ESP_LOGI(TAG, "Ethernet link up");
                break;
            case ETHERNET_EVENT_DISCONNECTED:
                if (eth_connected) {
                    eth_connected = false;
                    ESP_LOGW(TAG, "Ethernet link down");
                }
                break;
            case ETHERNET_EVENT_START:
                ESP_LOGI(TAG, "Ethernet started");
                break;
            case ETHERNET_EVENT_STOP:
                ESP_LOGI(TAG, "Ethernet stopped");
                break;
            default:
                break;
        }
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_ETH_GOT_IP) {
        ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
        if (event != NULL) {
            ESP_LOGI(TAG, "Ethernet got IP: " IPSTR, IP2STR(&event->ip_info.ip));
            ESP_LOGI(TAG, "Gateway: " IPSTR, IP2STR(&event->ip_info.gw));
            ESP_LOGI(TAG, "Netmask: " IPSTR, IP2STR(&event->ip_info.netmask));
            eth_connected = true;
        }
    }
}

/**
 * @brief Initialize Ethernet backend
 * Called by network_manager after common TCP/IP stack initialization
 */
esp_err_t network_backend_init(void) {
    esp_err_t ret;

    ESP_LOGI(TAG, "Initializing Ethernet backend for ESP32-P4");

    // Create default Ethernet network interface
    esp_netif_config_t netif_cfg = ESP_NETIF_DEFAULT_ETH();
    esp_netif_t *eth_netif = esp_netif_new(&netif_cfg);
    if (eth_netif == NULL) {
        ESP_LOGE(TAG, "Failed to create Ethernet netif");
        return ESP_FAIL;
    }

    // Configure Ethernet MAC
    eth_mac_config_t mac_config = ETH_MAC_DEFAULT_CONFIG();

    // Configure Ethernet PHY based on Kconfig selection
    eth_phy_config_t phy_config = ETH_PHY_DEFAULT_CONFIG();
    phy_config.phy_addr = CONFIG_ETH_PHY_ADDR;
    phy_config.reset_gpio_num = CONFIG_ETH_PHY_RST_GPIO;

    // Create MAC and PHY instances
    esp_eth_mac_t *mac = NULL;
    esp_eth_phy_t *phy = NULL;

#if CONFIG_ETH_USE_ESP32_EMAC
    // ESP32-P4 internal MAC - use default config which sets all required fields
    // including clock_config_out_in which is essential for ESP32-P4
    eth_esp32_emac_config_t esp32_emac_config = ETH_ESP32_EMAC_DEFAULT_CONFIG();

    // Note: ESP32-P4 default config uses these RMII pins (matching ESP32-P4-Module-DEV-KIT):
    // TX_EN=49, TXD0=34, TXD1=35, CRS_DV=28, RXD0=29, RXD1=30, REF_CLK=50
    // SMI: MDC=31, MDIO=52
    // These match our Kconfig defaults, so no override needed unless custom board

    mac = esp_eth_mac_new_esp32(&esp32_emac_config, &mac_config);
#else
    #error "No Ethernet MAC selected"
#endif

    if (mac == NULL) {
        ESP_LOGE(TAG, "Failed to create Ethernet MAC");
        return ESP_FAIL;
    }

    // Create PHY based on configured type
#if CONFIG_ETH_PHY_IP101
    phy = esp_eth_phy_new_ip101(&phy_config);
#elif CONFIG_ETH_PHY_RTL8201
    phy = esp_eth_phy_new_rtl8201(&phy_config);
#elif CONFIG_ETH_PHY_LAN87XX
    phy = esp_eth_phy_new_lan87xx(&phy_config);
#elif CONFIG_ETH_PHY_DP83848
    phy = esp_eth_phy_new_dp83848(&phy_config);
#elif CONFIG_ETH_PHY_KSZ80XX
    phy = esp_eth_phy_new_ksz80xx(&phy_config);
#else
    #error "No Ethernet PHY selected"
#endif

    if (phy == NULL) {
        ESP_LOGE(TAG, "Failed to create Ethernet PHY");
        if (mac) {
            mac->del(mac);
        }
        return ESP_FAIL;
    }

    // Install Ethernet driver
    esp_eth_config_t eth_config = ETH_DEFAULT_CONFIG(mac, phy);
    ret = esp_eth_driver_install(&eth_config, &eth_handle);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to install Ethernet driver: %s", esp_err_to_name(ret));
        if (phy) {
            phy->del(phy);
        }
        if (mac) {
            mac->del(mac);
        }
        return ret;
    }

    // Attach Ethernet driver to TCP/IP stack
    ret = esp_netif_attach(eth_netif, esp_eth_new_netif_glue(eth_handle));
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to attach Ethernet to netif: %s", esp_err_to_name(ret));
        esp_eth_driver_uninstall(eth_handle);
        return ret;
    }

    // Register Ethernet event handler
    ret = esp_event_handler_instance_register(
        ETH_EVENT, ESP_EVENT_ANY_ID, &eth_event_handler, NULL, NULL);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to register Ethernet event handler: %s", esp_err_to_name(ret));
        esp_eth_driver_uninstall(eth_handle);
        return ret;
    }

    // Register IP event handler
    ret = esp_event_handler_instance_register(
        IP_EVENT, IP_EVENT_ETH_GOT_IP, &eth_event_handler, NULL, NULL);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to register IP event handler: %s", esp_err_to_name(ret));
        esp_eth_driver_uninstall(eth_handle);
        return ret;
    }

    // Start Ethernet driver
    ret = esp_eth_start(eth_handle);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to start Ethernet: %s", esp_err_to_name(ret));
        esp_eth_driver_uninstall(eth_handle);
        return ret;
    }

    ESP_LOGI(TAG, "Ethernet backend initialization completed");
    return ESP_OK;
}

/**
 * @brief Wait for Ethernet connection with timeout
 */
bool network_backend_wait_connected(int timeout_seconds) {
    ESP_LOGI(TAG, "Waiting for Ethernet connection (cable + DHCP)");

    for (int i = 0; i < timeout_seconds && !eth_connected; i++) {
        ESP_LOGI(TAG, "Waiting for Ethernet... (%d/%d)", i + 1, timeout_seconds);
        vTaskDelay(pdMS_TO_TICKS(1000));
    }

    return eth_connected;
}

/**
 * @brief Get Ethernet connection status
 */
bool network_backend_is_connected(void) {
    return eth_connected;
}

/**
 * @brief Cleanup Ethernet resources
 */
void network_backend_cleanup(void) {
    ESP_LOGI(TAG, "Cleaning up Ethernet backend");

    if (eth_handle != NULL) {
        esp_eth_stop(eth_handle);
        esp_eth_driver_uninstall(eth_handle);
        eth_handle = NULL;
    }

    ESP_LOGI(TAG, "Ethernet backend cleanup complete");
}
