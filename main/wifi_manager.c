#include "wifi_manager.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include <string.h>
#include "inttypes.h"

static const char *TAG = "WiFiManager";
static bool wifi_connected = false;
static TaskHandle_t reconnect_task_handle = NULL;

// Forward declarations for internal functions
static void wifi_event_handler(void* arg, esp_event_base_t event_base,
                              int32_t event_id, void* event_data);
static void wifi_reconnect_task(void* pvParameters);

/**
 * @brief WiFi event handler for connection management
 */
static void wifi_event_handler(void* arg, esp_event_base_t event_base,
                              int32_t event_id, void* event_data) {
    if (event_base == WIFI_EVENT) {
        if (event_id == WIFI_EVENT_STA_START) {
            ESP_LOGI(TAG, "WiFi started, connecting to AP");
            esp_wifi_connect();
        } else if (event_id == WIFI_EVENT_STA_DISCONNECTED) {
            if (wifi_connected) {
                wifi_connected = false;
                ESP_LOGW(TAG, "WiFi disconnected");
            }

            if (reconnect_task_handle != NULL) {
                xTaskNotifyGive(reconnect_task_handle);
            }
        }
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
        if (event != NULL) {
            ESP_LOGI(TAG, "Connected to WiFi, IP: " IPSTR, IP2STR(&event->ip_info.ip));
            wifi_connected = true;
        }
    }
}

/**
 * @brief Task for handling WiFi reconnection with backoff
 */
static void wifi_reconnect_task(void* pvParameters) {
    while (1) {
        ulTaskNotifyTake(pdTRUE, portMAX_DELAY);

        for (int i = 0; i < CONFIG_WIFI_MAX_CONNECT_RETRIES && !wifi_connected; i++) {
            uint32_t delay = CONFIG_WIFI_RECONNECT_BASE_DELAY_MS << i;
            if (delay > CONFIG_WIFI_RECONNECT_MAX_DELAY_MS) {
                delay = CONFIG_WIFI_RECONNECT_MAX_DELAY_MS;
            }

            ESP_LOGI(TAG, "Attempting reconnect in %" PRIu32 " ms (attempt %d/%d)",
                     delay, i + 1, CONFIG_WIFI_MAX_CONNECT_RETRIES);

            vTaskDelay(pdMS_TO_TICKS(delay));

            if (!wifi_connected) {
                esp_wifi_connect();
            } else {
                break;
            }
        }

        if (!wifi_connected) {
            ESP_LOGE(TAG, "Failed to reconnect after %d attempts", CONFIG_WIFI_MAX_CONNECT_RETRIES);
        }
    }
}

esp_err_t wifi_init(void) {
    esp_err_t ret;

    ESP_LOGI(TAG, "Initializing WiFi");
    ret = esp_netif_init();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to initialize TCP/IP stack");
        return ret;
    }

    ret = esp_event_loop_create_default();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to create event loop");
        return ret;
    }

    esp_netif_create_default_wifi_sta();

    wifi_init_config_t wifi_config = WIFI_INIT_CONFIG_DEFAULT();
    ret = esp_wifi_init(&wifi_config);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to initialize WiFi");
        return ret;
    }

    ret = esp_event_handler_instance_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, NULL);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to register WiFi event handler");
        return ret;
    }

    ret = esp_event_handler_instance_register(
        IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL, NULL);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to register IP event handler");
        return ret;
    }

    wifi_config_t sta_config = {
        .sta = {
            .ssid     = CONFIG_WIFI_SSID,
            .password = CONFIG_WIFI_PASSWORD,
            .threshold.authmode = WIFI_AUTH_WPA2_PSK,
        },
    };

    ret = esp_wifi_set_mode(WIFI_MODE_STA);
    if (ret != ESP_OK) return ret;

    ret = esp_wifi_set_config(WIFI_IF_STA, &sta_config);
    if (ret != ESP_OK) return ret;

    // Create WiFi reconnection task
    xTaskCreate(wifi_reconnect_task, "wifi_reconnect", 2048, NULL, 5, &reconnect_task_handle);

    ret = esp_wifi_start();
    if (ret != ESP_OK) return ret;

    ESP_LOGI(TAG, "WiFi initialization completed");
    return ESP_OK;
}

bool wifi_wait_connected(int timeout_seconds) {
    ESP_LOGI(TAG, "Waiting for WiFi connection");

    for (int i = 0; i < timeout_seconds && !wifi_connected; i++) {
        ESP_LOGI(TAG, "Waiting for WiFi... (%d/%d)", i + 1, timeout_seconds);
        vTaskDelay(pdMS_TO_TICKS(1000));
    }

    return wifi_connected;
}

bool wifi_is_connected(void) {
    return wifi_connected;
}

void wifi_cleanup(void) {
    esp_wifi_disconnect();
    esp_wifi_stop();
    esp_wifi_deinit();
    ESP_LOGI(TAG, "WiFi cleanup complete");
}
