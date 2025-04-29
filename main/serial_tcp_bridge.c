#include <stdio.h>  // Needed for fopen(), FILE
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "string.h"
#include "sdkconfig.h"
#include "wifi_manager.h"
#include "uart_manager.h"
#include "tcp_server.h"
#include "esp_spiffs.h"

/**
 * @file serial_tcp_bridge.c
 * @brief Multi-UART to TCP bridge for ESP32
 *
 * Creates bridges between TCP sockets and UART peripherals, allowing
 * bidirectional communication between connected TCP clients and multiple
 * UART devices simultaneously. Each UART is connected to its own TCP port.
 */

/* ----------------- Global variables ----------------- */
static const char *TAG = "SerialTCP";    // Logging tag

/* ----------------- Function prototypes ----------------- */
static void cleanup_resources(void);
#if defined(CONFIG_TLS_ENABLE)
static char* load_cert_file(const char* file_path);
static void free_tls_files(tcp_server_tls_config_t *cfg);
#endif

/**
 * @brief Load certificate or key file from filesystem
 *
 * @param file_path Path to the certificate or key file
 * @return Pointer to null-terminated string with file contents, or NULL on error
 *         Caller must free this memory
 */
#if defined(CONFIG_TLS_ENABLE)
static char* load_cert_file(const char* file_path) {
    FILE* file = fopen(file_path, "r");
    if (file == NULL) {
        ESP_LOGE(TAG, "Failed to open %s", file_path);
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    char* buffer = malloc(file_size + 1);
    if (buffer == NULL) {
        ESP_LOGE(TAG, "Failed to allocate memory for certificate");
        fclose(file);
        return NULL;
    }

    size_t read_size = fread(buffer, 1, file_size, file);
    fclose(file);

    if (read_size != file_size) {
        ESP_LOGE(TAG, "Failed to read certificate file");
        free(buffer);
        return NULL;
    }

    buffer[file_size] = '\0';
    return buffer;
}

static void free_tls_files(tcp_server_tls_config_t *cfg) {
    if (cfg->server_cert_pem) free((void*)cfg->server_cert_pem);
    if (cfg->server_key_pem)  free((void*)cfg->server_key_pem);
    if (cfg->ca_cert_pem)     free((void*)cfg->ca_cert_pem);
    memset(cfg, 0, sizeof(*cfg));
}
#endif

/**
 * @brief Clean up all resources before exit
 *
 * Closes sockets, stops UART drivers, and deinitializes WiFi
 */
static void cleanup_resources(void) {
    ESP_LOGI(TAG, "Cleaning up resources");

    tcp_cleanup();
    uart_manager_cleanup();
    wifi_cleanup();

#if defined(CONFIG_TLS_ENABLE)
    esp_vfs_spiffs_unregister("spiffs");
#endif

    ESP_LOGI(TAG, "Cleanup complete");
}

/**
 * @brief Application entry point
 */
void app_main(void) {
    esp_log_level_set("wifi", ESP_LOG_WARN);
    esp_log_level_set("esp_netif_handlers", ESP_LOG_WARN);
    esp_log_level_set("system_api", ESP_LOG_WARN);

    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_LOGW(TAG, "Erasing NVS flash");
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    esp_register_shutdown_handler(cleanup_resources);

    ESP_ERROR_CHECK(wifi_init());

    if (!wifi_wait_connected(30)) {
        ESP_LOGE(TAG, "WiFi connection failed, aborting");
        return;
    }

#if defined(CONFIG_TLS_ENABLE)
    esp_vfs_spiffs_conf_t spiffs_conf = {
        .base_path = "/spiffs",
        .partition_label = "spiffs",
        .max_files = 5,
        .format_if_mount_failed = true
    };

    ret = esp_vfs_spiffs_register(&spiffs_conf);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to mount SPIFFS (%s)", esp_err_to_name(ret));
        return;
    }
#endif

    ESP_LOGI(TAG, "Initializing UART bridges");
    if (uart_manager_init() != ESP_OK) {
        ESP_LOGE(TAG, "Failed to initialize UART manager, aborting");
        return;
    }

    int active_bridges = uart_manager_get_active_count();
    ESP_LOGI(TAG, "Successfully initialized %d UART bridges", active_bridges);

#if defined(CONFIG_TLS_ENABLE)
    tcp_server_tls_config_t tls_config = {0};
    bool cert_loaded = false;

    tls_config.server_cert_pem = load_cert_file(CONFIG_TLS_SERVER_CERT_PATH);
    if (!tls_config.server_cert_pem) {
        ESP_LOGE(TAG, "Failed to load server certificate");
        goto cleanup;
    }

    tls_config.server_key_pem = load_cert_file(CONFIG_TLS_SERVER_KEY_PATH);
    if (!tls_config.server_key_pem) {
        ESP_LOGE(TAG, "Failed to load server key");
        goto cleanup;
    }

#ifdef CONFIG_TLS_CLIENT_VERIFY
    tls_config.verify_client = true;
    tls_config.ca_cert_pem = load_cert_file(CONFIG_TLS_CA_CERT_PATH);
    if (!tls_config.ca_cert_pem) {
        ESP_LOGE(TAG, "Failed to load CA certificate");
        goto cleanup;
    }
    ESP_LOGI(TAG, "TLS enabled with client verification");
#else
    tls_config.verify_client = false;
    tls_config.ca_cert_pem = NULL;
    ESP_LOGI(TAG, "TLS enabled without client verification");
#endif

    cert_loaded = true;

    if (tcp_server_init(&tls_config) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to initialize TLS servers, aborting");
        goto cleanup;
    }
#else
    if (tcp_server_init(NULL) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to initialize TCP servers, aborting");
        return;
    }
    ESP_LOGI(TAG, "TCP servers initialized (TLS disabled)");
#endif

    ESP_LOGI(TAG, "Startup complete, entering main loop");
    while (1) {
        tcp_handle_new_connections();
        tcp_process_data();
        vTaskDelay(pdMS_TO_TICKS(CONFIG_TASK_DELAY_MS));
    }

#if defined(CONFIG_TLS_ENABLE)
cleanup:
    if (cert_loaded) {
        free_tls_files(&tls_config);
    }
    esp_vfs_spiffs_unregister(spiffs_conf.partition_label);
    return;
#endif
}

