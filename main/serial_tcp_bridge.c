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
 * @brief TCP to UART bridge for ESP32
 *
 * Creates a bridge between a TCP socket and UART peripheral, allowing
 * bidirectional communication between connected TCP clients and UART devices.
 */

/* ----------------- Global variables ----------------- */
static const char *TAG = "SerialTCP";    // Logging tag

// Module-scope buffers (safer than large stack allocations)
static uint8_t tcp_buf[CONFIG_DATA_BUF_SIZE];
static uint8_t uart_buf[CONFIG_DATA_BUF_SIZE];

/* ----------------- Function prototypes ----------------- */
static void cleanup_resources(void);
static void process_data(void);
#ifdef CONFIG_TLS_ENABLE
static char* load_cert_file(const char* file_path);
#endif

/**
 * @brief Load certificate or key file from filesystem
 *
 * @param file_path Path to the certificate or key file
 * @return Pointer to null-terminated string with file contents, or NULL on error
 *         Caller must free this memory
 */
#ifdef CONFIG_TLS_ENABLE
static char* load_cert_file(const char* file_path) {
    FILE* file = fopen(file_path, "r");
    if (file == NULL) {
        ESP_LOGE(TAG, "Failed to open %s", file_path);
        return NULL;
    }

    // Get file size
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    // Allocate memory for file contents plus null terminator
    char* buffer = malloc(file_size + 1);
    if (buffer == NULL) {
        ESP_LOGE(TAG, "Failed to allocate memory for certificate");
        fclose(file);
        return NULL;
    }

    // Read the file
    size_t read_size = fread(buffer, 1, file_size, file);
    fclose(file);

    if (read_size != file_size) {
        ESP_LOGE(TAG, "Failed to read certificate file");
        free(buffer);
        return NULL;
    }

    // Null terminate the buffer
    buffer[file_size] = '\0';
    return buffer;
}
#endif

/**
 * @brief Clean up all resources before exit
 *
 * Closes sockets, stops UART driver, and deinitializes WiFi
 */
static void cleanup_resources(void) {
    ESP_LOGI(TAG, "Cleaning up resources");

    // Clean up all resources using the appropriate managers
    tcp_cleanup();
    uart_cleanup();
    wifi_cleanup();

    ESP_LOGI(TAG, "Cleanup complete");
}

/**
 * @brief Process data in both directions between TCP and UART
 */
static void process_data(void) {
    // Process TCP to UART direction
    if (tcp_is_client_connected()) {
        // Try to receive data from TCP client
        int bytes_read = tcp_receive_data(tcp_buf, sizeof(tcp_buf));

        // If we received data, forward it to UART
        if (bytes_read > 0) {
            int bytes_written = uart_write_data(tcp_buf, bytes_read);
            if (bytes_written < 0) {
                ESP_LOGW(TAG, "UART write error: %d", bytes_written);
            } else if (bytes_written < bytes_read) {
                ESP_LOGW(TAG, "UART write incomplete: %d of %d bytes", bytes_written, bytes_read);
            }
        }

        // Process UART to TCP direction
        size_t available_bytes;
        if (uart_get_available_bytes(&available_bytes) == ESP_OK && available_bytes > 0) {
            // Read data from UART
            int to_read = (available_bytes > sizeof(uart_buf)) ? sizeof(uart_buf) : available_bytes;
            int uart_bytes = uart_read_data(uart_buf, to_read, CONFIG_UART_READ_TIMEOUT_MS);

            if (uart_bytes > 0) {
                // Forward data to TCP client
                int bytes_sent = tcp_send_data(uart_buf, uart_bytes);
                if (bytes_sent < uart_bytes) {
                    ESP_LOGW(TAG, "TCP send incomplete: %d of %d bytes sent", bytes_sent, uart_bytes);
                }
            }
        }
    }
}

/**
 * @brief Application entry point
 */
void app_main(void) {
    // Set log levels - suppress unwanted components
    esp_log_level_set("wifi", ESP_LOG_WARN);      // Only show WiFi warnings and errors
    esp_log_level_set("esp_netif_handlers", ESP_LOG_WARN); // Suppress network interface info
    esp_log_level_set("system_api", ESP_LOG_WARN);  // Suppress system API info messages

    // Initialize NVS (required for WiFi)
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_LOGW(TAG, "Erasing NVS flash");
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    // Initialize components
    ESP_ERROR_CHECK(wifi_init());
    ESP_ERROR_CHECK(uart_init());

    // Register shutdown handler (useful for debugging)
    esp_register_shutdown_handler(cleanup_resources);

    // Wait for WiFi connection
    if (!wifi_wait_connected(30)) {
        ESP_LOGE(TAG, "WiFi connection failed, aborting");
        return;
    }

#ifdef CONFIG_TLS_ENABLE
    // Initialize file system to access certificates
    esp_vfs_spiffs_conf_t spiffs_conf = {
        .base_path = "/spiffs",
        .partition_label = "spiffs",  // Must match your partition table
        .max_files = 5,
        .format_if_mount_failed = true
    };

    ret = esp_vfs_spiffs_register(&spiffs_conf);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to mount SPIFFS (%s)", esp_err_to_name(ret));
        return;
    }

    // Initialize TLS configuration
    tcp_server_tls_config_t tls_config = {0};
    bool cert_loaded = false;

    // Load server certificate
    tls_config.server_cert_pem = load_cert_file(CONFIG_TLS_SERVER_CERT_PATH);
    if (tls_config.server_cert_pem == NULL) {
        ESP_LOGE(TAG, "Failed to load server certificate");
        goto cleanup;
    }

    // Load server key
    tls_config.server_key_pem = load_cert_file(CONFIG_TLS_SERVER_KEY_PATH);
    if (tls_config.server_key_pem == NULL) {
        ESP_LOGE(TAG, "Failed to load server key");
        goto cleanup;
    }

    // Load CA certificate for client verification if needed
#ifdef CONFIG_TLS_CLIENT_VERIFY
    tls_config.verify_client = true;
    tls_config.ca_cert_pem = load_cert_file(CONFIG_TLS_CA_CERT_PATH);
    if (tls_config.ca_cert_pem == NULL) {
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

    // Initialize TCP server with TLS
    if (tcp_server_init(&tls_config) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to initialize TLS server, aborting");
        goto cleanup;
    }
#else
    // Initialize TCP server without TLS
    if (tcp_server_init(NULL) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to initialize TCP server, aborting");
        return;
    }
    ESP_LOGI(TAG, "TCP server initialized (TLS disabled)");
#endif

    // Main processing loop
    ESP_LOGI(TAG, "Entering main loop");
    while (1) {
        // Try to accept new client if none connected
        tcp_handle_new_connection();

        // Process data in both directions
        process_data();

        // Small delay to prevent CPU hogging
        vTaskDelay(pdMS_TO_TICKS(CONFIG_TASK_DELAY_MS));
    }

#ifdef CONFIG_TLS_ENABLE
cleanup:
    // Free certificate resources if they were allocated
    if (cert_loaded) {
        if (tls_config.server_cert_pem) free((void*)tls_config.server_cert_pem);
        if (tls_config.server_key_pem) free((void*)tls_config.server_key_pem);
        if (tls_config.ca_cert_pem) free((void*)tls_config.ca_cert_pem);
    }
    // Unmount SPIFFS
    esp_vfs_spiffs_unregister(spiffs_conf.partition_label);
    return;
#endif
}
