#include "uart_manager.h"
#include "driver/uart.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "soc/soc_caps.h"
#include "sdkconfig.h"
#include <string.h>
#include <stdlib.h>

static const char *TAG = "UARTManager";

/**
 * Array of bridge instances - one for each UART being managed.
 * UART0 is reserved for debug, so bridges start from UART1.
 */
static uart_bridge_t bridges[CONFIG_AVAILABLE_BRIDGE_UARTS];

/**
 * Tracks the number of successfully initialized bridges.
 * Used to report status and determine if initialization succeeded.
 */
static int active_bridges = 0;

/**
 * @brief Initialize UART hardware for a bridge
 *
 * Configures and initializes the UART hardware with specified parameters.
 * Sets up the UART driver, parameters, and pin assignments.
 *
 * @param bridge Pointer to the bridge instance to initialize
 * @return ESP_OK on success, error code on failure
 */
static esp_err_t init_uart(uart_bridge_t *bridge) {
    uart_config_t uart_config = {
        .baud_rate = bridge->baud_rate,
        .data_bits = UART_DATA_8_BITS,
        .parity    = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
    };

    ESP_LOGI(TAG, "Initializing UART%d (TX:%d, RX:%d, baud:%d)",
             bridge->uart_port, bridge->tx_pin, bridge->rx_pin, bridge->baud_rate);

    // Install UART driver with appropriate buffer sizes
    esp_err_t ret = uart_driver_install(bridge->uart_port, CONFIG_UART_BUF_SIZE,
                                       CONFIG_UART_BUF_SIZE, 0, NULL, 0);
    if (ret != ESP_OK) return ret;

    // Configure UART parameters (baud rate, data bits, etc.)
    ret = uart_param_config(bridge->uart_port, &uart_config);
    if (ret != ESP_OK) {
        uart_driver_delete(bridge->uart_port);
        return ret;
    }

    // Assign GPIO pins to UART signals
    ret = uart_set_pin(bridge->uart_port, bridge->tx_pin, bridge->rx_pin,
                       UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);
    if (ret != ESP_OK) {
        uart_driver_delete(bridge->uart_port);
    }

    return ret;
}

/**
 * @brief Initialize a single bridge instance
 *
 * Sets up a bridge structure with configuration from menuconfig,
 * allocates memory for buffers, and initializes the UART hardware.
 *
 * @param bridge_idx Index of the bridge to initialize (0-based)
 * @return ESP_OK on success, appropriate error code on failure
 */
static esp_err_t init_bridge(int bridge_idx) {
    if (bridge_idx >= CONFIG_AVAILABLE_BRIDGE_UARTS) {
        ESP_LOGE(TAG, "Bridge index %d exceeds available UARTs", bridge_idx);
        return ESP_ERR_INVALID_ARG;
    }

    // UART number is bridge_idx + 1 (skipping UART0 which is reserved for debug)
    int uart_num = bridge_idx + 1;
    uart_bridge_t *bridge = &bridges[bridge_idx];

    // Configure the bridge based on UART number using Kconfig settings
    switch (uart_num) {
        case 1: // UART1
            bridge->uart_port = UART_NUM_1;
            bridge->tx_pin = CONFIG_UART1_TX_PIN;
            bridge->rx_pin = CONFIG_UART1_RX_PIN;
            bridge->baud_rate = CONFIG_UART1_BAUD_RATE;
            bridge->tcp_port = CONFIG_UART1_TCP_PORT;
            break;

    #if SOC_UART_NUM > 2
        case 2: // UART2
            bridge->uart_port = UART_NUM_2;
            bridge->tx_pin = CONFIG_UART2_TX_PIN;
            bridge->rx_pin = CONFIG_UART2_RX_PIN;
            bridge->baud_rate = CONFIG_UART2_BAUD_RATE;
            bridge->tcp_port = CONFIG_UART2_TCP_PORT;
            break;
    #endif

    #if SOC_UART_NUM > 3
        case 3: // UART3
            bridge->uart_port = UART_NUM_3;
            bridge->tx_pin = CONFIG_UART3_TX_PIN;
            bridge->rx_pin = CONFIG_UART3_RX_PIN;
            bridge->baud_rate = CONFIG_UART3_BAUD_RATE;
            bridge->tcp_port = CONFIG_UART3_TCP_PORT;
            break;
    #endif

    #if SOC_UART_NUM > 4
        case 4: // UART4
            bridge->uart_port = UART_NUM_4;
            bridge->tx_pin = CONFIG_UART4_TX_PIN;
            bridge->rx_pin = CONFIG_UART4_RX_PIN;
            bridge->baud_rate = CONFIG_UART4_BAUD_RATE;
            bridge->tcp_port = CONFIG_UART4_TCP_PORT;
            break;
    #endif

        default:
            ESP_LOGE(TAG, "Unsupported UART number: %d", uart_num);
            return ESP_ERR_INVALID_ARG;
    }

    // Allocate data buffers for this bridge
    bridge->uart_buf = malloc(CONFIG_UART_BUF_SIZE);
    bridge->tcp_buf = malloc(CONFIG_UART_BUF_SIZE);

    if (!bridge->uart_buf || !bridge->tcp_buf) {
        ESP_LOGE(TAG, "Failed to allocate buffers for UART%d bridge", uart_num);
        free(bridge->uart_buf);  // Safe even if NULL
        free(bridge->tcp_buf);   // Safe even if NULL
        return ESP_ERR_NO_MEM;
    }

    // Initialize UART hardware
    esp_err_t ret = init_uart(bridge);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to initialize UART%d: %s",
                 uart_num, esp_err_to_name(ret));
        free(bridge->uart_buf);
        free(bridge->tcp_buf);
        return ret;
    }

    // Initialize remaining bridge fields to safe defaults
    bridge->server_sock = -1;
    bridge->client_sock = -1;
#if defined(CONFIG_TLS_ENABLE)
    bridge->tls_handle = NULL;
#endif

    // Mark the bridge as enabled and ready for use
    bridge->enabled = true;
    ESP_LOGI(TAG, "Initialized bridge %d: UART%d (baud:%d) <-> TCP port %d",
             bridge_idx, bridge->uart_port, bridge->baud_rate, bridge->tcp_port);

    return ESP_OK;
}

/* -------------- Public API Implementation -------------- */

/**
 * @brief Initialize all configured UART bridges
 *
 * Initializes each UART bridge based on Kconfig settings, allocating
 * necessary resources and configuring the hardware.
 *
 * @return ESP_OK if at least one bridge initialized successfully, ESP_FAIL otherwise
 */
esp_err_t uart_manager_init(void) {
    // Get number of bridges to initialize from configuration
    int num_bridges = CONFIG_ENABLE_UART_BRIDGES;
    int max_available = CONFIG_AVAILABLE_BRIDGE_UARTS;
    active_bridges = 0;

    // Initialize bridge array to safe values
    memset(bridges, 0, sizeof(bridges));
    for (int i = 0; i < CONFIG_AVAILABLE_BRIDGE_UARTS; i++) {
        bridges[i].enabled = false;
        bridges[i].uart_port = -1;
        bridges[i].server_sock = -1;
        bridges[i].client_sock = -1;
    }

    // Ensure we don't exceed available UARTs
    if (num_bridges > max_available) {
        ESP_LOGW(TAG, "Requested %d bridges, but only %d available. Limiting to %d.",
                 num_bridges, max_available, max_available);
        num_bridges = max_available;
    }

    ESP_LOGI(TAG, "Initializing %d UART bridges", num_bridges);

    // Initialize each bridge
    for (int i = 0; i < num_bridges; i++) {
        if (init_bridge(i) == ESP_OK) {
            active_bridges++;
        }
    }

    // Check if at least one bridge initialized successfully
    if (active_bridges == 0) {
        ESP_LOGE(TAG, "Failed to initialize any bridges");
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "Successfully initialized %d/%d bridges",
             active_bridges, num_bridges);

    return ESP_OK;
}

/**
 * @brief Process data for all active bridges
 *
 * This function is intentionally empty in this implementation.
 * Data processing is handled by the TCP server component, which
 * has access to the bridge instances.
 */
void uart_manager_process(void) {
    // Data processing is handled by the tcp_server component
    // which accesses bridge instances directly
}

/**
 * @brief Handle new TCP connections for all bridges
 *
 * This function is intentionally empty in this implementation.
 * Connection handling is managed by the TCP server component.
 */
void uart_manager_handle_connections(void) {
    // Connection handling is managed by the tcp_server component
    // which accesses bridge instances directly
}

/**
 * @brief Clean up all UART resources
 *
 * Releases all resources allocated for UART bridges, including
 * deleting UART drivers and freeing allocated memory.
 */
void uart_manager_cleanup(void) {
    for (int i = 0; i < CONFIG_AVAILABLE_BRIDGE_UARTS; i++) {
        if (bridges[i].enabled) {
            // Clean up UART hardware
            uart_driver_delete(bridges[i].uart_port);

            // Free allocated buffers
            free(bridges[i].uart_buf);
            free(bridges[i].tcp_buf);

            bridges[i].enabled = false;
        }
    }

    active_bridges = 0;
    ESP_LOGI(TAG, "UART manager cleanup complete");
}

/**
 * @brief Get number of active bridges
 *
 * @return Number of successfully initialized bridges
 */
int uart_manager_get_active_count(void) {
    return active_bridges;
}

/**
 * @brief Get the array of bridge instances
 *
 * Provides direct access to the bridge instances, allowing
 * other components (like tcp_server) to work with the bridges.
 *
 * @return Pointer to the array of bridge instances
 */
uart_bridge_t* uart_manager_get_instances(void) {
    return bridges;
}

/* -------------- UART Operation Functions -------------- */

/**
 * @brief Read data from a UART
 *
 * Reads available data from the specified UART bridge with timeout.
 *
 * @param bridge Pointer to the bridge instance
 * @param buffer Buffer to store read data
 * @param max_len Maximum number of bytes to read
 * @param timeout_ms Timeout in milliseconds
 * @return Number of bytes read, or -1 on error
 */
int uart_read_data(uart_bridge_t *bridge, uint8_t *buffer, size_t max_len, uint32_t timeout_ms) {
    if (!bridge || !bridge->enabled || !buffer || max_len == 0) {
        return -1;
    }

    return uart_read_bytes(bridge->uart_port, buffer, max_len, pdMS_TO_TICKS(timeout_ms));
}

/**
 * @brief Write data to a UART
 *
 * Sends data to the specified UART.
 *
 * @param bridge Pointer to the bridge instance
 * @param data Data to write
 * @param len Length of data to write
 * @return Number of bytes written, or -1 on error
 */
int uart_write_data(uart_bridge_t *bridge, const uint8_t *data, size_t len) {
    if (!bridge || !bridge->enabled || !data || len == 0) {
        return -1;
    }

    return uart_write_bytes(bridge->uart_port, (const char *)data, len);
}

/**
 * @brief Get number of bytes available in UART RX buffer
 *
 * @param bridge Pointer to the bridge instance
 * @param available Pointer to store the number of available bytes
 * @return ESP_OK on success, error code otherwise
 */
esp_err_t uart_get_available_bytes(uart_bridge_t *bridge, size_t *available) {
    if (!bridge || !bridge->enabled || !available) {
        return ESP_ERR_INVALID_ARG;
    }

    return uart_get_buffered_data_len(bridge->uart_port, available);
}
