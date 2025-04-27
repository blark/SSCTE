#include "uart_manager.h"
#include "driver/uart.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "UARTManager";

esp_err_t uart_init(void) {
    uart_config_t uart_config = {
        .baud_rate = CONFIG_UART_BAUD_RATE,
        .data_bits = UART_DATA_8_BITS,
        .parity    = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
    };

    ESP_LOGI(TAG, "Initializing UART on port %d (TX:%d, RX:%d, baud:%d)",
             CONFIG_UART_PORT, CONFIG_UART_TX_PIN, CONFIG_UART_RX_PIN, CONFIG_UART_BAUD_RATE);

    // Install UART driver and set parameters
    esp_err_t ret = uart_driver_install(CONFIG_UART_PORT, CONFIG_UART_BUF_SIZE,
                                       CONFIG_UART_BUF_SIZE, 0, NULL, 0);
    if (ret != ESP_OK) return ret;

    ret = uart_param_config(CONFIG_UART_PORT, &uart_config);
    if (ret != ESP_OK) return ret;

    ret = uart_set_pin(CONFIG_UART_PORT, CONFIG_UART_TX_PIN, CONFIG_UART_RX_PIN,
                       UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);

    return ret;
}

int uart_read_data(uint8_t *buffer, size_t max_len, uint32_t timeout_ms) {
    if (buffer == NULL || max_len == 0) {
        return -1;
    }

    return uart_read_bytes(CONFIG_UART_PORT, buffer, max_len, pdMS_TO_TICKS(timeout_ms));
}

int uart_write_data(const uint8_t *data, size_t len) {
    if (data == NULL || len == 0) {
        return -1;
    }

    return uart_write_bytes(CONFIG_UART_PORT, (const char *)data, len);
}

esp_err_t uart_get_available_bytes(size_t *available) {
    if (available == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    return uart_get_buffered_data_len(CONFIG_UART_PORT, available);
}

void uart_cleanup(void) {
    uart_driver_delete(CONFIG_UART_PORT);
    ESP_LOGI(TAG, "UART cleanup complete");
}
