# Base source files (always compiled)
set(COMPONENT_SRCS
    "serial_tcp_bridge.c"
    "network_manager.c"
    "uart_manager.c"
    "tcp_server.c"
)

# Add network backend based on configuration
if(CONFIG_NETWORK_INTERFACE_WIFI)
    list(APPEND COMPONENT_SRCS "network_wifi.c")
elseif(CONFIG_NETWORK_INTERFACE_ETHERNET)
    list(APPEND COMPONENT_SRCS "network_ethernet.c")
endif()

idf_component_register(
    SRCS ${COMPONENT_SRCS}
    INCLUDE_DIRS "."
)
