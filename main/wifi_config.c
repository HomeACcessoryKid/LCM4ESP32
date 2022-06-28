#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "freertos/FreeRTOS.h"
#include "freertos/timers.h"
#include "esp_wifi.h"
#include <lwip/sockets.h>
#include "form_urlencoded.h"
#include "esp_ota_ops.h"

#define WIFI_CONFIG_SERVER_PORT 80

#ifndef WIFI_CONFIG_CONNECT_TIMEOUT
#define WIFI_CONFIG_CONNECT_TIMEOUT 15000
#endif

#define DEBUG(message, ...) printf(">>> wifi_config: %s: " message "\n", __func__, ##__VA_ARGS__);
#define INFO(message, ...) printf(">>> wifi_config: " message "\n", ##__VA_ARGS__);
#define ERROR(message, ...) printf("!!! wifi_config: " message "\n", ##__VA_ARGS__);


typedef enum {
    ENDPOINT_UNKNOWN = 0,
    ENDPOINT_INDEX,
    ENDPOINT_SETTINGS,
    ENDPOINT_SETTINGS_UPDATE,
} endpoint_t;


typedef struct {
    char *ssid_prefix;
    char *password;
    void (*on_wifi_ready)();

    TickType_t connect_start_time;
    TimerHandle_t sta_connect_timeout;
    TaskHandle_t http_task_handle;
    TaskHandle_t dns_task_handle;
} wifi_config_context_t;


static wifi_config_context_t *context;

// 
// typedef struct _client {
//     int fd;
// 
//     http_parser parser;
//     endpoint_t endpoint;
//     uint8_t *body;
//     size_t body_length;
// } client_t;


static int wifi_config_station_connect();
static void wifi_config_softap_start();
static void wifi_config_softap_stop();
// 
// static client_t *client_new() {
//     client_t *client = malloc(sizeof(client_t));
//     memset(client, 0, sizeof(client_t));
// 
//     http_parser_init(&client->parser, HTTP_REQUEST);
//     client->parser.data = client;
// 
//     return client;
// }
// 
// 
// static void client_free(client_t *client) {
//     if (client->body)
//         free(client->body);
// 
//     free(client);
// }
// 
// 
// static void client_send(client_t *client, const char *payload, size_t payload_size) {
//     lwip_write(client->fd, payload, payload_size);
// }
// 
// 
// static void client_send_chunk(client_t *client, const char *payload) {
//     int len = strlen(payload);
//     char buffer[10];
//     int buffer_len = snprintf(buffer, sizeof(buffer), "%x\r\n", len);
//     client_send(client, buffer, buffer_len);
//     client_send(client, payload, len);
//     client_send(client, "\r\n", 2);
// }
// 
// 
// static void client_send_redirect(client_t *client, int code, const char *redirect_url) {
//     DEBUG("Redirecting to %s", redirect_url);
//     char buffer[128];
//     size_t len = snprintf(buffer, sizeof(buffer), "HTTP/1.1 %d \r\nLocation: %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", code, redirect_url);
//     client_send(client, buffer, len);
// }
// 
// 
// typedef struct _wifi_network_info {
//     char ssid[33];
//     bool secure;
// 
//     struct _wifi_network_info *next;
// } wifi_network_info_t;
// 
// 
// wifi_network_info_t *wifi_networks = NULL;
// SemaphoreHandle_t wifi_networks_mutex;
// 
// 
// static void wifi_scan_done_cb(void *arg, sdk_scan_status_t status)
// {
//     if (status != SCAN_OK)
//     {
//         ERROR("WiFi scan failed");
//         return;
//     }
// 
//     xSemaphoreTake(wifi_networks_mutex, portMAX_DELAY);
// 
//     wifi_network_info_t *wifi_network = wifi_networks;
//     while (wifi_network) {
//         wifi_network_info_t *next = wifi_network->next;
//         free(wifi_network);
//         wifi_network = next;
//     }
//     wifi_networks = NULL;
// 
//     struct sdk_bss_info *bss = (struct sdk_bss_info *)arg;
//     // first one is invalid
//     bss = bss->next.stqe_next;
// 
//     while (bss) {
//         wifi_network_info_t *net = wifi_networks;
//         while (net) {
//             if (!strncmp(net->ssid, (char *)bss->ssid, sizeof(net->ssid)))
//                 break;
//             net = net->next;
//         }
//         if (!net) {
//             wifi_network_info_t *net = malloc(sizeof(wifi_network_info_t));
//             memset(net, 0, sizeof(*net));
//             strncpy(net->ssid, (char *)bss->ssid, sizeof(net->ssid));
//             net->secure = bss->authmode != AUTH_OPEN;
//             net->next = wifi_networks;
// 
//             wifi_networks = net;
//         }
// 
//         bss = bss->next.stqe_next;
//     }
// 
//     xSemaphoreGive(wifi_networks_mutex);
// }
// 
// static void wifi_scan_task(void *arg)
// {
//     INFO("Starting WiFi scan");
//     while (true)
//     {
//         if (sdk_wifi_get_opmode() != STATIONAP_MODE)
//             break;
// 
//         sdk_wifi_station_scan(NULL, wifi_scan_done_cb);
//         vTaskDelay(10000 / portTICK_PERIOD_MS);
//     }
// 
//     xSemaphoreTake(wifi_networks_mutex, portMAX_DELAY);
// 
//     wifi_network_info_t *wifi_network = wifi_networks;
//     while (wifi_network) {
//         wifi_network_info_t *next = wifi_network->next;
//         free(wifi_network);
//         wifi_network = next;
//     }
//     wifi_networks = NULL;
// 
//     xSemaphoreGive(wifi_networks_mutex);
// 
//     vTaskDelete(NULL);
// }
// 
// #include "index.html.h"
// 
// static void wifi_config_server_on_settings(client_t *client) {
//     char *ota_repo=NULL;
//     bool lcm_beta=0;
//     static const char http_prologue[] =
//         "HTTP/1.1 200 \r\n"
//         "Content-Type: text/html; charset=utf-8\r\n"
//         "Cache-Control: no-store\r\n"
//         "Transfer-Encoding: chunked\r\n"
//         "Connection: close\r\n"
//         "\r\n";
// 
//     client_send(client, http_prologue, sizeof(http_prologue)-1);
//     client_send_chunk(client, html_settings_header);
// 
//     char buffer[64];
//     if (xSemaphoreTake(wifi_networks_mutex, 5000 / portTICK_PERIOD_MS)) {
//         wifi_network_info_t *net = wifi_networks;
//         while (net) {
//             snprintf(
//                 buffer, sizeof(buffer),
//                 html_network_item,
//                 net->secure ? "secure" : "unsecure", net->ssid
//             );
//             client_send_chunk(client, buffer);
// 
//             net = net->next;
//         }
// 
//         xSemaphoreGive(wifi_networks_mutex);
//     }
// 
//     client_send_chunk(client, html_settings_middle);
//     
//     if (sysparam_get_string("ota_repo", &ota_repo)!=SYSPARAM_OK) client_send_chunk(client, html_settings_otaparameters);
//     else free(ota_repo);
//     
//     if (sysparam_get_bool("lcm_beta", &lcm_beta)==SYSPARAM_OK && lcm_beta) client_send_chunk(client, html_settings_otaserver);
// 
//     client_send_chunk(client, html_settings_footer);
//     client_send_chunk(client, "");
// }
// 
// 
// static void wifi_config_server_on_settings_update(client_t *client) {
//     DEBUG("Update settings, body = %s", client->body);
// 
//     form_param_t *form = form_params_parse((char *)client->body);
//     if (!form) {
//         client_send_redirect(client, 302, "/settings");
//         return;
//     }
// 
//     form_param_t *ssid_param = form_params_find(form, "ssid");
//     form_param_t *password_param = form_params_find(form, "password");
//     form_param_t *led_pin_param = form_params_find(form, "led_pin");
//     form_param_t *led_pol_param = form_params_find(form, "led_pol");
//     form_param_t *otarepo_param = form_params_find(form, "otarepo");
//     form_param_t *otafile_param = form_params_find(form, "otafile");
//     form_param_t *otastr_param  = form_params_find(form, "otastr");
//     form_param_t *otabeta_param = form_params_find(form, "otabeta");
//     form_param_t *otasrvr_param = form_params_find(form, "otasrvr");
//     if (!ssid_param) {
//         form_params_free(form);
//         client_send_redirect(client, 302, "/settings");
//         return;
//     }
// 
//     static const char payload[] = "HTTP/1.1 204 \r\nContent-Type: text/html\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
//     client_send(client, payload, sizeof(payload)-1);
// 
//     sysparam_set_string("wifi_ssid", ssid_param->value);
//     if (led_pin_param && led_pin_param->value && led_pol_param && led_pol_param->value) {
//         if (strcmp(led_pin_param->value,"n")) 
//              sysparam_set_int8("led_pin", (strcmp(led_pol_param->value,"1")?1:-1) * atoi(led_pin_param->value));
//         else if (!strcmp(led_pol_param->value,"1")) sysparam_set_data("led_pin", NULL,0,0); //wipe only if "n" and ledpol=1
//     }
//     if (otarepo_param && otarepo_param->value) sysparam_set_string("ota_repo", otarepo_param->value);
//     if (otafile_param && otafile_param->value) sysparam_set_string("ota_file", otafile_param->value);
//     if (otastr_param  && otastr_param->value) sysparam_set_string("ota_string", otastr_param->value);
//     if (otabeta_param && otabeta_param->value) sysparam_set_bool("ota_beta", otabeta_param->value[0]-0x30);
//     if (otasrvr_param && otasrvr_param->value && strcmp(otasrvr_param->value,"not.github.com/somewhere/"))
//                                                sysparam_set_string("ota_srvr", otasrvr_param->value);
//     if (password_param) {
//         sysparam_set_string("wifi_password", password_param->value);
//     } else {
//         sysparam_set_string("wifi_password", "");
//     }
//     form_params_free(form);
// 
//     vTaskDelay(500 / portTICK_PERIOD_MS);
// 
//     wifi_config_station_connect();
// }
// 
// 
// static int wifi_config_server_on_url(http_parser *parser, const char *data, size_t length) {
//     client_t *client = (client_t*) parser->data;
// 
//     client->endpoint = ENDPOINT_UNKNOWN;
//     if (parser->method == HTTP_GET) {
//         if (!strncmp(data, "/settings", length)) {
//             client->endpoint = ENDPOINT_SETTINGS;
//         } else if (!strncmp(data, "/", length)) {
//             client->endpoint = ENDPOINT_INDEX;
//         }
//     } else if (parser->method == HTTP_POST) {
//         if (!strncmp(data, "/settings", length)) {
//             client->endpoint = ENDPOINT_SETTINGS_UPDATE;
//         }
//     }
// 
//     if (client->endpoint == ENDPOINT_UNKNOWN) {
//         char *url = strndup(data, length);
//         ERROR("Unknown endpoint: %s %s", http_method_str(parser->method), url);
//         free(url);
//     }
// 
//     return 0;
// }
// 
// 
// static int wifi_config_server_on_body(http_parser *parser, const char *data, size_t length) {
//     client_t *client = parser->data;
//     client->body = realloc(client->body, client->body_length + length + 1);
//     memcpy(client->body + client->body_length, data, length);
//     client->body_length += length;
//     client->body[client->body_length] = 0;
// 
//     return 0;
// }
// 
// 
// static int wifi_config_server_on_message_complete(http_parser *parser) {
//     client_t *client = parser->data;
// 
//     switch(client->endpoint) {
//         case ENDPOINT_INDEX: {
//             client_send_redirect(client, 301, "/settings");
//             break;
//         }
//         case ENDPOINT_SETTINGS: {
//             wifi_config_server_on_settings(client);
//             break;
//         }
//         case ENDPOINT_SETTINGS_UPDATE: {
//             wifi_config_server_on_settings_update(client);
//             break;
//         }
//         case ENDPOINT_UNKNOWN: {
//             DEBUG("Unknown endpoint");
//             client_send_redirect(client, 302, "http://192.168.4.1/settings");
//             break;
//         }
//     }
// 
//     if (client->body) {
//         free(client->body);
//         client->body = NULL;
//         client->body_length = 0;
//     }
// 
//     return 0;
// }
// 
// 
// static http_parser_settings wifi_config_http_parser_settings = {
//     .on_url = wifi_config_server_on_url,
//     .on_body = wifi_config_server_on_body,
//     .on_message_complete = wifi_config_server_on_message_complete,
// };
// 
// 
// static void http_task(void *arg) {
//     INFO("Starting HTTP server");
// 
//     struct sockaddr_in serv_addr;
//     int listenfd = socket(AF_INET, SOCK_STREAM, 0);
//     memset(&serv_addr, '0', sizeof(serv_addr));
//     serv_addr.sin_family = AF_INET;
//     serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
//     serv_addr.sin_port = htons(WIFI_CONFIG_SERVER_PORT);
//     int flags;
//     if ((flags = lwip_fcntl(listenfd, F_GETFL, 0)) < 0) {
//         ERROR("Failed to get HTTP socket flags");
//         lwip_close(listenfd);
//         vTaskDelete(NULL);
//         return;
//     };
//     if (lwip_fcntl(listenfd, F_SETFL, flags | O_NONBLOCK) < 0) {
//         ERROR("Failed to set HTTP socket flags");
//         lwip_close(listenfd);
//         vTaskDelete(NULL);
//         return;
//     }
//     bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
//     listen(listenfd, 2);
// 
//     char data[64];
// 
//     bool running = true;
//     while (running) {
//         uint32_t task_value = 0;
//         if (xTaskNotifyWait(0, 1, &task_value, 0) == pdTRUE) {
//             if (task_value) {
//                 running = false;
//                 break;
//             }
//         }
// 
//         int fd = accept(listenfd, (struct sockaddr *)NULL, (socklen_t *)NULL);
//         if (fd < 0) {
//             vTaskDelay(500 / portTICK_PERIOD_MS);
//             continue;
//         }
// 
//         const struct timeval timeout = { 2, 0 }; /* 2 second timeout */
//         setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
// 
//         client_t *client = client_new();
//         client->fd = fd;
// 
//         for (;;) {
//             int data_len = lwip_read(client->fd, data, sizeof(data));
//             DEBUG("lwip_read: %d", data_len);
// 
//             if (data_len > 0) {
// 
//                 http_parser_execute(
//                     &client->parser, &wifi_config_http_parser_settings,
//                     data, data_len
//                 );
//             } else {
//                 break;
//             }
// 
//             if (xTaskNotifyWait(0, 1, &task_value, 0) == pdTRUE) {
//                 if (task_value) {
//                     running = false;
//                     break;
//                 }
//             }
//         }
// 
//         INFO("Client disconnected");
// 
//         lwip_close(client->fd);
//         client_free(client);
//     }
// 
//     INFO("Stopping HTTP server");
// 
//     lwip_close(listenfd);
// 
//     context->http_task_handle=NULL;
//     vTaskDelete(NULL);
// }
// 
// 
// static void http_start() {
//     xTaskCreate(http_task, "wifi_config HTTP", 512, NULL, 2, &context->http_task_handle);
// }
// 
// 
// static void http_stop() {
//     if (! context->http_task_handle)
//         return;
// 
//     xTaskNotify(context->http_task_handle, 1, eSetValueWithOverwrite);
// }
// 
// 
// static void dns_task(void *arg)
// {
//     INFO("Starting DNS server");
// 
//     ip4_addr_t server_addr;
//     IP4_ADDR(&server_addr, 192, 168, 4, 1);
// 
//     struct sockaddr_in serv_addr;
//     int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
// 
//     memset(&serv_addr, '0', sizeof(serv_addr));
//     serv_addr.sin_family = AF_INET;
//     serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
//     serv_addr.sin_port = htons(53);
//     bind(fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
// 
//     const struct timeval timeout = { 2, 0 }; /* 2 second timeout */
//     setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
// 
//     const struct ifreq ifreq1 = { "en1" };
//     setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &ifreq1, sizeof(ifreq1));
// 
//     for (;;) {
//         char buffer[96];
//         struct sockaddr src_addr;
//         socklen_t src_addr_len = sizeof(src_addr);
//         size_t count = recvfrom(fd, buffer, sizeof(buffer), 0, (struct sockaddr*)&src_addr, &src_addr_len);
// 
//         /* Drop messages that are too large to send a response in the buffer */
//         if (count > 0 && count <= sizeof(buffer) - 16 && src_addr.sa_family == AF_INET) {
//             size_t qname_len = strlen(buffer + 12) + 1;
//             uint32_t reply_len = 2 + 10 + qname_len + 16 + 4;
// 
//             char *head = buffer + 2;
//             *head++ = 0x80; // Flags
//             *head++ = 0x00;
//             *head++ = 0x00; // Q count
//             *head++ = 0x01;
//             *head++ = 0x00; // A count
//             *head++ = 0x01;
//             *head++ = 0x00; // Auth count
//             *head++ = 0x00;
//             *head++ = 0x00; // Add count
//             *head++ = 0x00;
//             head += qname_len;
//             *head++ = 0x00; // Q type
//             *head++ = 0x01;
//             *head++ = 0x00; // Q class
//             *head++ = 0x01;
//             *head++ = 0xC0; // LBL offs
//             *head++ = 0x0C;
//             *head++ = 0x00; // Type
//             *head++ = 0x01;
//             *head++ = 0x00; // Class
//             *head++ = 0x01;
//             *head++ = 0x00; // TTL
//             *head++ = 0x00;
//             *head++ = 0x00;
//             *head++ = 0x78;
//             *head++ = 0x00; // RD len
//             *head++ = 0x04;
//             *head++ = ip4_addr1(&server_addr);
//             *head++ = ip4_addr2(&server_addr);
//             *head++ = ip4_addr3(&server_addr);
//             *head++ = ip4_addr4(&server_addr);
// 
//             sendto(fd, buffer, reply_len, 0, &src_addr, src_addr_len);
//         }
// 
//         uint32_t task_value = 0;
//         if (xTaskNotifyWait(0, 1, &task_value, 0) == pdTRUE) {
//             if (task_value)
//                 break;
//         }
//     }
// 
//     INFO("Stopping DNS server");
// 
//     lwip_close(fd);
// 
//     context->dns_task_handle=NULL;
//     vTaskDelete(NULL);
// }
// 
// 
// static void dns_start() {
//     xTaskCreate(dns_task, "wifi_config DNS", 384, NULL, 2, &context->dns_task_handle);
// }
// 
// 
// static void dns_stop() {
//     if (!context->dns_task_handle)
//         return;
// 
//     xTaskNotify(context->dns_task_handle, 1, eSetValueWithOverwrite);
// }


static void wifi_config_context_free(wifi_config_context_t *context) {
    if (context->ssid_prefix)
        free(context->ssid_prefix);

    if (context->password)
        free(context->password);

    free(context);
}

static void wifi_config_softap_start() {
    INFO("Starting AP mode");
    esp_wifi_set_mode(WIFI_MODE_APSTA); //TODO: does this prevent a flash write if not changed?
// 
//     uint8_t macaddr[6];
//     sdk_wifi_get_macaddr(SOFTAP_IF, macaddr);
// 
//     struct sdk_softap_config softap_config;
//     softap_config.ssid_len = snprintf(
//         (char *)softap_config.ssid, sizeof(softap_config.ssid),
//         "%s-%02X%02X%02X", context->ssid_prefix, macaddr[3], macaddr[4], macaddr[5]
//     );
//     softap_config.ssid_hidden = 0;
//     softap_config.channel = 3;
//     if (context->password) {
//         softap_config.authmode = AUTH_WPA_WPA2_PSK;
//         strncpy((char *)softap_config.password,
//                 context->password, sizeof(softap_config.password));
//     } else {
//         softap_config.authmode = AUTH_OPEN;
//     }
//     softap_config.max_connection = 2;
//     softap_config.beacon_interval = 100;
// 
//     DEBUG("Starting AP SSID=%s", softap_config.ssid);
// 
//     struct ip_info ap_ip;
//     IP4_ADDR(&ap_ip.ip, 192, 168, 4, 1);
//     IP4_ADDR(&ap_ip.netmask, 255, 255, 255, 0);
//     IP4_ADDR(&ap_ip.gw, 0, 0, 0, 0);
//     sdk_wifi_set_ip_info(SOFTAP_IF, &ap_ip);
// 
//     sdk_wifi_softap_set_config(&softap_config);
// 
//     ip4_addr_t first_client_ip;
//     first_client_ip.addr = ap_ip.ip.addr + htonl(1);
// 
//     wifi_networks_mutex = xSemaphoreCreateBinary();
//     xSemaphoreGive(wifi_networks_mutex);
// 
//     xTaskCreate(wifi_scan_task, "wifi_config scan", 384, NULL, 2, NULL);
// 
//     INFO("Starting DHCP server");
//     dhcpserver_start(&first_client_ip, 4);
//     dhcpserver_set_router(&ap_ip.ip);
//     dhcpserver_set_dns(&ap_ip.ip);
// 
//     dns_start();
//     http_start();
}


static void wifi_config_softap_stop() {
//     dhcpserver_stop();
//     dns_stop();
//     http_stop();
//     while (context->dns_task_handle || context->http_task_handle) vTaskDelay(20/ portTICK_PERIOD_MS);
//     sdk_wifi_set_opmode(STATION_MODE);
    esp_wifi_set_mode(WIFI_MODE_STA); //TODO: does this prevent a flash write if not changed?
    INFO("Stopping AP mode");
}


static void wifi_config_sta_connect_timeout_callback(TimerHandle_t context) {    
    DEBUG("Timeout connecting to WiFi network, starting config AP");
    // Not connected to station, launch configuration AP
    wifi_config_softap_start();
}


static int wifi_config_station_connect() {
    wifi_config_t wifi_config;
    esp_wifi_get_config(WIFI_IF_STA, &wifi_config);
    if (wifi_config.sta.ssid[0]==0) {
        DEBUG("No configuration found");
        return -1;
    }
    INFO("Found configuration, connecting to %s", wifi_config.sta.ssid);

    esp_wifi_set_mode(WIFI_MODE_STA); //TODO: does this prevent a flash write if not changed?
    ESP_ERROR_CHECK(esp_wifi_start());

    esp_wifi_connect();
    
    xTimerStart(context->sta_connect_timeout,0);
    return 0;
}


size_t tty_readline(char *buffer, size_t buf_size) {
    size_t i = 0;
    int c;

    while (true) {
        c = getchar(); //this seems to translate a \r in a \n, effectivly detecting two \n  on \r\n
        if (c == '\n') { //ignore  c == '\r' || 
            putchar('\n');
            getchar(); //flush that extra \n! supposedly getchar does not block...
            break;
        } else if (c == '\b' || c == 0x7f) {
            if (i) {
                printf("\b \b");
                fflush(stdout);
                i--;
            }
        } else if (c < 0x20) {
            /* Ignore other control characters */
        } else if (i >= buf_size - 1) {
            putchar('\a');
            fflush(stdout);
        } else {
            buffer[i++] = c;
            putchar(c);
            fflush(stdout);
        }
        vTaskDelay(1);
    }
    buffer[i] = 0;
    return i;
}

int  timeleft=30; //30 seconds timeout to setup the welcome screen
#define CMD_BUF_SIZE 80
#define DEFAULTREPO "HomeACcessoryKid/lcm-demo"
#define DEFAULTFILE "main.bin"
void serial_input(void *arg) {
    char cmd_buffer[CMD_BUF_SIZE];
    size_t len;
    wifi_config_t wifi_config = {
        .sta = {
            .scan_method = WIFI_ALL_CHANNEL_SCAN,
            .sort_method = WIFI_CONNECT_AP_BY_SIGNAL,
            .threshold.authmode = WIFI_AUTH_OPEN,
            .threshold.rssi = -127,
        },
    };

    printf(
    "\nLifeCycleManager4ESP32 version %s\n"
    "Will start Wifi AP for config if no input in 10 seconds\n"
    "Press <enter> to begin\n"
    "Too Late, Typo? Just restart\n"
    , esp_ota_get_app_description()->version);
    timeleft=10; //wait 10 seconds after presenting the welcome message
    len=tty_readline(cmd_buffer, CMD_BUF_SIZE); //collect the <enter>
    timeleft=1000; //wait 15+ minutes

    while (timeleft>1) {
//         printf( "Enter the ota repository or <enter> for " DEFAULTREPO "\n");
//         len=tty_readline(cmd_buffer, CMD_BUF_SIZE); //collect the otarepo
//         if (!len) strcpy(cmd_buffer,DEFAULTREPO);
//         sysparam_set_string("ota_repo",cmd_buffer);
//     
//         printf("Enter the ota file or <enter> for " DEFAULTFILE "\n");
//         len=tty_readline(cmd_buffer, CMD_BUF_SIZE); //collect the otafile
//         if (!len) strcpy(cmd_buffer,DEFAULTFILE);
//         sysparam_set_string("ota_file",cmd_buffer);
//     
//         printf("Enter the ota parameters or <enter> for \"\"\n");
//         len=tty_readline(cmd_buffer, CMD_BUF_SIZE); //collect the ota parameters
//         if (!len) strcpy(cmd_buffer,"");
//         sysparam_set_string("ota_string",cmd_buffer);
//     
//         printf("Enter the ota use of pre-release \"y\" or <enter> for not\n");
//         len=tty_readline(cmd_buffer, CMD_BUF_SIZE); //collect the otabeta
//         if (len) sysparam_set_string("ota_beta","y"); else sysparam_set_string("ota_beta","");
//     
//         printf("Enter the LED pin, use -15 till 15, or <enter> for not\n");
//         len=tty_readline(cmd_buffer, CMD_BUF_SIZE); //collect the ledpin
//         if (len) sysparam_set_int8("led_pin",atoi(cmd_buffer)); else sysparam_set_data("led_pin", NULL,0,0);
    
        printf("Enter the wifi SSID\n");
        tty_readline(cmd_buffer, CMD_BUF_SIZE); //collect the SSID
        strlcpy((char*)wifi_config.sta.ssid,cmd_buffer,32);
    
        printf("Enter the wifi password or <enter> to skip\n");
        len=tty_readline(cmd_buffer, CMD_BUF_SIZE); //collect the password
        if (len) { //if password, enforce WPA2_PSK minimum
            strlcpy((char*)wifi_config.sta.password,cmd_buffer,64);
            wifi_config.sta.threshold.authmode=WIFI_AUTH_WPA2_PSK;
        } else {
            wifi_config.sta.password[0]=0;
            wifi_config.sta.threshold.authmode=WIFI_AUTH_OPEN;
        }

//         printf("Result:\n");
//         status = sysparam_iter_start(&iter);
//         if (status < 0) timeleft=1;
//         while (true) {
//             status = sysparam_iter_next(&iter);
//             if (status != SYSPARAM_OK) break; //at the end SYSPARAM_NOTFOUND
//             printf("'%s'=",iter.key);
//             if (iter.binary) printf("%d\n",(int8_t)iter.value[0]);
//             else           printf("'%s'\n",(char *)iter.value);
//         }
//         sysparam_iter_end(&iter);
// 
        printf("\nPress <enter> if this is OK,\n"
                "Enter any other value to try again\n");
        len=tty_readline(cmd_buffer, CMD_BUF_SIZE); //collect the <enter>
        if (!len) {
//             sysparam_set_string("ota_version","0.0.0");
            ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
            timeleft=1;
        }
    }
    while (1) vTaskDelay(200); //wait for the end
}    


void timeout_task(void *arg) {
    while(timeleft-->0) {
        vTaskDelay(1000/portTICK_PERIOD_MS); //1 second
    }
    vTaskDelete(arg);
    
    if (wifi_config_station_connect()) {
        wifi_config_softap_start();
    }   
    vTaskDelete(NULL);
}

static void on_got_ip(void *arg,esp_event_base_t event_base,int32_t event_id,void *event_data) {
    INFO("Got IP");
    xTimerStop(context->sta_connect_timeout,0);
    wifi_config_softap_stop();
    if (context->on_wifi_ready)
        context->on_wifi_ready();
    wifi_config_context_free(context);
    context = NULL;
}

TaskHandle_t xHandle = NULL;
void wifi_config_init(const char *ssid_prefix, const char *password, void (*on_wifi_ready)()) {
    INFO("Initializing WiFi config");
    if (password && strlen(password) < 8) {
        ERROR("Password should be at least 8 characters");
        return;
    }

    context = malloc(sizeof(wifi_config_context_t));
    memset(context, 0, sizeof(*context));

    context->ssid_prefix = strndup(ssid_prefix, 33-7);
    if (password)
        context->password = strdup(password);

    context->on_wifi_ready = on_wifi_ready;

    context->sta_connect_timeout=xTimerCreate("timer",15000/portTICK_PERIOD_MS,pdFALSE,(void*)context,wifi_config_sta_connect_timeout_callback);

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    esp_netif_inherent_config_t esp_netif_config = ESP_NETIF_INHERENT_DEFAULT_WIFI_STA();
    esp_netif_config.route_prio = 128;
    esp_netif_create_wifi(WIFI_IF_STA, &esp_netif_config);
    esp_wifi_set_default_wifi_sta_handlers();
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_FLASH));
    esp_wifi_set_mode(WIFI_MODE_STA); //TODO: does this prevent a flash write if not changed?

    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &on_got_ip, NULL));

    if (wifi_config_station_connect()) {
        xTaskCreate(serial_input,"serial" ,2048,NULL,1,&xHandle);
        xTaskCreate(timeout_task,"timeout",2048,xHandle,1,NULL);
    }
}


// void wifi_config_reset() {
//     sysparam_set_string("wifi_ssid", "");
//     sysparam_set_string("wifi_password", "");
// }
// 
// 
// void wifi_config_get(char **ssid, char **password) {
//     sysparam_get_string("wifi_ssid", ssid);
//     sysparam_get_string("wifi_password", password);
// }
// 
// 
// void wifi_config_set(const char *ssid, const char *password) {
//     sysparam_set_string("wifi_ssid", ssid);
//     sysparam_set_string("wifi_password", password);
// }
