#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "freertos/FreeRTOS.h"
#include "freertos/timers.h"
#include "esp_wifi.h"
#include <lwip/sockets.h>
#include "form_urlencoded.h"
#include "esp_ota_ops.h"
#include "esp_https_server.h"
#include "nvs.h"

#define WIFI_CONFIG_SERVER_PORT 80

#ifndef WIFI_CONFIG_CONNECT_TIMEOUT
#define WIFI_CONFIG_CONNECT_TIMEOUT 15000
#endif

#define DEBUG(message, ...) printf(">>> wifi_config: %s: " message "\n", __func__, ##__VA_ARGS__);
#define INFO(message, ...) printf(">>> wifi_config: " message "\n", ##__VA_ARGS__);
#define ERROR(message, ...) printf("!!! wifi_config: " message "\n", ##__VA_ARGS__);


typedef struct {
    char *ssid_prefix;
    char *password;
    void (*on_wifi_ready)();

    TimerHandle_t sta_connect_timeout;
    TaskHandle_t https_task_handle;
    TaskHandle_t http_task_handle;
    TaskHandle_t dns_task_handle;
} wifi_config_context_t;

extern nvs_handle_t lcm_handle;

static wifi_config_context_t *context;

static int wifi_config_station_connect();
static void wifi_config_softap_start();
static void wifi_config_softap_stop();


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
#include "index.html.h"
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


static esp_err_t post_handler(httpd_req_t *req) {
    wifi_config_t wifi_config = {
        .sta = {
            .scan_method = WIFI_ALL_CHANNEL_SCAN,
            .sort_method = WIFI_CONNECT_AP_BY_SIGNAL,
            .threshold.authmode = WIFI_AUTH_OPEN,
            .threshold.rssi = -127,
        },
    };
    char body[512];
    httpd_req_recv(req,body,512);
    printf("collected: %s\n",body);
    form_param_t *form = form_params_parse(body);
    if (!form) {
//         client_send_redirect(client, 302, "/settings");
//         return;
        return ESP_OK;
    }

    form_param_t *ssid_param    = form_params_find(form, "ssid");
    form_param_t *password_param= form_params_find(form, "password");
//     form_param_t *led_pin_param = form_params_find(form, "led_pin");
//     form_param_t *led_pol_param = form_params_find(form, "led_pol");
    form_param_t *otarepo_param = form_params_find(form, "otarepo");
    form_param_t *otafile_param = form_params_find(form, "otafile");
    form_param_t *otastr_param  = form_params_find(form, "otastr");
    form_param_t *otabeta_param = form_params_find(form, "otabeta");
    form_param_t *otasrvr_param = form_params_find(form, "otasrvr");

    if (!ssid_param) {
        form_params_free(form);
//         client_send_redirect(client, 302, "/settings");
//         return;
        return ESP_OK;
    }

    httpd_resp_set_status(req,HTTPD_204); //TODO: better some user feedback?
    httpd_resp_send(req, NULL, 0);

    strlcpy((char*)wifi_config.sta.ssid,ssid_param->value,32);

    if (password_param) { //if password, enforce WPA2_PSK minimum
        strlcpy((char*)wifi_config.sta.password,password_param->value,64);
        wifi_config.sta.threshold.authmode=WIFI_AUTH_WPA2_PSK;
    } else {
        wifi_config.sta.password[0]=0;
        wifi_config.sta.threshold.authmode=WIFI_AUTH_OPEN;
    }
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));

//     if (led_pin_param && led_pin_param->value && led_pol_param && led_pol_param->value) {
//         if (strcmp(led_pin_param->value,"n")) 
//              sysparam_set_int8("led_pin", (strcmp(led_pol_param->value,"1")?1:-1) * atoi(led_pin_param->value));
//         else if (!strcmp(led_pol_param->value,"1")) sysparam_set_data("led_pin", NULL,0,0); //wipe only if "n" and ledpol=1
//     }
    if (otarepo_param && otarepo_param->value) nvs_set_str(lcm_handle,"ota_repo", otarepo_param->value);
    if (otafile_param && otafile_param->value) nvs_set_str(lcm_handle,"ota_file", otafile_param->value);
    if (otastr_param  && otastr_param->value)  nvs_set_str(lcm_handle,"ota_string",otastr_param->value);
    if (otabeta_param && otabeta_param->value) nvs_set_u8( lcm_handle,"ota_beta", otabeta_param->value[0]-0x30);
    if (otasrvr_param && otasrvr_param->value && strcmp(otasrvr_param->value,"not.github.com/somewhere/"))
                                               nvs_set_str(lcm_handle,"ota_srvr", otasrvr_param->value);
    nvs_commit(lcm_handle);
    form_params_free(form);

    vTaskDelay(500 / portTICK_PERIOD_MS);

    wifi_config_station_connect();
    
    return ESP_OK;
}

static esp_err_t get_handler(httpd_req_t *req) {
    //TODO: dynamic content
    httpd_resp_set_hdr(req,"Cache-Control","no-store");
    httpd_resp_send_chunk(req, html_settings_header,        HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, html_settings_middle,        HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, html_settings_otaparameters, HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, html_settings_otaserver,     HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, html_settings_footer,        HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

static const httpd_uri_t settings_get = {
    .uri       = "/settings",
    .method    = HTTP_GET,
    .handler   = get_handler
};

static const httpd_uri_t settings_post = {
    .uri       = "/settings",
    .method    = HTTP_POST,
    .handler   = post_handler
};

static void https_task(void *arg) {
    INFO("Starting HTTPS server");
    httpd_handle_t https_server = NULL;
    httpd_ssl_config_t conf = HTTPD_SSL_CONFIG_DEFAULT();

    extern const unsigned char cacert_pem_start[] asm("_binary_cacert_pem_start");//TODO: make this dynamic certs
    extern const unsigned char cacert_pem_end[]   asm("_binary_cacert_pem_end");
    conf.cacert_pem = cacert_pem_start;
    conf.cacert_len = cacert_pem_end - cacert_pem_start;

    extern const unsigned char prvtkey_pem_start[] asm("_binary_prvtkey_pem_start");
    extern const unsigned char prvtkey_pem_end[]   asm("_binary_prvtkey_pem_end");
    conf.prvtkey_pem = prvtkey_pem_start;
    conf.prvtkey_len = prvtkey_pem_end - prvtkey_pem_start;

    esp_err_t ret = httpd_ssl_start(&https_server, &conf);
    if (ret == ESP_OK) {
        httpd_register_uri_handler(https_server, &settings_get);
        httpd_register_uri_handler(https_server, &settings_post);
    } else {
        INFO("Error starting HTTPS server!");
    }
    
    bool running = true;
    while (running) {
        uint32_t task_value = 0;
        if (xTaskNotifyWait(0, 1, &task_value, 1) == pdTRUE) {
            if (task_value) {
                running = false;
                break;
            }
        }
    }
    INFO("Stopping HTTPS server");
    if (https_server) httpd_ssl_stop(https_server);
    context->https_task_handle=NULL;
    vTaskDelete(NULL);
}

static void https_start() {
    xTaskCreate(https_task, "wcHTTPS", 4096, NULL, 2, &context->https_task_handle);
}

static void https_stop() {
    if (! context->https_task_handle) return;
    xTaskNotify(context->https_task_handle, 1, eSetValueWithOverwrite);
}


static void client_send_redirect(int fd, int code, const char *redirect_url) {
    INFO("Redirecting to %s", redirect_url);
    char buffer[128];
    size_t len = snprintf(buffer, sizeof(buffer), "HTTP/1.1 %d \r\nLocation: %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", code, redirect_url);
    lwip_write(fd, buffer, len);
}

static void http_task(void *arg) {
    INFO("Starting HTTP server");

    struct sockaddr_in serv_addr;
    int listenfd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&serv_addr, '0', sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(WIFI_CONFIG_SERVER_PORT);
    int flags;
    if ((flags = lwip_fcntl(listenfd, F_GETFL, 0)) < 0) {
        ERROR("Failed to get HTTP socket flags");
        lwip_close(listenfd);
        vTaskDelete(NULL);
        return;
    };
    if (lwip_fcntl(listenfd, F_SETFL, flags | O_NONBLOCK) < 0) {
        ERROR("Failed to set HTTP socket flags");
        lwip_close(listenfd);
        vTaskDelete(NULL);
        return;
    }
    bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
    listen(listenfd, 2);

    char data[1024]; //usually a single request is less than 600?

    bool running = true;
    while (running) {
        uint32_t task_value = 0;
        if (xTaskNotifyWait(0, 1, &task_value, 0) == pdTRUE) {
            if (task_value) {
                running = false;
                break;
            }
        }

        int fd = accept(listenfd, (struct sockaddr *)NULL, (socklen_t *)NULL);
        if (fd < 0) {
            vTaskDelay(500 / portTICK_PERIOD_MS);
            continue;
        }

        const struct timeval timeout = { 2, 0 }; /* 2 second timeout */
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));


        for (;;) {
            int data_len = lwip_read(fd, data, sizeof(data));
            if (data_len > 0) {
                client_send_redirect(fd, 302, "https://192.168.4.1/settings");
            } else break;

            if (xTaskNotifyWait(0, 1, &task_value, 0) == pdTRUE) {
                if (task_value) {
                    running = false;
                    break;
                }
            }
        }
        INFO("Client disconnected");
        lwip_close(fd);
    }
    INFO("Stopping HTTP server");
    lwip_close(listenfd);
    context->http_task_handle=NULL;
    vTaskDelete(NULL);
}

static void http_start() {
    xTaskCreate(http_task, "wcHTTP", 4096, NULL, 2, &context->http_task_handle);
}

static void http_stop() {
    if (! context->http_task_handle) return;
    xTaskNotify(context->http_task_handle, 1, eSetValueWithOverwrite);
}


static void dns_task(void *arg) {
    INFO("Starting DNS server");

    ip4_addr_t server_addr;
    IP4_ADDR(&server_addr, 192, 168, 4, 1);

    struct sockaddr_in serv_addr;
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    memset(&serv_addr, '0', sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(53);
    bind(fd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));

    const struct timeval timeout = { 2, 0 }; /* 2 second timeout */
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

//     const struct ifreq ifreq1 = { "en1" };
//     setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &ifreq1, sizeof(ifreq1));

    for (;;) {
        char buffer[96];
        struct sockaddr src_addr;
        socklen_t src_addr_len = sizeof(src_addr);
        size_t count = recvfrom(fd, buffer, sizeof(buffer), 0, (struct sockaddr*)&src_addr, &src_addr_len);

        /* Drop messages that are too large to send a response in the buffer */
        if (count > 0 && count <= sizeof(buffer) - 16 && src_addr.sa_family == AF_INET) {
            size_t qname_len = strlen(buffer + 12) + 1;
            uint32_t reply_len = 2 + 10 + qname_len + 16 + 4;

            char *head = buffer + 2;
            *head++ = 0x80; // Flags
            *head++ = 0x00;
            *head++ = 0x00; // Q count
            *head++ = 0x01;
            *head++ = 0x00; // A count
            *head++ = 0x01;
            *head++ = 0x00; // Auth count
            *head++ = 0x00;
            *head++ = 0x00; // Add count
            *head++ = 0x00;
            head += qname_len;
            *head++ = 0x00; // Q type
            *head++ = 0x01;
            *head++ = 0x00; // Q class
            *head++ = 0x01;
            *head++ = 0xC0; // LBL offs
            *head++ = 0x0C;
            *head++ = 0x00; // Type
            *head++ = 0x01;
            *head++ = 0x00; // Class
            *head++ = 0x01;
            *head++ = 0x00; // TTL
            *head++ = 0x00;
            *head++ = 0x00;
            *head++ = 0x78;
            *head++ = 0x00; // RD len
            *head++ = 0x04;
            *head++ = ip4_addr1(&server_addr);
            *head++ = ip4_addr2(&server_addr);
            *head++ = ip4_addr3(&server_addr);
            *head++ = ip4_addr4(&server_addr);

            sendto(fd, buffer, reply_len, 0, &src_addr, src_addr_len);
        }

        uint32_t task_value = 0;
        if (xTaskNotifyWait(0, 1, &task_value, 0) == pdTRUE) {
            if (task_value)
                break;
        }
    }

    INFO("Stopping DNS server");

    lwip_close(fd);

    context->dns_task_handle=NULL;
    vTaskDelete(NULL);
}

static void dns_start() {
    xTaskCreate(dns_task, "wcDNS", 2048, NULL, 2, &context->dns_task_handle);
}

static void dns_stop() {
    if (!context->dns_task_handle) return;
    xTaskNotify(context->dns_task_handle, 1, eSetValueWithOverwrite);
}


static void wifi_config_context_free(wifi_config_context_t *context) {
    if (context->ssid_prefix)
        free(context->ssid_prefix);

    if (context->password)
        free(context->password);

    free(context);
}

static void wifi_config_softap_start() {
    wifi_mode_t mode; esp_wifi_get_mode(&mode);
    if (mode==WIFI_MODE_APSTA) {
        INFO("AP mode already started");
        return;
    }
    INFO("Starting AP mode");
    esp_wifi_set_mode(WIFI_MODE_APSTA);
    uint8_t macaddr[6];
    esp_read_mac(macaddr, ESP_MAC_WIFI_STA);
    wifi_config_t softap_config = {
        .ap = {
            .channel=6,
            .authmode = WIFI_AUTH_OPEN,
            .max_connection = 2,
            .ssid_hidden = 0,
        },
    };
    softap_config.ap.ssid_len = snprintf(
        (char *)softap_config.ap.ssid, sizeof(softap_config.ap.ssid),
        "%s-%02X%02X%02X", context->ssid_prefix, macaddr[3], macaddr[4], macaddr[5]
    );
    if (context->password) {
        softap_config.ap.authmode = WIFI_AUTH_WPA2_PSK;
        strncpy((char *)softap_config.ap.password,
                context->password, sizeof(softap_config.ap.password));
    }
    INFO("Starting AP SSID=%s", softap_config.ap.ssid);

    esp_netif_t *ap_netif = esp_netif_create_default_wifi_ap();
    assert(ap_netif);

    esp_netif_ip_info_t ap_ip;
    IP4_ADDR(&ap_ip.ip, 192, 168, 4, 1);
    IP4_ADDR(&ap_ip.netmask, 255, 255, 255, 0);
    IP4_ADDR(&ap_ip.gw, 0, 0, 0, 0);
    esp_netif_set_ip_info(ap_netif, &ap_ip);
    INFO("Starting DHCP server");
    esp_netif_dhcps_start(ap_netif); //all settings seem to be automatic
    esp_wifi_set_config(ESP_IF_WIFI_AP, &softap_config);

//     wifi_networks_mutex = xSemaphoreCreateBinary();
//     xSemaphoreGive(wifi_networks_mutex);
// 
//     xTaskCreate(wifi_scan_task, "wifi_config scan", 2048, NULL, 2, NULL);
// 
    dns_start();
    http_start();
    https_start();
}


static void wifi_config_softap_stop() {
//     dhcpserver_stop();
    wifi_mode_t mode; esp_wifi_get_mode(&mode);
    if (mode==WIFI_MODE_STA) return;
    INFO("Stopping AP mode");
    dns_stop();
    http_stop();
    https_stop();
    while (context->dns_task_handle || context->http_task_handle || context->https_task_handle) vTaskDelay(20/ portTICK_PERIOD_MS);
    esp_wifi_set_mode(WIFI_MODE_STA);
    INFO("Stopped AP mode");
}


static void wifi_config_sta_connect_timeout_callback(TimerHandle_t context) {    
    INFO("Timeout connecting to WiFi network, starting config AP");
    // Not connected to station, launch configuration AP
    wifi_config_softap_start();
}


static int wifi_config_station_connect() {
    wifi_config_t wifi_config;
    esp_wifi_get_config(WIFI_IF_STA, &wifi_config);
    if (wifi_config.sta.ssid[0]==0) {
        INFO("No configuration found");
        return -1;
    }
    INFO("Found configuration, trying to connect to %s", wifi_config.sta.ssid);
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
        printf( "Enter the ota repository or <enter> for " DEFAULTREPO "\n");
        len=tty_readline(cmd_buffer, CMD_BUF_SIZE); //collect the otarepo
        if (!len) strcpy(cmd_buffer,DEFAULTREPO);
        nvs_set_str(lcm_handle,"ota_repo",cmd_buffer);
    
        printf("Enter the ota file or <enter> for " DEFAULTFILE "\n");
        len=tty_readline(cmd_buffer, CMD_BUF_SIZE); //collect the otafile
        if (!len) strcpy(cmd_buffer,DEFAULTFILE);
        nvs_set_str(lcm_handle,"ota_file",cmd_buffer);
    
        printf("Enter the ota parameters or <enter> for \"\"\n");
        len=tty_readline(cmd_buffer, CMD_BUF_SIZE); //collect the ota parameters
        if (!len) strcpy(cmd_buffer,"");
        nvs_set_str(lcm_handle,"ota_string",cmd_buffer);
    
        printf("Enter the ota use of pre-release \"y\" or <enter> for not\n");
        len=tty_readline(cmd_buffer, CMD_BUF_SIZE); //collect the otabeta
        nvs_set_u8(lcm_handle,"ota_beta", len?1:0);
    
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

        printf("Result:\n");
        char    string[64];
        size_t  size=64;
        uint8_t number;
        //TODO: add readout of ssid and password here
        nvs_iterator_t it = nvs_entry_find("nvs", "LCM", NVS_TYPE_ANY);
        while (it != NULL) {
            nvs_entry_info_t info;
            nvs_entry_info(it, &info);
            it = nvs_entry_next(it);
            printf("namespace:%-15s key:%-15s type:%2d  value: ", info.namespace_name, info.key, info.type);
            if (info.type==0x21) { //string
                string[0]=0;
                nvs_get_str(lcm_handle,info.key,string,&size);
                printf("'%s'\n",string);
            } else { //number
                nvs_get_u8(lcm_handle,info.key,&number);
                printf("%d\n",number);
            }
        }

        printf("\nPress <enter> if this is OK,\n"
                "Enter any other value to try again\n");
        len=tty_readline(cmd_buffer, CMD_BUF_SIZE); //collect the <enter>
        if (!len) {
            nvs_set_str(lcm_handle,"ota_version","0.0.0");
            nvs_commit(lcm_handle);
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
    esp_wifi_set_country_code("01", 0); //world safe mode
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &on_got_ip, NULL));

    ESP_ERROR_CHECK(esp_wifi_start()); //TODO: is this the right place?
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
