#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "esp_http_client.h"
#include "esp_flash_partitions.h"
#include "esp_partition.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "driver/gpio.h"
#include "protocol_examples_common.h"
#include "errno.h"

#if CONFIG_EXAMPLE_CONNECT_WIFI
#include "esp_wifi.h"
#endif
//===============================
#define UDPLGP printf  //TODO: replace inline

#include "ota.h"

bool userbeta=0;
bool otabeta=0;
// int8_t led=16;

void  ota_active_sector() {
    UDPLGP("--- ota_active_sector: ");
    extern int active_cert_sector;
    extern int backup_cert_sector;
    // set active_cert_sector
    // first byte of the sector is its state:
    // 0xff backup being evaluated
    // 0x30 active sector
    // 0x00 deactivated
//     byte fourbyte[4];
    active_cert_sector=HIGHERCERTSECTOR;
    backup_cert_sector=LOWERCERTSECTOR;
//     if (!spiflash_read(active_cert_sector, (byte *)fourbyte, 4)) { //get first 4 active
//         UDPLGP("error reading flash\n");
//     } // if OTHER  vvvvvv sector active
//     if (fourbyte[0]!=0x30 || fourbyte[1]!=0x76 || fourbyte[2]!=0x30 || fourbyte[3]!=0x10 ) {
//         active_cert_sector=LOWERCERTSECTOR;
//         backup_cert_sector=HIGHERCERTSECTOR;
//         if (!spiflash_read(active_cert_sector, (byte *)fourbyte, 4)) {
//             UDPLGP("error reading flash\n");
//         }
//         if (fourbyte[0]!=0x30 || fourbyte[1]!=0x76 || fourbyte[2]!=0x30 || fourbyte[3]!=0x10 ) {
// #ifdef OTABOOT
//             #include "certs.h"
//             active_cert_sector=HIGHERCERTSECTOR;
//             backup_cert_sector=LOWERCERTSECTOR;
//             spiflash_erase_sector(active_cert_sector); //just in case
//             spiflash_write(active_cert_sector, certs_sector, certs_sector_len);
// #else
//             active_cert_sector=0;
//             backup_cert_sector=0;
// #endif
//         }
//     }
    UDPLGP("0x%x\n",active_cert_sector);
}

void  ota_init() {
    UDPLGP("--- ota_init\n");

//     sysparam_get_bool("lcm_beta", &otabeta);
//     sysparam_get_bool("ota_beta", &userbeta);
    UDPLGP("userbeta=\'%d\' otabeta=\'%d\'\n",userbeta,otabeta);

//     ip_addr_t target_ip;
//     int ret;
    
//     sysparam_status_t status;
//     uint8_t led_info=0;
// 
//     status = sysparam_get_int8("led_pin", &led);
//     if (status == SYSPARAM_OK) {
//         if (led<0) {led_info=0x10; led=-led;}
//         led_info+=(led<16)?(0x40+(led&0x0f)):0;
//         if (led<16) xTaskCreate(led_blink_task, "ledblink", 256, NULL, 1, &ledblinkHandle);
//     }

//     //rboot setup
//     rboot_config conf;
//     conf=rboot_get_config();
//     UDPLGP("rboot_config.unused[1]=LEDinfo from 0x%02x to 0x%02x\n",conf.unused[1],led_info);
//     if (conf.count!=2 || conf.roms[0]!=BOOT0SECTOR || conf.roms[1]!=BOOT1SECTOR || conf.current_rom!=0 || conf.unused[1]!=led_info) {
//         conf.count =2;   conf.roms[0] =BOOT0SECTOR;   conf.roms[1] =BOOT1SECTOR;   conf.current_rom =0;   conf.unused[1] =led_info;
//         rboot_set_config(&conf);
//     }
    
//     //time support
//     const char *servers[] = {SNTP_SERVERS};
// 	sntp_set_update_delay(24*60*60000); //SNTP will request an update every 24 hour
// 	//const struct timezone tz = {1*60, 0}; //Set GMT+1 zone, daylight savings off
// 	//sntp_initialize(&tz);
// 	sntp_initialize(NULL);
// 	sntp_set_servers(servers, sizeof(servers) / sizeof(char*)); //Servers must be configured right after initialization

    
//     wolfSSL_Init();
// 
//     ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
//     if (!ctx) {
//         //error
//     }
    ota_active_sector();
//     ota_set_verify(0);
//     UDPLGP("--- DNS: ");
//     ret = netconn_gethostbyname(HOST, &target_ip);
//     while(ret) {
//         UDPLGP("%d",ret);
//         vTaskDelay(200);
//         ret = netconn_gethostbyname(HOST, &target_ip);
//     }
    UDPLGP("done!\n");
}

void  ota_write_status(char * version) {
    UDPLGP("--- ota_write_status\n");
    
//     sysparam_set_string("ota_version", version);
}

int   ota_boot(void) {
    UDPLGP("--- ota_boot...");
    byte bootrom;
//     rboot_get_last_boot_rom(&bootrom);
    const esp_partition_t *running = esp_ota_get_running_partition();
    if (running->subtype==ESP_PARTITION_SUBTYPE_APP_OTA_0) bootrom=0; else bootrom=1;
    
    UDPLGP("%d\n",bootrom);
    return 1-bootrom;
}




//===================================================
#define BUFFSIZE 1024

static const char *TAG = "native_ota_library";
/*an ota data write buffer ready to write to the flash*/
static char ota_write_data[BUFFSIZE + 1] = { 0 };
extern const uint8_t server_cert_pem_start[] asm("_binary_ca_cert_pem_start");
extern const uint8_t server_cert_pem_end[] asm("_binary_ca_cert_pem_end");

#define OTA_URL_SIZE 256

static void http_cleanup(esp_http_client_handle_t client)
{
    esp_http_client_close(client);
    esp_http_client_cleanup(client);
}

static void __attribute__((noreturn)) task_fatal_error(void)
{
    ESP_LOGE(TAG, "Exiting task due to fatal error...");
    (void)vTaskDelete(NULL);

    while (1) {
        ;
    }
}

static void infinite_loop(void)
{
    int i = 0;
    ESP_LOGI(TAG, "When a new firmware is available on the server, press the reset button to download it");
    while(1) {
        ESP_LOGI(TAG, "Waiting for a new firmware ... %d", ++i);
        vTaskDelay(2000 / portTICK_PERIOD_MS);
    }
}

void ota_example_task(void *pvParameter)
{
    esp_err_t err;
    /* update handle : set by esp_ota_begin(), must be freed via esp_ota_end() */
    esp_ota_handle_t update_handle = 0 ;
    const esp_partition_t *update_partition = NULL;

    ESP_LOGI(TAG, "Starting OTA example");

    const esp_partition_t *configured = esp_ota_get_boot_partition();
    const esp_partition_t *running = esp_ota_get_running_partition();

    if (configured != running) {
        ESP_LOGW(TAG, "Configured OTA boot partition at offset 0x%08x, but running from offset 0x%08x",
                 configured->address, running->address);
        ESP_LOGW(TAG, "(This can happen if either the OTA boot data or preferred boot image become corrupted somehow.)");
    }
    ESP_LOGI(TAG, "Running partition type %d subtype %d (offset 0x%08x)",
             running->type, running->subtype, running->address);

    esp_http_client_config_t config = {
        .url = "https://github.com/HomeACcessoryKid/LCM4ESP32/releases/latest",
        .cert_pem = (char *)server_cert_pem_start,
        .timeout_ms = CONFIG_EXAMPLE_OTA_RECV_TIMEOUT,
        .keep_alive_enable = true,
        .buffer_size    = 1024,
        .buffer_size_tx = 1024,
    };

    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (client == NULL) {
        ESP_LOGE(TAG, "Failed to initialise HTTP connection");
        task_fatal_error();
    }
    err = esp_http_client_open(client, 0);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to perform HTTP connection: %s", esp_err_to_name(err));
        esp_http_client_cleanup(client);
        task_fatal_error();
    }
    esp_http_client_fetch_headers(client);
    int code=esp_http_client_get_status_code(client);
    printf("code=%d\n",code);
//     this doesn't work because it doesn't actually flush the internal buffer
//     int flushlen;
//     printf("result %d of ",esp_http_client_flush_response(client,&flushlen));
//     printf("flushed %d\n",flushlen);
    ota_write_data[esp_http_client_read(client, ota_write_data, BUFFSIZE)]=0;
    printf("flushed: %s\n",ota_write_data);
    
//     this doesn't work because client struct set up as private...
//     printf("loca=%s\n",&client->location);
    esp_http_client_set_redirection(client);
    char url[500];
    esp_http_client_get_url(client, url, 500);
    printf("URL=%s\n",url);
    char *found_ptr=strstr(url,"releases/tag/");
    if (found_ptr[13]=='v' || found_ptr[13]=='V') found_ptr++;
    char *version=malloc(strlen(found_ptr+13));
    strcpy(version,found_ptr+13);
    printf("version:\"%s\"\n",version);

    esp_http_client_set_url(client,"https://github.com/HomeACcessoryKid/LCM4ESP32/releases/download/0.0.2/LCM4ESP32.bin");

    err = esp_http_client_open(client, 0);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to perform HTTP connection: %s", esp_err_to_name(err));
        esp_http_client_cleanup(client);
        task_fatal_error();
    }
    esp_http_client_fetch_headers(client);

    code=esp_http_client_get_status_code(client);
    printf("code=%d\n",code);
    
    if (code==302) {
        ota_write_data[esp_http_client_read(client, ota_write_data, BUFFSIZE)]=0;
        printf("flushed: %s\n",ota_write_data);        
        esp_http_client_set_redirection(client); // this fails because it still has the original location pre-pended to URL
    }

    err = esp_http_client_open(client, 0);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to perform HTTP connection: %s", esp_err_to_name(err));
        esp_http_client_cleanup(client);
        task_fatal_error();
    }
    esp_http_client_fetch_headers(client);    
    

    update_partition = esp_ota_get_next_update_partition(NULL);
    assert(update_partition != NULL);
    ESP_LOGI(TAG, "Writing to partition subtype %d at offset 0x%x",
             update_partition->subtype, update_partition->address);

    int binary_file_length = 0;
    /*deal with all receive packet*/
    bool image_header_was_checked = false;
    while (1) {
        int data_read = esp_http_client_read(client, ota_write_data, BUFFSIZE);
        if (data_read < 0) {
            ESP_LOGE(TAG, "Error: SSL data read error");
            http_cleanup(client);
            task_fatal_error();
        } else if (data_read > 0) {
            if (image_header_was_checked == false) {
                esp_app_desc_t new_app_info;
                if (data_read > sizeof(esp_image_header_t) + sizeof(esp_image_segment_header_t) + sizeof(esp_app_desc_t)) {
                    // check current version with downloading
                    memcpy(&new_app_info, &ota_write_data[sizeof(esp_image_header_t) + sizeof(esp_image_segment_header_t)], sizeof(esp_app_desc_t));
                    ESP_LOGI(TAG, "New firmware version: %s", new_app_info.version);

                    esp_app_desc_t running_app_info;
                    if (esp_ota_get_partition_description(running, &running_app_info) == ESP_OK) {
                        ESP_LOGI(TAG, "Running firmware version: %s", running_app_info.version);
                    }

                    const esp_partition_t* last_invalid_app = esp_ota_get_last_invalid_partition();
                    esp_app_desc_t invalid_app_info;
                    if (esp_ota_get_partition_description(last_invalid_app, &invalid_app_info) == ESP_OK) {
                        ESP_LOGI(TAG, "Last invalid firmware version: %s", invalid_app_info.version);
                    }

                    // check current version with last invalid partition
                    if (last_invalid_app != NULL) {
                        if (memcmp(invalid_app_info.version, new_app_info.version, sizeof(new_app_info.version)) == 0) {
                            ESP_LOGW(TAG, "New version is the same as invalid version.");
                            ESP_LOGW(TAG, "Previously, there was an attempt to launch the firmware with %s version, but it failed.", invalid_app_info.version);
                            ESP_LOGW(TAG, "The firmware has been rolled back to the previous version.");
                            http_cleanup(client);
                            infinite_loop();
                        }
                    }
#ifndef CONFIG_EXAMPLE_SKIP_VERSION_CHECK
                    if (memcmp(new_app_info.version, running_app_info.version, sizeof(new_app_info.version)) == 0) {
                        ESP_LOGW(TAG, "Current running version is the same as a new. We will not continue the update.");
                        http_cleanup(client);
                        infinite_loop();
                    }
#endif

                    image_header_was_checked = true;

                    err = esp_ota_begin(update_partition, OTA_WITH_SEQUENTIAL_WRITES, &update_handle);
                    if (err != ESP_OK) {
                        ESP_LOGE(TAG, "esp_ota_begin failed (%s)", esp_err_to_name(err));
                        http_cleanup(client);
                        esp_ota_abort(update_handle);
                        task_fatal_error();
                    }
                    ESP_LOGI(TAG, "esp_ota_begin succeeded");
                } else {
                    ESP_LOGE(TAG, "received package is not fit len");
                    http_cleanup(client);
                    esp_ota_abort(update_handle);
                    task_fatal_error();
                }
            }
            err = esp_ota_write( update_handle, (const void *)ota_write_data, data_read);
            if (err != ESP_OK) {
                http_cleanup(client);
                esp_ota_abort(update_handle);
                task_fatal_error();
            }
            binary_file_length += data_read;
            ESP_LOGD(TAG, "Written image length %d", binary_file_length);
        } else if (data_read == 0) {
           /*
            * As esp_http_client_read never returns negative error code, we rely on
            * `errno` to check for underlying transport connectivity closure if any
            */
            if (errno == ECONNRESET || errno == ENOTCONN) {
                ESP_LOGE(TAG, "Connection closed, errno = %d", errno);
                break;
            }
            if (esp_http_client_is_complete_data_received(client) == true) {
                ESP_LOGI(TAG, "Connection closed");
                break;
            }
        }
    }
    ESP_LOGI(TAG, "Total Write binary data length: %d", binary_file_length);
    if (esp_http_client_is_complete_data_received(client) != true) {
        ESP_LOGE(TAG, "Error in receiving complete file");
        http_cleanup(client);
        esp_ota_abort(update_handle);
        task_fatal_error();
    }

    err = esp_ota_end(update_handle);
    if (err != ESP_OK) {
        if (err == ESP_ERR_OTA_VALIDATE_FAILED) {
            ESP_LOGE(TAG, "Image validation failed, image is corrupted");
        } else {
            ESP_LOGE(TAG, "esp_ota_end failed (%s)!", esp_err_to_name(err));
        }
        http_cleanup(client);
        task_fatal_error();
    }

    err = esp_ota_set_boot_partition(update_partition);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_ota_set_boot_partition failed (%s)!", esp_err_to_name(err));
        http_cleanup(client);
        task_fatal_error();
    }
    ESP_LOGI(TAG, "Prepare to restart system in 30 seconds!");
    vTaskDelay(3000);
    esp_restart();
    return ;
}
