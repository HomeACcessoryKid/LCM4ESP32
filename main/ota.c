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

#include "ota.h"
#include "mbedtls/sha512.h" //contains sha384 support
#define BUFFSIZE 1024
#define NAME2SECTOR(sectorname) esp_partition_find_first(ESP_PARTITION_TYPE_ANY,ESP_PARTITION_SUBTYPE_ANY,sectorlabel[sectorname])

static const char *TAG = "native_ota_library";
/*an ota data write buffer ready to write to the flash*/
static char http_buffer[BUFFSIZE + 1] = { 0 };

char sectorlabel[][10]={"zero","lcmcert_1","lcmcert_2","ota_0","ota_1"}; //label of sector in partition table to index. zero reserved
bool userbeta=0;
bool otabeta=0;
// int8_t led=16;
esp_http_client_handle_t client1=NULL, client2=NULL;

static void __attribute__((noreturn)) task_fatal_error(void){
    ESP_LOGE(TAG, "Exiting task due to fatal error...");
    (void)vTaskDelete(NULL);
    while (1) {;}
}

void  ota_active_sector() {
    UDPLGP("--- ota_active_sector: ");
    // set active_cert_sector
    // first byte of the sector is its state:
    // 0xff backup being evaluated
    // 0x30 active sector
    // 0x00 deactivated
    byte fourbyte[4];
    active_cert_sector=HIGHERCERTSECTOR;
    backup_cert_sector=LOWERCERTSECTOR;
    if (esp_partition_read(NAME2SECTOR(active_cert_sector),0,(byte *)fourbyte,4)!=ESP_OK) {
        UDPLGP("error reading flash\n");
    } // if OTHER  vvvvvv sector active
    if (fourbyte[0]!=0x30 || fourbyte[1]!=0x76 || fourbyte[2]!=0x30 || fourbyte[3]!=0x10 ) {
        active_cert_sector=LOWERCERTSECTOR;
        backup_cert_sector=HIGHERCERTSECTOR;
        if (esp_partition_read(NAME2SECTOR(active_cert_sector),0,(byte *)fourbyte,4)!=ESP_OK) {
            UDPLGP("error reading flash\n");
        }
        if (fourbyte[0]!=0x30 || fourbyte[1]!=0x76 || fourbyte[2]!=0x30 || fourbyte[3]!=0x10 ) {
#ifdef OTABOOT
            #include "certs.h"
            active_cert_sector=HIGHERCERTSECTOR;
            backup_cert_sector=LOWERCERTSECTOR;
            esp_partition_erase_range(NAME2SECTOR(active_cert_sector),0,SECTORSIZE);
            esp_partition_write(NAME2SECTOR(active_cert_sector),0,certs_sector, certs_sector_len);
            if (esp_partition_read(NAME2SECTOR(active_cert_sector),0,(byte *)fourbyte,4)!=ESP_OK) {
                UDPLGP("error reading flash\n");
            } // if OTHER  vvvvvv sector active
            if (fourbyte[0]!=0x30 || fourbyte[1]!=0x76 || fourbyte[2]!=0x30 || fourbyte[3]!=0x10 ) {
                active_cert_sector=0;
                backup_cert_sector=0;
            }
#else
            active_cert_sector=0;
            backup_cert_sector=0;
#endif
        }
    }
    
    UDPLGP("%s\n",sectorlabel[active_cert_sector]);
}

char location[600];
esp_err_t ota_event_handler(esp_http_client_event_t *evt){
    if (evt->event_id==HTTP_EVENT_ON_HEADER && !strcasecmp(evt->header_key,"location")) {
        strcpy(location,evt->header_value);
    }
    return ESP_OK;
}

static int  verify = 1;
void  ota_set_verify(int onoff) {
    UDPLGP("--- ota_set_verify...");
    
    if (onoff) {
        UDPLGP("ON\n");
        if (verify==0) {
            verify= 1;

//             ret=wolfSSL_CTX_load_verify_buffer(ctx, certs, ret, SSL_FILETYPE_PEM);
//             if ( ret != SSL_SUCCESS) {
//                 UDPLGP("fail cert loading, return %d\n", ret);
//             }
//             free(certs);
//             
            time_t ts;
//             do {
                ts = time(NULL);
//                 if (ts == ((time_t)-1)) printf("ts=-1, ");
//                 vTaskDelay(1);
//             } while (!(ts>1073741823)); //2^30-1 which is supposed to be like 2004
            UDPLGP("TIME: %s", ctime(&ts)); //we need to have the clock right to check certificates
            
//             wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        }
    } else {
        UDPLGP("OFF\n");
        if (verify==1) {
            verify= 0;
//             wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
        }
    }
}

char *certs=NULL;
void  ota_init() {
    UDPLGP("--- ota_init\n");

    int size=0;
    byte abyte[1];
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

    ota_active_sector();
    
    do {
        if (esp_partition_read(NAME2SECTOR(active_cert_sector),PKEYSIZE+(size++), (byte *)abyte, 1)!=ESP_OK) {
            UDPLGP("error reading flash\n");
            break;
        }
    } while (abyte[0]!=0xff); size--;
    UDPLGP("certs size: %d\n",size);
    certs=malloc(size);
    esp_partition_read(NAME2SECTOR(active_cert_sector),PKEYSIZE, (byte *)certs, size);
    esp_http_client_config_t config1 = {
        .url = "https://" CONFIG_LCM_GITHOST "/",
        .cert_pem = certs,
        .timeout_ms = CONFIG_EXAMPLE_OTA_RECV_TIMEOUT,
        .keep_alive_enable = true,
        .buffer_size    = 1024,
        .buffer_size_tx = 1024,
        .event_handler = ota_event_handler,
    };
    client1 = esp_http_client_init(&config1);
    if (client1 == NULL) {
        ESP_LOGE(TAG, "Failed to initialise HTTP connection");
        task_fatal_error();
    }

    ota_set_verify(0);
}

int   ota_load_user_app(char * *repo, char * *version, char * *file) {
    UDPLGP("--- ota_load_user_app\n");
//     sysparam_status_t status;
//     char *value;
// 
//     status = sysparam_get_string("ota_repo", &value);
//     if (status == SYSPARAM_OK) {
//         *repo=value;
//     } else return -1;
//     status = sysparam_get_string("ota_version", &value);
//     if (status == SYSPARAM_OK) {
//         *version=value;
//     } else {
//         *version=malloc(6);
//         strcpy(*version,"0.0.0");
//     }
//     status = sysparam_get_string("ota_file", &value);
//     if (status == SYSPARAM_OK) {
//         *file=value;
//     } else return -1;
    *repo="HomeACcessoryKid/life-cycle-manager";
    *version="0.0.1";
    *file="otaboot.bin";

    UDPLGP("user_repo=\'%s\' user_version=\'%s\' user_file=\'%s\'\n",*repo,*version,*file);
    return 0;
}

int   ota_get_file_ex(char * repo, char * version, char * file, int sector, byte * buffer, int bufsz) { //number of bytes
    UDPLGP("--- ota_get_file_ex\n");

    char* found_ptr=NULL;
    bool emergency=(strcmp(version,EMERGENCY))?0:1;
    int data_read=0;
    int collected=0;
    esp_err_t err;
    esp_ota_handle_t handle=0;
    
    if (sector==0 && buffer==NULL) return -5; //needs to be either a sector or a signature
    
    if (!emergency) { //if not emergency, find the redirection done by GitHub
        snprintf(location,600,"https://%s/%s/releases/download/%s/%s",CONFIG_LCM_GITHOST,repo,version,file);
        esp_http_client_set_url(client1,location);
    } else { //emergency mode, repo is expected to have the format "not.github.com/somewhere/"
//         esp_http_client_set_url(client,);
    } //loaded the right url
    printf("URL1=%s\n",location);
    err = esp_http_client_open(client1, 0);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to perform HTTP connection: %s", esp_err_to_name(err));
        esp_http_client_cleanup(client1);
        task_fatal_error();
    }
    esp_http_client_fetch_headers(client1);
    int code=esp_http_client_get_status_code(client1);
    printf("code1=%d\n",code);
    
    if (code==302) {
        http_buffer[esp_http_client_read(client1, http_buffer, BUFFSIZE)]=0;
        if (http_buffer[0]) printf("flushed: %s\n",http_buffer);
        //now setup client2 with location as url
        if (client2==NULL) {
            esp_http_client_config_t config2 = {
                .url = location,
                .cert_pem = certs,
                .timeout_ms = CONFIG_EXAMPLE_OTA_RECV_TIMEOUT,
                .keep_alive_enable = true,
                .buffer_size    = 1024,
                .buffer_size_tx = 1024,
            };
            client2 = esp_http_client_init(&config2);
            if (client2 == NULL) {
                ESP_LOGE(TAG, "Failed to initialise HTTP connection");
                task_fatal_error();
            }
        } else {
            esp_http_client_set_url(client2,location);
        } //now url is set for client2
        printf("URL2=%s\n",location);
        err = esp_http_client_open(client2, 0);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "Failed to perform HTTP connection: %s", esp_err_to_name(err));
            esp_http_client_cleanup(client2);
            task_fatal_error();
        }
        esp_http_client_fetch_headers(client2);
        int code=esp_http_client_get_status_code(client2);
        printf("code2=%d\n",code);
        while (1) {
            data_read = esp_http_client_read(client2, http_buffer, BUFFSIZE);
            if (data_read < 0) {
                ESP_LOGE(TAG, "Error: SSL data read error");
                esp_http_client_cleanup(client2);
                task_fatal_error();
            } else if (data_read > 0) {
                if (sector>2) {//ota partitions
                    if (!collected) {
                        esp_ota_begin(NAME2SECTOR(sector),
                        OTA_WITH_SEQUENTIAL_WRITES, &handle);
                    }
                    esp_ota_write(handle,(const void *)http_buffer,data_read);
                } else if (sector) {//cert_sectors
                    if (!collected) { //TODO add first byte concept
                        esp_partition_erase_range(NAME2SECTOR(sector),0,SECTORSIZE);
                    }
                    esp_partition_write(NAME2SECTOR(sector),collected,http_buffer,data_read);
                } else {//buffer
                    memcpy(buffer+collected,http_buffer,data_read);
                }
                collected+=data_read;
            } else if (data_read == 0) {
                // As esp_http_client_read never returns negative error code, we rely on
                // `errno` to check for underlying transport connectivity closure if any
                if (errno == ECONNRESET || errno == ENOTCONN) {
                    ESP_LOGE(TAG, "Connection closed, errno = %d", errno);
                    break;
                }
                if (esp_http_client_is_complete_data_received(client2) == true) {
                    printf("Transfer Complete: ");
                    break;
                }
            }
        }
        if (sector>2) {//ota partitions
            esp_ota_end(handle);
            printf("data length=%d, sector written=%s\n",collected,sectorlabel[sector]);
        } else if (sector) {//cert_sectors
            printf("data length=%d, sector written=%s\n",collected,sectorlabel[sector]);
        } else {//buffer
            printf("data length=%d, buffer=%02x%02x %02x%02x ... %02x%02x %02x%02x\n",collected,
            buffer[0],buffer[1],buffer[2],buffer[3],buffer[collected-4],
            buffer[collected-3],buffer[collected-2],buffer[collected-1]);
        }
        if (esp_http_client_is_complete_data_received(client2) != true) {
            ESP_LOGE(TAG, "Error in receiving complete file");
            return -5; //TODO check values
        }
    }
    return collected;
}

int   ota_get_file(char * repo, char * version, char * file, int sector) { //number of bytes
    UDPLGP("--- ota_get_file\n");
    return ota_get_file_ex(repo,version,file,sector,NULL,0);
}

char* ota_get_version(char * repo) {
    UDPLGP("--- ota_get_version\n");

    char* version=NULL;
    char prerelease[64]; 
    esp_err_t err;
    
    snprintf(location,600,"https://%s/%s/releases/latest",CONFIG_LCM_GITHOST,repo);
    esp_http_client_set_url(client1,location);
    err = esp_http_client_open(client1, 0);
    if (err != ESP_OK) { //TODO make this a macro
        ESP_LOGE(TAG, "Failed to perform HTTP connection: %s", esp_err_to_name(err));
        esp_http_client_cleanup(client1);
        task_fatal_error();
    }
    esp_http_client_fetch_headers(client1);
    int code=esp_http_client_get_status_code(client1);
    printf("code=%d\n",code);
    if (code==302) {
        // this doesn't work because it doesn't actually flush the internal buffer
        // int flushlen;
        // printf("result %d of ",esp_http_client_flush_response(client1,&flushlen));
        // printf("flushed %d\n",flushlen);
        http_buffer[esp_http_client_read(client1, http_buffer, BUFFSIZE)]=0;
        char *found_ptr=strstr(location,"releases/tag/");
        if (found_ptr[13]=='v' || found_ptr[13]=='V') found_ptr++;
        version=malloc(strlen(found_ptr+13));
        strcpy(version,found_ptr+13);
        location[0]=0;
    } else {
        return "404";
    }
//     //find latest-pre-release if joined beta program
//     bool OTAorBTL=!(strcmp(OTAREPO,repo)&&strcmp(BTLREPO,repo));
//     if ( (userbeta && !OTAorBTL) || (otabeta && OTAorBTL)) {
//         prerelease[63]=0;
//         ret=ota_get_file_ex(repo,version,"latest-pre-release",0,(byte *)prerelease,63);
//         if (ret>0) {
//             prerelease[ret]=0; //TODO: UNTESTED make a final 0x0a and or 0x0d optional
//             if (prerelease[ret-1]=='\n') {
//                 prerelease[ret-1]=0;
//                 if (prerelease[ret-2]=='\r') prerelease[ret-2]=0;                
//             }
//             free(version);
//             version=malloc(strlen(prerelease)+1);
//             strcpy(version,prerelease);
//         }
//     }
//     
//     if (ota_boot() && ota_compare(version,OTAVERSION)<0) { //this acts when setting up a new version
//         free(version);
//         version=malloc(strlen(OTAVERSION)+1);
//         strcpy(version,OTAVERSION);
//     }
    UDPLGP("%s@version:\"%s\"\n",repo,version);
    return version;
}

int ota_get_pubkey(int sector) { //get the ecdsa key from the indicated sector, report filesize
    UDPLGP("--- ota_get_pubkey\n");
    
    byte buf[PKEYSIZE];
    byte * buffer=buf;
    int length,ret=0;
    //load public key as produced by openssl
    if (esp_partition_read(NAME2SECTOR(sector),
                                                    0,(byte *)buffer, PKEYSIZE)!=ESP_OK) {
        UDPLGP("error reading flash\n");    return -1;
    }
    //do not test the first byte since else the key-update routine will not be able to collect a key
    if (buffer[ 1]!=0x76 || buffer[ 2]!=0x30 || buffer[ 3]!=0x10) return -2; //not a valid keyformat
    if (buffer[20]!=0x03 || buffer[21]!=0x62 || buffer[22]!=0x00) return -2; //not a valid keyformat
    length=97;
    
    int idx; for (idx=0;idx<length;idx++) printf(" %02x",buffer[idx+23]);
//     wc_ecc_init(&pubecckey);
//     ret=wc_ecc_import_x963_ex(buffer+23,length,&pubecckey,ECC_SECP384R1);
    printf("\n");
    UDPLGP("ret: %d\n",ret);

    if (!ret)return PKEYSIZE; else return ret;
}

void ota_hash(int start_sector, int filesize, byte * hash, byte first_byte) {
    UDPLGP("--- ota_hash\n");
    
    int bytes;
    byte buffer[1024];
    mbedtls_sha512_context sha;
    
    mbedtls_sha512_init(&sha);
    mbedtls_sha512_starts_ret(&sha,1); //SHA384
    //printf("bytes: ");
    for (bytes=0;bytes<filesize-1024;bytes+=1024) {
        //printf("%d ",bytes);
        if (esp_partition_read(NAME2SECTOR(start_sector),bytes,(byte *)buffer,1024)!=ESP_OK) {
            UDPLGP("error reading flash\n");   break;
        }
        if (!bytes && first_byte!=0xff) buffer[0]=first_byte;
        mbedtls_sha512_update_ret(&sha, buffer, 1024);
    }
    //printf("%d\n",bytes);
    if (esp_partition_read(NAME2SECTOR(start_sector),bytes,(byte *)buffer,filesize-bytes)!=ESP_OK) {
        UDPLGP("error reading flash @ %d for %d bytes\n",start_sector+bytes,filesize-bytes);
    }
    if (!bytes && first_byte!=0xff) buffer[0]=first_byte;
    //printf("filesize %d\n",filesize);
    mbedtls_sha512_update_ret(&sha, buffer, filesize-bytes);
    mbedtls_sha512_finish_ret(&sha, hash);
    mbedtls_sha512_free(&sha);
}

int   ota_get_hash(char * repo, char * version, char * file, signature_t* signature) {
    UDPLGP("--- ota_get_hash\n");
    int ret;
    byte buffer[HASHSIZE+4+SIGNSIZE];
    char * signame=malloc(strlen(file)+5);
    strcpy(signame,file);
    strcat(signame,".sig");
    memset(signature->hash,0,HASHSIZE);
    memset(signature->sign,0,SIGNSIZE);
    ret=ota_get_file_ex(repo,version,signame,0,buffer,HASHSIZE+4+SIGNSIZE);
    free(signame);
    if (ret<0) return ret;
    memcpy(signature->hash,buffer,HASHSIZE);
    signature->size=((buffer[HASHSIZE]*256 + buffer[HASHSIZE+1])*256 + buffer[HASHSIZE+2])*256 + buffer[HASHSIZE+3];
    if (ret>HASHSIZE+4) memcpy(signature->sign,buffer+HASHSIZE+4,SIGNSIZE);

    return 0;
}

int   ota_verify_hash(int address, signature_t* signature) {
    UDPLGP("--- ota_verify_hash\n");
    
    byte hash[HASHSIZE+16]; //add 16 because mbedtls has 64 byte result also for SHA384
//     ota_hash(address, signature->size, hash, file_first_byte[0]); //TODO 
    //int i;
    //printf("signhash:"); for (i=0;i<HASHSIZE;i++) printf(" %02x",signature->hash[i]); printf("\n");
    //printf("calchash:"); for (i=0;i<HASHSIZE;i++) printf(" %02x",           hash[i]); printf("\n");
    
    if (memcmp(hash,signature->hash,HASHSIZE)) ota_hash(address, signature->size, hash, 0xff);
    for (int i=0;i<HASHSIZE;i++) {printf("%02x ",hash[i]);} printf("hash384\n");
    return memcmp(hash,signature->hash,HASHSIZE);
}

int   ota_verify_signature(signature_t* signature) {
    UDPLGP("--- ota_verify_signature\n");
    
    int answer=0;

//     wc_ecc_verify_hash(signature->sign, SIGNSIZE, signature->hash, HASHSIZE, &answer, &pubecckey);
    UDPLGP("signature valid: %d\n",answer);
        
    return answer-1;
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

void  ota_temp_boot(void) {
    UDPLGP("--- ota_temp_boot\n");
    
//     rboot_set_temp_rom(1);
    vTaskDelay(20); //allows UDPLOG to flush
    //TODO: this should force a boot from ota_1
    esp_restart();
}

void  ota_reboot(void) {
    UDPLGP("--- ota_reboot\n");

//     if (ledblinkHandle) {
//         vTaskDelete(ledblinkHandle);
//         gpio_enable(led, GPIO_INPUT);
//         gpio_set_pullup(led, 0, 0);
//     }
    vTaskDelay(20); //allows UDPLOG to flush
    //TODO: this should force a boot from ota_0
    esp_restart();
}




//===================================================

#define OTA_URL_SIZE 256
static char ota_write_data[BUFFSIZE + 1] = { 0 };

static void http_cleanup(esp_http_client_handle_t client)
{
    esp_http_client_close(client);
    esp_http_client_cleanup(client);
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
//         .cert_pem = (char *)server_cert_pem_start,
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
