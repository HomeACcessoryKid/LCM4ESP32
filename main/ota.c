/*  (c) 2018-2022 HomeAccessoryKid */
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_ota_ops.h"
#include "esp_app_desc.h"
#include "esp_http_client.h"
#include "esp_flash_partitions.h"
#include "esp_partition.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "errno.h"
#include "ota.h"
#include "mbedtls/sha512.h" //contains sha384 support
#include "mbedtls/platform.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/esp_debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/ecdsa.h"
#include "bootloader_common.h"
#include "esp_wifi.h"
#include "esp_sntp.h"
#include <udplogger.h>
#include "hal/gpio_hal.h" //TODO: evaluate if using HAL is acceptable

mbedtls_ssl_config mbedtls_conf;
mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_x509_crt cacert;
mbedtls_ecdsa_context mbedtls_ecdsa_ctx;

#define BUFFSIZE 1024
#define NAME2SECTOR(sectorname) esp_partition_find_first(ESP_PARTITION_TYPE_ANY,ESP_PARTITION_SUBTYPE_ANY,sectorlabel[sectorname])
char sectorlabel[][10]={"buffer","lcmcert_1","lcmcert_2","ota_0","ota_1"}; //label of sector in partition table to index. zero reserved

int active_cert_sector;
int backup_cert_sector;

static int  verify = 1;
uint8_t userbeta=0;
uint8_t otabeta=0;
static byte file_first_byte[]={0xff};

nvs_handle_t lcm_handle;
void  ota_nvs_init() {
    UDPLGP("\n\n\n\n%s %s version %s\n",esp_app_get_description()->project_name,ota_boot()?"OTABOOT":"OTAMAIN",esp_app_get_description()->version);
    esp_err_t err = nvs_flash_init(); // Initialize NVS
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        // OTA app partition table has a smaller NVS partition size than the non-OTA
        // partition table. This size mismatch may cause NVS initialization to fail.
        // If this happens, we erase NVS partition and initialize NVS again.
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);

    nvs_stats_t nvs_stats;
    nvs_get_stats(NULL, &nvs_stats);
    printf("Count: UsedEntries = (%d), FreeEntries = (%d), AllEntries = (%d)\n",
           nvs_stats.used_entries, nvs_stats.free_entries, nvs_stats.total_entries);

    nvs_open("LCM",NVS_READWRITE,&lcm_handle);
}

char *ota_strstr(const char *full_string, const char *search) { //lowercase version of strstr()
    char *lc_string = strdup(full_string);
    unsigned char *ch = (unsigned char *) lc_string;
    while(*ch) {
        *ch = tolower(*ch);
        ch++;
    }
    const char *found = strstr(lc_string, search);
    if(found == NULL) {free(lc_string); return NULL;}
    
    const int offset = (int) found - (int) lc_string;
    free(lc_string);
    return (char *) ((int) full_string + offset);
}

uint8_t led=0;
TaskHandle_t ledblinkHandle = NULL;
void   led_blink_task(void *pvParameter) {
    UDPLGP("--- led_blink_task pin %d\n",led);
    if (led<6 || led>11) { //do not allow pins 6-11
        // gpio_config_t io_conf = {};
        // io_conf.intr_type = GPIO_INTR_DISABLE;
        // io_conf.mode = GPIO_MODE_OUTPUT;
        // io_conf.pin_bit_mask = 1ULL<<led;
        // io_conf.pull_down_en = 0;
        // io_conf.pull_up_en = 0;
        // gpio_config(&io_conf);
        // while(1) {
        //     gpio_set_level(led, 1); vTaskDelay(BLINKDELAY/portTICK_PERIOD_MS);
        //     gpio_set_level(led, 0); vTaskDelay(BLINKDELAY/portTICK_PERIOD_MS);
        // }
        gpio_ll_output_enable (&GPIO, led);
        while(1) {
            gpio_ll_set_level (&GPIO, led, 1); vTaskDelay(BLINKDELAY/portTICK_PERIOD_MS);
            gpio_ll_set_level (&GPIO, led, 0); vTaskDelay(BLINKDELAY/portTICK_PERIOD_MS);
        }
    } else {
        UDPLGP(": invalid pin!\n");
    }
    ledblinkHandle = NULL;
    vTaskDelete(NULL);
}

static uint8_t count=0,rtc_read_busy=1;
void ota_rtc_read_task(void *arg) {
#if CONFIG_IDF_TARGET_ESP32
    if (bootloader_common_get_rtc_retain_mem_reboot_counter()) { //if zero, RTC CRC not valid
        rtc_retain_mem_t* rtcmem=bootloader_common_get_rtc_retain_mem(); //access to the memory struct
        count=rtcmem->custom[0]; //byte zero for count
    } else {
        count=0;
    }
    bootloader_common_reset_rtc_retain_mem(); //this will clear RTC
#else
    //do nothing for now
#endif
    rtc_read_busy=0;
    vTaskDelete(NULL);
}

void  ota_pre_wifi() {
    UDPLGP("--- ota_pre_wifi\n");
    const esp_partition_t *partition=NULL;
#ifdef OTABOOT
    // checking if partition table contains the minimum parts, only the size, not the location
    // otadata,    data,   ota,    0x09000,   0x2000,
    // phy_init,   data,   phy,    0x0b000,   0x1000,
    // lcmcert_1,  0x65,   0x18,   0x0c000,   0x1000,
    // lcmcert_2,  0x65,   0x18,   0x0d000,   0x1000,
    // nvs,        data,   nvs,    0x0e000,  0x12000,
    // #user can redefine nvs to minimum 0x4000 and extras for total 0x12000
    // ota_1,      app,    ota_1,  0x20000,  0xd0000,
    // #from here, user can define rest of ptable with at least ota_0
    // ota_0,      app,    ota_0,  0xf0000, 0x110000,
    UDPLGP("Partition Table for use with LCM4ESP32 checking: ");

    partition=esp_partition_find_first(ESP_PARTITION_TYPE_DATA,ESP_PARTITION_SUBTYPE_DATA_OTA,"otadata");
    if (partition && partition->size==0x2000) {} else {UDPLGP("otadata not OK! ABORT\n");vTaskDelete(NULL);}

    partition=esp_partition_find_first(ESP_PARTITION_TYPE_DATA,ESP_PARTITION_SUBTYPE_DATA_PHY,"phy_init");
    if (partition && partition->size==0x1000) {} else {UDPLGP("phy_init not OK! ABORT\n");vTaskDelete(NULL);}

    partition=esp_partition_find_first(0x65,0x18,"lcmcert_1");
    if (partition && partition->size==0x1000) {} else {UDPLGP("lcmcert_1 not OK! ABORT\n");vTaskDelete(NULL);}

    partition=esp_partition_find_first(0x65,0x18,"lcmcert_2");
    if (partition && partition->size==0x1000) {} else {UDPLGP("lcmcert_2 not OK! ABORT\n");vTaskDelete(NULL);}

    partition=esp_partition_find_first(ESP_PARTITION_TYPE_DATA,ESP_PARTITION_SUBTYPE_DATA_NVS,"nvs");
    if (partition && partition->size>=0x4000) {} else {UDPLGP("nvs not OK! ABORT\n");vTaskDelete(NULL);}

    partition=esp_partition_find_first(ESP_PARTITION_TYPE_APP,ESP_PARTITION_SUBTYPE_APP_OTA_1,"ota_1");
    if (partition && partition->size>=0xc0000) {} else {UDPLGP("ota_1 not OK! ABORT\n");vTaskDelete(NULL);}

    partition=esp_partition_find_first(ESP_PARTITION_TYPE_APP,ESP_PARTITION_SUBTYPE_APP_OTA_0,"ota_0");
    if (partition && partition->size>=0xc0000) {} else {UDPLGP("ota_0 not OK! ABORT\n");vTaskDelete(NULL);}
    
    UDPLGP("OK\n");
#endif
    rtc_read_busy=1;
    xTaskCreatePinnedToCore(ota_rtc_read_task,"rtcr",4096,NULL,1,NULL,0); //CPU_0 PRO_CPU needed for rtc operations
    while (rtc_read_busy) vTaskDelay(1);
	uint8_t user_count=1,count_step=3;
    char *value=NULL;
    bool reset_wifi=0;
    bool reset_otabeta=0;
    bool factory_reset=0;

    nvs_get_u8(lcm_handle,"lcm_beta", &otabeta); //NOTE: if a key does not exist, the value remains unchanged
    nvs_get_u8(lcm_handle,"ota_beta", &userbeta);
    nvs_get_u8(lcm_handle,"ota_count_step", &count_step);
    if (count_step>3 || count_step<1) count_step=3;
    UDPLGP("--- count_step=%d\n",count_step);
    
    nvs_get_u8(lcm_handle,"ota_count", &user_count);
    if (user_count>0) {
        nvs_erase_key(lcm_handle,"ota_count");
        nvs_commit(lcm_handle);
    }
	if (count<2) count=user_count;
    
    UDPLGP("--- count=%d\n",count);
    if      (count<5+count_step*1) { //standard ota-main or ota-boot behavior
            value="--- standard ota";
    }
    else if (count<5+count_step*2) { //reset wifi parameters and clear LCM_beta
            value="--- reset wifi and clear LCM_beta";
            reset_wifi=1;
            reset_otabeta=1;
    }
    else if (count<5+count_step*3) { //reset wifi parameters and set LCM_beta
            value="--- reset wifi and set LCM_beta";
            reset_wifi=1;
            otabeta=1;
    }
    else    {//factory reset
            value="--- factory reset";
            factory_reset=1;
    }
    UDPLGP("%s\n",value);
    if (count>4+count_step) {
        UDPLGP("IF this is NOT what you wanted, reset/power-down NOW!\n");
        for (int i=19;i>-1;i--) {
            vTaskDelay(1000/portTICK_PERIOD_MS);
            UDPLGP("%s in %d s\n",value,i);
        }
    }
    if (factory_reset) {        
        nvs_flash_deinit();
        esp_partition_iterator_t it=esp_partition_find(ESP_PARTITION_TYPE_ANY,ESP_PARTITION_SUBTYPE_ANY,NULL);
        while (it) {
            partition=esp_partition_get(it);
            UDPLGP("partition: %s",partition->label);
            if (strcmp(partition->label,"lcmcert_1") &&
                strcmp(partition->label,"lcmcert_2") &&
                //strcmp(partition->label,"ota_data")  &&
                #ifdef OTABOOT
                strcmp(partition->label,"ota_0")     &&
                #endif
                strcmp(partition->label,"ota_1")        ) //no not erase these partitions, but all else yes
            {
                esp_partition_erase_range(partition,0,partition->size);
                UDPLGP(" erased");
            }
            UDPLGP("\n");
            it=esp_partition_next(it);
        }
        esp_partition_iterator_release(it);
        ESP_ERROR_CHECK(nvs_flash_init());
        nvs_open("LCM",NVS_READWRITE,&lcm_handle);
    }

    if (reset_wifi) {
        esp_err_t err;
        uint8_t *blob_data;
        size_t   blob_size=0;
        nvs_handle_t wifi_handle;
        nvs_open("nvs.net80211",NVS_READWRITE,&wifi_handle);

        err=nvs_get_blob(wifi_handle,"sta.ssid",NULL,&blob_size);
        if (err==ESP_OK) {
            blob_data=malloc(blob_size);
            memset(blob_data,0,blob_size);
            nvs_set_blob(wifi_handle,"sta.ssid",blob_data,blob_size);
            free(blob_data);
        }

        err=nvs_get_blob(wifi_handle,"sta.pswd",NULL,&blob_size);
        if (err==ESP_OK) {
            blob_data=malloc(blob_size);
            memset(blob_data,0,blob_size);
            nvs_set_blob(wifi_handle,"sta.pswd",blob_data,blob_size);
            free(blob_data);
        }
        
        nvs_commit(wifi_handle);
        nvs_close( wifi_handle);
    }
    
    if (otabeta && !reset_otabeta) nvs_set_u8(lcm_handle,"lcm_beta", 1);
    if (!otabeta || reset_otabeta) nvs_erase_key(lcm_handle,"lcm_beta");
    nvs_commit(lcm_handle);

    nvs_get_u8(lcm_handle,"led_pin", &led); //default is zero
    //write value of led to ota-data partition
    if (led) {
        if ((partition=esp_partition_find_first(ESP_PARTITION_TYPE_DATA,ESP_PARTITION_SUBTYPE_DATA_OTA,"otadata") ) ) {
            esp_partition_write(partition,  0x40-4,(byte *)(uint32_t*)&led,4);
            esp_partition_write(partition,0x4040-4,(byte *)(uint32_t*)&led,4);
        }
        if (led>127) led-=128;
        if (led && led<34) xTaskCreate(led_blink_task, "ledblink", 2048, NULL, 1, &ledblinkHandle);
    }
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

static void ota_get_certs() {
    UDPLGP("--- ota_get_certs\n");
    int size=0;
    byte abyte[1];

    do {
        if (esp_partition_read(NAME2SECTOR(active_cert_sector),PKEYSIZE+(size++), (byte *)abyte, 1)!=ESP_OK) {
            UDPLGP("error reading flash\n");
            break;
        }
    } while (abyte[0]!=0xff); size--;
    UDPLGP("certs size: %d\n",size);
    byte* certs=malloc(size);
    esp_partition_read(NAME2SECTOR(active_cert_sector),PKEYSIZE, certs, size);
    if (certs[size-1]==0x0a) certs[size-1]=0x00; //life-cycle-manager wolfssl uses a closing 0x0a but mbedtls requires a 0x00
    mbedtls_x509_crt_free(&cacert);
    mbedtls_x509_crt_init(&cacert);
    printf("cert parse: %d errors\n",mbedtls_x509_crt_parse(&cacert,certs,size));
    mbedtls_ssl_conf_ca_chain(&mbedtls_conf, &cacert, NULL);
    free(certs);
}

void  ota_init() {
    UDPLGP("--- ota_init\n");

    UDPLGP("userbeta=\'%d\' otabeta=\'%d\'\n",userbeta,otabeta);
    
    if (!ledblinkHandle) {
        led=0;
        nvs_get_u8(lcm_handle,"led_pin", &led); //default is zero
        //write value of led to ota-data partition
        if (led) {
            const esp_partition_t *partition=NULL;
            if ((partition=esp_partition_find_first(ESP_PARTITION_TYPE_DATA,ESP_PARTITION_SUBTYPE_DATA_OTA,"otadata") )) {
                esp_partition_write(partition,  0x40-4,(byte *)(uint32_t*)&led,4);
                esp_partition_write(partition,0x4040-4,(byte *)(uint32_t*)&led,4);
            }
            if (led>127) led-=128;
            if (led && led<34) xTaskCreate(led_blink_task, "ledblink", 1024, NULL, 1, &ledblinkHandle);
        }
    }
    //time support
    esp_sntp_setoperatingmode(SNTP_OPMODE_POLL);
    esp_sntp_setservername(0, "pool.ntp.org");
    //setenv("TZ", "CET-1CEST,M3.5.0,M10.5.0", 3); //https://github.com/nayarsystems/posix_tz_db/blob/master/zones.csv
    //tzset();
    esp_sntp_init();

    ota_active_sector();
    
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,NULL, 0);
    mbedtls_ssl_config_init(&mbedtls_conf);
    mbedtls_ssl_config_defaults(&mbedtls_conf,MBEDTLS_SSL_IS_CLIENT,MBEDTLS_SSL_TRANSPORT_STREAM,MBEDTLS_SSL_PRESET_DEFAULT);
    mbedtls_ssl_conf_rng(&mbedtls_conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    ota_get_certs();
    #ifdef CONFIG_MBEDTLS_DEBUG
        mbedtls_esp_enable_debug_log(&mbedtls_conf, CONFIG_MBEDTLS_DEBUG_LEVEL);
    #endif
    
    ota_set_verify(0);
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
    printf("\n");

    //typedef struct mbedtls_ecp_keypair { //this is also mbedtls_ecdsa_context
    //    mbedtls_ecp_group grp;      /*!<  Elliptic curve and base point     */
    //    mbedtls_mpi d;              /*!<  our secret value                  */
    //    mbedtls_ecp_point Q;        /*!<  our public value                  */
    mbedtls_ecdsa_init(&mbedtls_ecdsa_ctx);
    mbedtls_ecp_group_load(&mbedtls_ecdsa_ctx.MBEDTLS_PRIVATE(grp), MBEDTLS_ECP_DP_SECP384R1);
    ret=mbedtls_ecp_point_read_binary(&mbedtls_ecdsa_ctx.MBEDTLS_PRIVATE(grp),&mbedtls_ecdsa_ctx.MBEDTLS_PRIVATE(Q),buffer+23,length);
    printf("keycheck: 0x%02x\n",mbedtls_ecp_check_pubkey(&mbedtls_ecdsa_ctx.MBEDTLS_PRIVATE(grp),&mbedtls_ecdsa_ctx.MBEDTLS_PRIVATE(Q)));
    UDPLGP("ret: %d\n",ret);

    if (!ret)return PKEYSIZE; else return ret;
}

void ota_hash(int start_sector, int filesize, byte * hash, byte first_byte) {
    UDPLGP("--- ota_hash\n");
    
    int bytes;
    byte buffer[1024];
    mbedtls_sha512_context sha;
    
    mbedtls_sha512_init(&sha);
    mbedtls_sha512_starts(&sha,1); //SHA384
    //printf("bytes: ");
    for (bytes=0;bytes<filesize-1024;bytes+=1024) {
        //printf("%d ",bytes);
        if (esp_partition_read(NAME2SECTOR(start_sector),bytes,(byte *)buffer,1024)!=ESP_OK) {
            UDPLGP("error reading flash\n");   break;
        }
        if (!bytes && first_byte!=0xff) buffer[0]=first_byte;
        mbedtls_sha512_update(&sha, buffer, 1024);
    }
    //printf("%d\n",bytes);
    if (esp_partition_read(NAME2SECTOR(start_sector),bytes,(byte *)buffer,filesize-bytes)!=ESP_OK) {
        UDPLGP("error reading flash @ %d for %d bytes\n",start_sector+bytes,filesize-bytes);
    }
    if (!bytes && first_byte!=0xff) buffer[0]=first_byte;
    //printf("filesize %d\n",filesize);
    mbedtls_sha512_update(&sha, buffer, filesize-bytes);
    mbedtls_sha512_finish(&sha, hash);
    mbedtls_sha512_free(&sha);
}

int ota_compare(char* newv, char* oldv) { //(if equal,0) (if newer,1) (if pre-release or older,-1)
    UDPLGP("--- ota_compare ");
    printf("\n");
    char* dot;
    int valuen=0,valueo=0;
    char news[MAXVERSIONLEN],olds[MAXVERSIONLEN];
    char * new=news;
    char * old=olds;
    int result=0;
    
    if (strcmp(newv,oldv)) { //https://semver.org/#spec-item-11
        do {
            if (strchr(newv,'-')) {result=-1;break;} //we cannot handle versions with pre-release suffix notation (yet)
            //pre-release marker in github serves to identify those
            strncpy(new,newv,MAXVERSIONLEN-1);
            strncpy(old,oldv,MAXVERSIONLEN-1);
            if ((dot=strchr(new,'.'))) {dot[0]=0; valuen=atoi(new); new=dot+1;}
            if ((dot=strchr(old,'.'))) {dot[0]=0; valueo=atoi(old); old=dot+1;}
            printf("%d-%d,%s-%s\n",valuen,valueo,new,old);
            if (valuen>valueo) {result= 1;break;}
            if (valuen<valueo) {result=-1;break;}
            valuen=valueo=0;
            if ((dot=strchr(new,'.'))) {dot[0]=0; valuen=atoi(new); new=dot+1;}
            if ((dot=strchr(old,'.'))) {dot[0]=0; valueo=atoi(old); old=dot+1;}
            printf("%d-%d,%s-%s\n",valuen,valueo,new,old);
            if (valuen>valueo) {result= 1;break;}
            if (valuen<valueo) {result=-1;break;}
            valuen=atoi(new);
            valueo=atoi(old);
            printf("%d-%d\n",valuen,valueo);
            if (valuen>valueo) {result= 1;break;}
            if (valuen<valueo) {result=-1;break;}        
        } while(0);
    } //they are equal
    UDPLGP("%s with %s=%d\n",newv,oldv,result);
    return result;
}

static int ota_connect(char* host, int port, mbedtls_net_context *socket, mbedtls_ssl_context *ssl) {
    UDPLGP("--- ota_connect\n");
    char buf[512];
    int ret, flags;
    
    printf("free heap %u\n",xPortGetFreeHeapSize());
    mbedtls_net_init(socket);
    UDPLGP("Connecting to %s:%d...\n", host, port);
    if ((ret = mbedtls_net_connect(socket, host,itoa(port,buf,10),MBEDTLS_NET_PROTO_TCP)) != 0) {
        UDPLGP("mbedtls_net_connect returned -%x\n", -ret);
        return -2;
    }
    //UDPLGP("Connected\n");

    if (port==HTTPS_PORT) { //SSL mode, in emergency mode this is skipped
        mbedtls_ssl_init(ssl);
         // Hostname set here should match CN in server certificate
        if((ret = mbedtls_ssl_set_hostname(ssl, host)) != 0) {
            UDPLGP("mbedtls_ssl_set_hostname returned -0x%x\n", -ret);
            return -1;
        }
        //UDPLGP("SSLsetup...\n");
        if ((ret = mbedtls_ssl_setup(ssl, &mbedtls_conf)) != 0) {
            UDPLGP("mbedtls_ssl_setup returned -0x%x\n", -ret);
            return -1;
        }
        //UDPLGP("BIOsetup...\n");
        mbedtls_ssl_set_bio(ssl, socket, mbedtls_net_send, mbedtls_net_recv, NULL);
        //UDPLGP("Performing the SSL/TLS handshake...\n");
        while ((ret = mbedtls_ssl_handshake(ssl)) != 0) {
            if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                UDPLGP("mbedtls_ssl_handshake returned -0x%x\n", -ret);
                break;
            }
        }
        //UDPLGP("Verifying peer X.509 certificate...\n");
        // MBEDTLS_X509_BADCERT_EXPIRED          0x01  < The certificate validity has expired.
        // MBEDTLS_X509_BADCERT_REVOKED          0x02  < The certificate has been revoked (is on a CRL).
        // MBEDTLS_X509_BADCERT_CN_MISMATCH      0x04  < The certificate Common Name (CN) does not match with the expected CN.
        // MBEDTLS_X509_BADCERT_NOT_TRUSTED      0x08  < The certificate is not correctly signed by the trusted CA.
        // MBEDTLS_X509_BADCRL_NOT_TRUSTED       0x10  < The CRL is not correctly signed by the trusted CA.
        // MBEDTLS_X509_BADCRL_EXPIRED           0x20  < The CRL is expired.
        // MBEDTLS_X509_BADCERT_MISSING          0x40  < Certificate was missing.
        // MBEDTLS_X509_BADCERT_SKIP_VERIFY      0x80  < Certificate verification was skipped.
        // MBEDTLS_X509_BADCERT_OTHER          0x0100  < Other reason (can be used by verify callback)
        // MBEDTLS_X509_BADCERT_FUTURE         0x0200  < The certificate validity starts in the future.
        // MBEDTLS_X509_BADCRL_FUTURE          0x0400  < The CRL is from the future
        // MBEDTLS_X509_BADCERT_KEY_USAGE      0x0800  < Usage does not match the keyUsage extension.
        // MBEDTLS_X509_BADCERT_EXT_KEY_USAGE  0x1000  < Usage does not match the extendedKeyUsage extension.
        // MBEDTLS_X509_BADCERT_NS_CERT_TYPE   0x2000  < Usage does not match the nsCertType extension.
        // MBEDTLS_X509_BADCERT_BAD_MD         0x4000  < The certificate is signed with an unacceptable hash.
        // MBEDTLS_X509_BADCERT_BAD_PK         0x8000  < The certificate is signed with an unacceptable PK alg (eg RSA vs ECDSA).
        // MBEDTLS_X509_BADCERT_BAD_KEY      0x010000  < The certificate is signed with an unacceptable key (eg bad curve, RSA too short).
        // MBEDTLS_X509_BADCRL_BAD_MD        0x020000  < The CRL is signed with an unacceptable hash.
        // MBEDTLS_X509_BADCRL_BAD_PK        0x040000  < The CRL is signed with an unacceptable PK alg (eg RSA vs ECDSA).
        // MBEDTLS_X509_BADCRL_BAD_KEY       0x080000  < The CRL is signed with an unacceptable key (eg bad curve, RSA too short).
        if ((flags = mbedtls_ssl_get_verify_result(ssl)) != 0) {
            bzero(buf, sizeof(buf));
            mbedtls_x509_crt_verify_info(buf, sizeof(buf), "", flags);
            UDPLGP("flags:0x%06x - %s\n", flags, buf);
        } else {
            UDPLGP("Certificate verified\n");
        }
        //UDPLGP("Cipher suite is %s\n", mbedtls_ssl_get_ciphersuite(ssl));
        if (ret) {
            UDPLGP("LCM: BAD error, will wait 1 hour before continuing\n");
            vTaskDelay(60*60*1000/portTICK_PERIOD_MS);
            return -1;
        }
    } //end SSL mode
    return 0;
}

int   ota_load_user_app(char * *repo, char * *version, char * *file) {
    UDPLGP("--- ota_load_user_app\n");

    size_t size;
    char* value=NULL;
    if (nvs_get_str(lcm_handle,"ota_repo", NULL,  &size)==ESP_OK) {
        value = malloc(size);
        nvs_get_str(lcm_handle,"ota_repo", value, &size);
        *repo=value;
    } else return -1;

    if (nvs_get_str(lcm_handle,"ota_file", NULL,  &size)==ESP_OK) {
        value = malloc(size);
        nvs_get_str(lcm_handle,"ota_file", value, &size);
        *file=value;
    } else return -1;

    if (nvs_get_str(lcm_handle,"ota_version", NULL,  &size)==ESP_OK) {
        value = malloc(size);
        nvs_get_str(lcm_handle,"ota_version", value, &size);
        *version=value;
    } else {
        *version=malloc(6);
        strcpy(*version,"0.0.0");
    }

    UDPLGP("user_repo=\'%s\' user_version=\'%s\' user_file=\'%s\'\n",*repo,*version,*file);
    return 0;
}

void  ota_set_verify(int onoff) {
    UDPLGP("--- ota_set_verify...");
    
    if (onoff) {
        UDPLGP("ON\n");
        if (verify==0) {
            verify= 1;

            time_t ts;
            do {
                ts = time(NULL);
                if (ts == ((time_t)-1)) printf("ts=-1, ");
                vTaskDelay(1);
            } while (!(ts>1666666666)); //October 25th 2022 
            UDPLGP("UTC-TIME: %s", ctime(&ts)); //we need to have the clock right to check certificates
            
            //TODO: check if this really detects a non-matching certificate
            mbedtls_ssl_conf_authmode(&mbedtls_conf, MBEDTLS_SSL_VERIFY_REQUIRED);
        }
    } else {
        UDPLGP("OFF\n");
        if (verify==1) {
            verify= 0;
            mbedtls_ssl_conf_authmode(&mbedtls_conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
        }
    }
}

int   ota_get_file_ex(char * repo, char * version, char * file, int sector, byte * buffer, int bufsz); //prototype needed
char* ota_get_version(char * repo) {
    UDPLGP("--- ota_get_version\n");

    char* version=NULL;
    char prerelease[64]; 
    int retc, ret=0;
    int httpcode;
    mbedtls_ssl_context ssl;
    mbedtls_net_context socket;
    //host=begin(repo);
    //mid =end(repo)+blabla+version
    char* found_ptr;
    char recv_buf[RECV_BUF_LEN];
    int  send_bytes; //= sizeof(send_data);
    int  len=0;
    
    strcat(strcat(strcat(strcat(strcat(strcpy(recv_buf, \
        REQUESTHEAD),repo),"/releases/latest"),REQUESTTAIL),CONFIG_LCM_GITHOST),CRLFCRLF);
    send_bytes=strlen(recv_buf);
    //printf("%s\n",recv_buf);

    retc = ota_connect(CONFIG_LCM_GITHOST, HTTPS_PORT, &socket, &ssl);  //release socket and ssl when ready
    
    if (!retc) {
        UDPLGP("%s",recv_buf);
        ret = mbedtls_ssl_write(&ssl, (byte*)recv_buf, send_bytes);
        if (ret > 0) {
            printf("sent OK\n");

            ret = mbedtls_ssl_read(&ssl, (byte*)recv_buf, RECV_BUF_LEN - 1);
            if (ret > 0) {
                recv_buf[ret]=0; //prevent falling of the end of the buffer when doing string operations
                found_ptr=ota_strstr(recv_buf,"http/1.1 ");
                found_ptr+=9; //flush "HTTP/1.1 "
                httpcode=atoi(found_ptr);
                UDPLGP("HTTP returns %d for ",httpcode);
                if (httpcode!=302) {
                    mbedtls_ssl_free(&ssl);
                    mbedtls_net_free(&socket);
                    return "404";
                }
            } else {
                UDPLGP("failed, return [-0x%x]\n", -ret);
                return "404";
            }

            while (1) {
                recv_buf[ret+len]=0; //prevent falling of the end of the buffer when doing string operations
                len=9; //length of "\nlocation"
                found_ptr=ota_strstr(recv_buf,"\nlocation:"); //if not found, could be that only ':' is missing
                if (found_ptr) break;
                for (int i=0;i<len;i++) recv_buf[i]=recv_buf[i+RECV_BUF_LEN-1-len];
                ret = mbedtls_ssl_read(&ssl, (byte*)recv_buf+len, RECV_BUF_LEN-1-len);

                if (ret <= 0) {
                    UDPLGP("failed, return [-0x%x]\n", -ret);
                    return "404";
                }
            }
            len=found_ptr-recv_buf+11; //this starts for sure with the content of "Location: "
            for (int i=0;i<RECV_BUF_LEN-1-len;i++) recv_buf[i]=recv_buf[i+len]; //flush all previous material
            ret = mbedtls_ssl_read(&ssl, (byte*)recv_buf+RECV_BUF_LEN-1-len, len); //fill recv_buf with remaining input
            recv_buf[ret+RECV_BUF_LEN-1-len]=0; //prevent falling of the end of the buffer when doing string operations
            strchr(recv_buf,'\r')[0]=0;
            found_ptr=ota_strstr(recv_buf,"releases/tag/");
            if (found_ptr[13]=='v' || found_ptr[13]=='V') found_ptr++;
            version=malloc(strlen(found_ptr+13)+1);
            strcpy(version,found_ptr+13);
            printf("%s@version:\"%s\" according to latest release\n",repo,version);
        } else {
            UDPLGP("failed, return [-0x%x]\n", -ret);
        }
    }
    if (retc<0) {
        version=malloc(6);
        strcpy(version,"0.0.0");
    }
    switch (retc) {
        case  0:
        case -1:
        mbedtls_ssl_free(&ssl);
        mbedtls_net_free(&socket);
        break;
        case -2:
        mbedtls_net_free(&socket);
        case -3:
        default:
        ;
    }

    //find latest-pre-release if joined beta program
    //bool OTAorBTL=!(strcmp(OTAREPO,repo)&&strcmp(BTLREPO,repo));
    bool OTAorBTL=!(strcmp(OTAREPO,repo)); //TODO: expand if bootloader becomes updateable
    if ( (userbeta && !OTAorBTL) || (otabeta && OTAorBTL)) {
        prerelease[63]=0;
        ret=ota_get_file_ex(repo,version,"latest-pre-release",0,(byte *)prerelease,63);
        if (ret>0) {
            prerelease[ret]=0; //TODO: UNTESTED make a final 0x0a and or 0x0d optional
            if (prerelease[ret-1]=='\n') {
                prerelease[ret-1]=0;
                if (prerelease[ret-2]=='\r') prerelease[ret-2]=0;                
            }
            free(version);
            version=malloc(strlen(prerelease)+1);
            strcpy(version,prerelease);
        }
    }
    if (ota_boot() && ota_compare(version,(char*)esp_app_get_description()->version)<0) { //this acts when setting up a new version
        free(version);
        version=malloc(strlen((char*)esp_app_get_description()->version)+1);
        strcpy(version,(char*)esp_app_get_description()->version);
    }
    
    UDPLGP("%s@version:\"%s\"\n",repo,version);
    return version;
}

int   ota_get_file_ex(char * repo, char * version, char * file, int sector, byte * buffer, int bufsz) { //number of bytes
    UDPLGP("--- ota_get_file_ex\n");
    
    int retc, ret=0, slash;
    mbedtls_ssl_context ssl;
    mbedtls_net_context socket;
    esp_ota_handle_t handle=0;
    //host=begin(repo);
    //mid =end(repo)+blabla+version
    char* found_ptr=NULL;
    char recv_buf[RECV_BUF_LEN];
    int  recv_bytes = 0;
    int  send_bytes; //= sizeof(send_data);
    int  length=1;
    int  clength=0;
    int  left,len=0;
    int  collected=0;
    int  writespace=0;
    int  header;
    bool emergency=(strcmp(version,EMERGENCY))?0:1;
    int  port=(emergency)?HTTP_PORT:HTTPS_PORT;
    
    if (sector==0 && buffer==NULL) return -5; //needs to be either a sector or a signature
    
    if (!emergency) { //if not emergency, find the redirection done by GitHub
    strcat(strcat(strcat(strcat(strcat(strcat(strcat(strcat(strcpy(recv_buf, \
        REQUESTHEAD),repo),"/releases/download/"),version),"/"),file),REQUESTTAIL),CONFIG_LCM_GITHOST),CRLFCRLF);
    send_bytes=strlen(recv_buf);
    UDPLGP("%s",recv_buf);

    retc = ota_connect(CONFIG_LCM_GITHOST, HTTPS_PORT, &socket, &ssl);  //release socket and ssl when ready
    
    if (!retc) {
        ret = mbedtls_ssl_write(&ssl, (byte*)recv_buf, send_bytes);
        if (ret > 0) {
            UDPLGP("sent OK\n");

            ret = mbedtls_ssl_read(&ssl, (byte*)recv_buf, RECV_BUF_LEN - 1);
            if (ret > 0) {
                recv_buf[ret]=0; //prevent falling of the end of the buffer when doing string operations
                found_ptr=ota_strstr(recv_buf,"http/1.1 ");
                found_ptr+=9; //flush "HTTP/1.1 "
                slash=atoi(found_ptr);
                UDPLGP("HTTP returns %d\n",slash);
                if (slash!=302) {
                    mbedtls_ssl_free(&ssl);
                    mbedtls_net_free(&socket);
                    return -1;
                }
            } else {
                UDPLGP("failed, return [-0x%x]\n", -ret);
                return -1;
            }
            while (1) {
                recv_buf[ret+len]=0; //prevent falling of the end of the buffer when doing string operations
                len=9; //length of "\nlocation"
                found_ptr=ota_strstr(recv_buf,"\nlocation:"); //if not found, could be that only ':' is missing
                if (found_ptr) break;
                for (int i=0;i<len;i++) recv_buf[i]=recv_buf[i+RECV_BUF_LEN-1-len];
                ret = mbedtls_ssl_read(&ssl, (byte*)recv_buf+len, RECV_BUF_LEN-1-len);

                if (ret <= 0) {
                    UDPLGP("failed, return [-0x%x]\n", -ret);
                    return -1;
                }
            }
            len=found_ptr-recv_buf+11; //this starts for sure with the content of "Location: "
            for (int i=0;i<RECV_BUF_LEN-1-len;i++) recv_buf[i]=recv_buf[i+len]; //flush all previous material
            ret = mbedtls_ssl_read(&ssl, (byte*)recv_buf+RECV_BUF_LEN-1-len, len); //fill recv_buf with remaining input
            recv_buf[ret+RECV_BUF_LEN-1-len]=0; //prevent falling of the end of the buffer when doing string operations
            strchr(recv_buf,'\r')[0]=0;
            found_ptr=ota_strstr(recv_buf,"https://");
            //if (found_ptr[0] == ' ') found_ptr++;
            found_ptr+=8; //flush https://
            //printf("location=%s\n",found_ptr);
        } else {
            UDPLGP("failed, return [-0x%x]\n", -ret);
        }
    }
    switch (retc) {
        case  0:
        case -1:
        mbedtls_ssl_free(&ssl);
        mbedtls_net_free(&socket);
        break;
        case -2:
        mbedtls_net_free(&socket);
        case -3:
        default:
        ;
    }

    if (retc) return retc;
    if (ret <= 0) return ret;
    
    } else { //emergency mode, repo is expected to have the format "not.github.com/somewhere/"
        strcpy(recv_buf,repo);
        found_ptr=recv_buf;
        if (found_ptr[strlen(found_ptr)-1]!='/') strcat(found_ptr, "/");
        strcat(found_ptr, file);
        UDPLGP("emergency GET http://%s\n",found_ptr);
    } //found_ptr now contains the url without https:// or http://
    //process the Location
    strcat(found_ptr, REQUESTTAIL);
    slash=strchr(found_ptr,'/')-found_ptr;
    found_ptr[slash]=0; //cut behind the hostname
    char * host2=malloc(strlen(found_ptr)+1);
    strcpy(host2,found_ptr);
    //printf("next host: %s\n",host2);

    retc = ota_connect(host2, port, &socket, &ssl);  //release socket and ssl when ready

    strcat(strcat(found_ptr+slash+1,host2),RANGE); //append hostname and range to URI    
    found_ptr+=slash-4;
    memcpy(found_ptr,REQUESTHEAD,5);
    char * getlinestart=malloc(strlen(found_ptr)+1);
    strcpy(getlinestart,found_ptr);
    //printf("request:\n%s\n",getlinestart);
    //if (!retc) {
    while (collected<length) {
        sprintf(recv_buf,"%s%d-%d%s",getlinestart,collected,collected+4095,CRLFCRLF);
        send_bytes=strlen(recv_buf);
        //printf("request:\n%s\n",recv_buf);
        printf("send request......");
        if (emergency) ret = mbedtls_net_send(&socket, (byte*)recv_buf, send_bytes); else ret = mbedtls_ssl_write(&ssl, (byte*)recv_buf, send_bytes);
        recv_bytes=0;
        if (ret > 0) {
            printf("OK\n");

            header=1;
            memset(recv_buf,0,RECV_BUF_LEN);
            do {
                if (emergency) ret = mbedtls_net_recv(&socket, (byte*)recv_buf, RECV_BUF_LEN - 1); else ret = mbedtls_ssl_read(&ssl, (byte*)recv_buf, RECV_BUF_LEN - 1);
                if (ret > 0) {
                    if (header) {
                        //printf("%s\n-------- %d\n", recv_buf, ret);
                        //parse Content-Length: xxxx
                        found_ptr=ota_strstr(recv_buf,"\ncontent-length:");
                        strchr(found_ptr,'\r')[0]=0;
                        found_ptr+=16; //flush Content-Length://
			            //if (found_ptr[0] == ' ') found_ptr++; //flush a space, atoi would also do that
                        clength=atoi(found_ptr);
                        found_ptr[strlen(found_ptr)]='\r'; //in case the order changes
                        //parse Content-Range: bytes xxxx-yyyy/zzzz
                        found_ptr=ota_strstr(recv_buf,"\ncontent-range:");
                        strchr(found_ptr,'\r')[0]=0;
                        found_ptr+=15; //flush Content-Range://
                        found_ptr=ota_strstr(recv_buf,"bytes ");
                        found_ptr+=6; //flush Content-Range: bytes //
                        found_ptr=strstr(found_ptr,"/"); found_ptr++; //flush /
                        length=atoi(found_ptr);
                        found_ptr[strlen(found_ptr)]='\r'; //search the entire buffer again
                        found_ptr=strstr(recv_buf,CRLFCRLF)+4; //go to end of header
                        if ((left=ret-(found_ptr-recv_buf))) {
                            header=0; //we have body in the same IP packet as the header so we need to process it already
                            ret=left;
                            memmove(recv_buf,found_ptr,left); //move this payload to the head of the recv_buf
                        }
                    }
                    if (!header) {
                        recv_bytes += ret;
                        if (sector>2) {//ota partitions
                           if (!collected) esp_ota_begin(NAME2SECTOR(sector),OTA_WITH_SEQUENTIAL_WRITES, &handle);
                           esp_ota_write(handle,(const void *)recv_buf,ret);
                        } else if (sector) {//cert_sectors
                            if (writespace<ret) {
                                UDPLGP("erasing %s@0x%05x>", sectorlabel[sector],collected);
                                if (esp_partition_erase_range(NAME2SECTOR(sector),collected,SECTORSIZE)) return -6; //erase error
                                writespace+=SECTORSIZE;
                            }
                            if (collected) {
                                if (esp_partition_write(NAME2SECTOR(sector),collected,(byte *)recv_buf,ret)) return -7; //write error
                            } else { //at the very beginning, do not write the first byte yet but store it for later
                                file_first_byte[0]=(byte)recv_buf[0];
                                if (esp_partition_write(NAME2SECTOR(sector),1,  (byte *)recv_buf+1,  ret-1)) return -7; //write error
                            }
                            writespace-=ret;
                        } else { //buffer
                            if (ret>bufsz) return -8; //too big
                            memcpy(buffer,recv_buf,ret);
                        }
                        collected+=ret;
                        int i;
                        for (i=0;i<3;i++) printf("%02x", recv_buf[i]);
                        printf("...");
                        for (i=3;i>0;i--) printf("%02x", recv_buf[ret-i]);
                        printf(" ");
                    }
                } else {
                    if (ret) UDPLGP("error %d\n",ret);
                    if (!ret && collected<length) retc = ota_connect(host2, port, &socket, &ssl); //memory leak?
                    break;
                }
                header=0; //if header and body are separted
            } while(recv_bytes<clength);
            printf(" so far collected %d bytes\n", collected);
            UDPLOG(" collected %d bytes\r",        collected);
        } else {
            printf("failed, return [-0x%x]\n", -ret);
            if (ret==-308) {
                retc = ota_connect(host2, port, &socket, &ssl); //dangerous for eternal connecting? memory leak?
            } else {
                break; //give up?
            }
        }
    }
    if (sector>2) { //ota partitions
        esp_err_t err = esp_ota_end(handle);
        if (err != ESP_OK) {
            if (err == ESP_ERR_OTA_VALIDATE_FAILED) UDPLGP("Image validation failed, image is corrupted\n");
            else UDPLGP("esp_ota_end failed (%s)!\n", esp_err_to_name(err));
        }
    }
    if (sector) {//cert_sectors and ota partitions
        printf("data length=%d, sector written=%s\n",collected,sectorlabel[sector]);
    } else {//buffer
        printf("data length=%d, buffer=%02x%02x %02x%02x ... %02x%02x %02x%02x\n",collected,
        buffer[0],buffer[1],buffer[2],buffer[3],buffer[collected-4],
        buffer[collected-3],buffer[collected-2],buffer[collected-1]);
    }

    UDPLOG("\n");
    switch (retc) {
        case  0:
        case -1:
        if (!emergency) {
            mbedtls_ssl_free(&ssl);
        }
        mbedtls_net_free(&socket);
        break;
        case -2:
        mbedtls_net_free(&socket);
        case -3:
        default:
        ;
    }
    free(host2);
    free(getlinestart);
    if (retc) return retc;
    if (ret < 0) return ret;
    return collected;
}

void  ota_finalize_file(int sector) {
    UDPLGP("--- ota_finalize_file\n");

    if (sector<3) { //cert partitions
        if (esp_partition_write(NAME2SECTOR(sector),0,(byte *)file_first_byte,1)) UDPLGP("error writing flash\n");
    }
    //TODO: add verification and retry and if wrong return status...
}

int   ota_get_file(char * repo, char * version, char * file, int sector) { //number of bytes
   UDPLGP("--- ota_get_file\n");
   return ota_get_file_ex(repo,version,file,sector,NULL,0);
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
    ota_hash(address, signature->size, hash, file_first_byte[0]);
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
    answer=mbedtls_ecdsa_read_signature(&mbedtls_ecdsa_ctx,signature->hash,HASHSIZE,signature->sign,signature->sign[1]+2);
    UDPLGP("signature valid:%s code:0x%02x\n",answer?"no":"yes",answer);

    return answer;
}

void  ota_kill_file(int sector) {
    UDPLGP("--- ota_kill_file\n");

    byte zero[]={0x00};
    if (esp_partition_write(NAME2SECTOR(sector),0,(byte *)zero,1)) UDPLGP("error writing flash\n");
}

void  ota_swap_cert_sector() {
    UDPLGP("--- ota_swap_cert_sector\n");
    
    ota_kill_file(active_cert_sector);
    ota_finalize_file(backup_cert_sector);
    if (active_cert_sector==HIGHERCERTSECTOR) {
        active_cert_sector=LOWERCERTSECTOR;
        backup_cert_sector=HIGHERCERTSECTOR;
    } else {
        active_cert_sector=HIGHERCERTSECTOR;
        backup_cert_sector=LOWERCERTSECTOR;
    }
    ota_get_certs();
}

void  ota_write_status(char * version) {
    UDPLGP("--- ota_write_status\n");
    
    nvs_set_str(lcm_handle,"ota_version", version);
    nvs_commit( lcm_handle);
}

int   ota_boot(void) {
    UDPLGP("--- ota_boot...");
    byte bootrom;
    const esp_partition_t *running = esp_ota_get_running_partition();
    if (running->subtype==ESP_PARTITION_SUBTYPE_APP_OTA_0) bootrom=0; else bootrom=1;
    
    UDPLGP("ROM=%d\n",bootrom);
    return 1-bootrom;
}

static uint8_t rtc_write_busy=1;
void ota_rtc_write_task(void *arg) {
#if CONFIG_IDF_TARGET_ESP32
    rtc_retain_mem_t* rtcmem=bootloader_common_get_rtc_retain_mem(); //access to the memory struct
    bootloader_common_reset_rtc_retain_mem(); //this will clear RTC    
    rtcmem->reboot_counter=1;
    rtcmem->custom[1]=1; //byte one for temp_boot signal (from app to bootloader)
    bootloader_common_update_rtc_retain_mem(NULL,false); //this will update the CRC only
#else
    //do nothing for now
#endif
    rtc_write_busy=0;
    vTaskDelete(NULL);
}

void  ota_temp_boot(void) {
    UDPLGP("--- ota_temp_boot\n");
    rtc_write_busy=1;
    xTaskCreatePinnedToCore(ota_rtc_write_task,"rtcw",4096,NULL,1,NULL,0); //CPU_0 PRO_CPU needed for rtc operations
    while (rtc_write_busy) vTaskDelay(1);
    vTaskDelay(50); //allows UDPLOG to flush
    esp_restart();
}

void  ota_reboot(void) {
    UDPLGP("--- ota_reboot\n");
    if (ledblinkHandle) {
        vTaskDelete(ledblinkHandle);
        gpio_ll_output_disable (&GPIO, led);
    }
    vTaskDelay(50); //allows UDPLOG to flush
    esp_restart();
}

int  ota_emergency(char * *ota_srvr) {
    UDPLGP("--- ota_emergency?\n");

    if (otabeta) {
        size_t size;
        char* value=NULL;
        if (nvs_get_str(lcm_handle,"ota_srvr", NULL,  &size)==ESP_OK) {
            value = malloc(size);
            nvs_get_str(lcm_handle,"ota_srvr", value, &size);
            *ota_srvr=value;
        } else return 0;
        nvs_erase_key(lcm_handle,"ota_srvr");
        nvs_erase_key(lcm_handle,"lcm_beta");
        nvs_commit(lcm_handle);
        UDPLGP("YES: backing up from http://%s\n",*ota_srvr);
        return 1;
    } else return 0;
}
