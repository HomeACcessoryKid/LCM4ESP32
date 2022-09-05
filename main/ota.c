/*  (c) 2018-2022 HomeAccessoryKid */
#include <string.h>
#include <time.h>
#include <sys/time.h>
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
#include "mbedtls/certs.h"
#include "mbedtls/ecdsa.h"
#include "bootloader_common.h"
#include "esp_wifi.h"
#include "esp_sntp.h"

mbedtls_ssl_config mbedtls_conf;
mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_x509_crt cacert;
mbedtls_ecdsa_context mbedtls_ecdsa_ctx;

#define BUFFSIZE 1024
#define NAME2SECTOR(sectorname) esp_partition_find_first(ESP_PARTITION_TYPE_ANY,ESP_PARTITION_SUBTYPE_ANY,sectorlabel[sectorname])
char sectorlabel[][10]={"buffer","lcmcert_1","lcmcert_2","ota_0","ota_1"}; //label of sector in partition table to index. zero reserved

static const char *TAG = "LCM";

static int  verify = 1;
uint8_t userbeta=0;
uint8_t otabeta=0;
// int8_t led=16;
static byte file_first_byte[]={0xff};

nvs_handle_t lcm_handle;
void  ota_nvs_init() {
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
    free(lc_string);
    if(found == NULL) return NULL;    
    const int offset = (int) found - (int) lc_string;
    
    return (char *) ((int) full_string + offset);
}

static uint8_t count=0,rtc_read_busy=1;
void ota_rtc_read_task(void *arg) {
    if (bootloader_common_get_rtc_retain_mem_reboot_counter()) { //if zero, RTC CRC not valid
        rtc_retain_mem_t* rtcmem=bootloader_common_get_rtc_retain_mem(); //access to the memory struct
        count=rtcmem->custom[0]; //byte zero for count
    } else {
        count=0;
    }
    bootloader_common_reset_rtc_retain_mem(); //this will clear RTC
    rtc_read_busy=0;
    vTaskDelete(NULL);
}

void  ota_read_rtc() {
    UDPLGP("--- ota_read_rtc\n");
    rtc_read_busy=1;
    xTaskCreatePinnedToCore(ota_rtc_read_task,"rtcr",4096,NULL,1,NULL,0); //CPU_0 PRO_CPU needed for rtc operations
    while (rtc_read_busy) vTaskDelay(1);
	uint8_t user_count=1,count_step=3;
    char *value=NULL;
    bool reset_wifi=0;
    bool reset_otabeta=0;
    bool factory_reset=0;

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
    if (count>4) {
        UDPLGP("IF this is NOT what you wanted, reset/power-down NOW!\n");
        for (int i=19;i>-1;i--) {
            vTaskDelay(1000/portTICK_PERIOD_MS);
            UDPLGP("%s in %d s\n",value,i);
        }
    }
    if (factory_reset) {        
        nvs_flash_deinit();
        esp_partition_t *partition=NULL;
        esp_partition_iterator_t it=esp_partition_find(ESP_PARTITION_TYPE_ANY,ESP_PARTITION_SUBTYPE_ANY,NULL);
        while (it) {
            partition=esp_partition_get(it);
            UDPLGP("partition: %s",partition->label);
            if (strcmp(partition->label,"lcmcert_1") &&
                strcmp(partition->label,"lcmcert_2") &&
                strcmp(partition->label,"ota_data")  &&
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
    
    #ifdef OTABETA
    otabeta=1; //using beta = pre-releases?
    #endif
    if (otabeta && !reset_otabeta) nvs_set_u8(lcm_handle,"lcm_beta", 1);
    if (            reset_otabeta) nvs_erase_key(lcm_handle,"lcm_beta");
    nvs_commit(lcm_handle);
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

void  ota_init() {
    UDPLGP("%s %s version %s\n",esp_ota_get_app_description()->project_name,ota_boot()?"OTABOOT":"OTAMAIN",esp_ota_get_app_description()->version);
    UDPLGP("--- ota_init\n");

    int size=0;
    byte abyte[1];
    nvs_get_u8(lcm_handle,"lcm_beta", &otabeta);
    nvs_get_u8(lcm_handle,"ota_beta", &userbeta);
    UDPLGP("userbeta=\'%d\' otabeta=\'%d\'\n",userbeta,otabeta);
    
//     uint8_t led_info=0;
// 
//     status = sysparam_get_int8("led_pin", &led);
//     if (status == SYSPARAM_OK) {
//         if (led<0) {led_info=0x10; led=-led;}
//         led_info+=(led<16)?(0x40+(led&0x0f)):0;
//         if (led<16) xTaskCreate(led_blink_task, "ledblink", 256, NULL, 1, &ledblinkHandle);
//     }

    //time support
    sntp_setoperatingmode(SNTP_OPMODE_POLL);
    sntp_setservername(0, "pool.ntp.org");
    //setenv("TZ", "CET-1CEST,M3.5.0,M10.5.0", 3); //https://github.com/nayarsystems/posix_tz_db/blob/master/zones.csv
    //tzset();
    sntp_init();

    mbedtls_ecdsa_init(&mbedtls_ecdsa_ctx);
    mbedtls_ecp_group_load(&mbedtls_ecdsa_ctx.grp, MBEDTLS_ECP_DP_SECP384R1);
    
    ota_active_sector();
    
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

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,NULL, 0);
    mbedtls_ssl_config_init(&mbedtls_conf);
    mbedtls_ssl_config_defaults(&mbedtls_conf,MBEDTLS_SSL_IS_CLIENT,MBEDTLS_SSL_TRANSPORT_STREAM,MBEDTLS_SSL_PRESET_DEFAULT);
    mbedtls_x509_crt_init(&cacert);
    printf("cert parse: %d errors\n",mbedtls_x509_crt_parse(&cacert,certs,size));
    mbedtls_ssl_conf_ca_chain(&mbedtls_conf, &cacert, NULL);
    mbedtls_ssl_conf_rng(&mbedtls_conf, mbedtls_ctr_drbg_random, &ctr_drbg);
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
    ret=mbedtls_ecp_point_read_binary(&mbedtls_ecdsa_ctx.grp,&mbedtls_ecdsa_ctx.Q,buffer+23,length);
    printf("keycheck: 0x%02x\n",mbedtls_ecp_check_pubkey(&mbedtls_ecdsa_ctx.grp,&mbedtls_ecdsa_ctx.Q));
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
    
    mbedtls_net_init(socket);
    ESP_LOGI(TAG, "Connecting to %s:%d...", host, port);
    if ((ret = mbedtls_net_connect(socket, host,itoa(port,buf,10),MBEDTLS_NET_PROTO_TCP)) != 0) {
        ESP_LOGE(TAG, "mbedtls_net_connect returned -%x", -ret);
        return -2;
    }
    //ESP_LOGI(TAG, "Connected.");

    if (port==HTTPS_PORT) { //SSL mode, in emergency mode this is skipped
        mbedtls_ssl_init(ssl);
         // Hostname set here should match CN in server certificate
        if((ret = mbedtls_ssl_set_hostname(ssl, host)) != 0) {
            ESP_LOGE(TAG, "mbedtls_ssl_set_hostname returned -0x%x", -ret);
            return -1;
        }
        //ESP_LOGI(TAG, "SSLsetup...");
        if ((ret = mbedtls_ssl_setup(ssl, &mbedtls_conf)) != 0) {
            ESP_LOGE(TAG, "mbedtls_ssl_setup returned -0x%x\n\n", -ret);
            return -1;
        }
        //ESP_LOGI(TAG, "BIOsetup...");
        mbedtls_ssl_set_bio(ssl, socket, mbedtls_net_send, mbedtls_net_recv, NULL);
        //ESP_LOGI(TAG, "Performing the SSL/TLS handshake...");
        while ((ret = mbedtls_ssl_handshake(ssl)) != 0) {
            if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                ESP_LOGE(TAG, "mbedtls_ssl_handshake returned -0x%x", -ret);
                return -1;
            }
        }
        //ESP_LOGI(TAG, "Verifying peer X.509 certificate...");
        if ((flags = mbedtls_ssl_get_verify_result(ssl)) != 0) {
            bzero(buf, sizeof(buf));
            mbedtls_x509_crt_verify_info(buf, sizeof(buf), "", flags);
            ESP_LOGI(TAG, "%s", buf);
        } else {
            ESP_LOGI(TAG, "Certificate verified.");
        }
        //ESP_LOGI(TAG, "Cipher suite is %s", mbedtls_ssl_get_ciphersuite(ssl));
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
//             do {
                ts = time(NULL);
//                 if (ts == ((time_t)-1)) printf("ts=-1, ");
//                 vTaskDelay(1);
//             } while (!(ts>1073741823)); //2^30-1 which is supposed to be like 2004
            UDPLGP("TIME: %s", ctime(&ts)); //we need to have the clock right to check certificates
            
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

            ret = mbedtls_ssl_read(&ssl, (byte*)recv_buf, RECV_BUF_LEN - 1); //peek
            if (ret > 0) {
                recv_buf[ret]=0; //prevent falling of the end of the buffer when doing string operations
                found_ptr=ota_strstr(recv_buf,"http/1.1 ");
                found_ptr+=9; //flush "HTTP/1.1 "
                httpcode=atoi(found_ptr);
                UDPLGP("HTTP returns %d for ",httpcode);
                if (httpcode!=302) {
                    mbedtls_ssl_session_reset(&ssl);
                    mbedtls_net_free(&socket);
                    return "404";
                }
            } else {
                UDPLGP("failed, return [-0x%x]\n", -ret);
                return "404";
            }

            while (1) {
//                 recv_buf[ret]=0; //prevent falling of the end of the buffer when doing string operations
                found_ptr=ota_strstr(recv_buf,"\nlocation:");
                if (found_ptr) break;
//                 mbedtls_ssl_read(&ssl, (byte*)recv_buf, RECV_BUF_LEN - 12);
//                 ret = mbedtls_ssl_peek(&ssl, recv_buf, RECV_BUF_LEN - 1); //peek
                if (ret <= 0) {
                    UDPLGP("failed, return [-0x%x]\n", -ret);
//                     ret=wolfSSL_get_error(ssl,ret);
//                     UDPLGP("wolfSSL_send error = %d\n", ret);
                    return "404";
                }
            }
//             ret=mbedtls_ssl_read(&ssl, recv_buf, found_ptr-recv_buf + 11); //flush all previous material
//             ret=mbedtls_ssl_read(&ssl, recv_buf, RECV_BUF_LEN - 1); //this starts for sure with the content of "Location: "
//             recv_buf[ret]=0; //prevent falling of the end of the buffer when doing string operations
//             strchr(recv_buf,'\r')[0]=0;
            strchr(found_ptr,'\r')[0]=0;
            found_ptr=ota_strstr(recv_buf,"releases/tag/");
            if (found_ptr[13]=='v' || found_ptr[13]=='V') found_ptr++;
            version=malloc(strlen(found_ptr+13)+1);
            strcpy(version,found_ptr+13);
            printf("%s@version:\"%s\" according to latest release\n",repo,version);
        } else {
            UDPLGP("failed, return [-0x%x]\n", -ret);
//             ret=wolfSSL_get_error(ssl,ret);
//             UDPLGP("wolfSSL_send error = %d\n", ret);
        }
    }
    switch (retc) {
        case  0:
        case -1:
        mbedtls_ssl_session_reset(&ssl);
        case -2:
        mbedtls_net_free(&socket);
        case -3:
        default:
        ;
    }

//     if (retc) return retc;
//     if (ret <= 0) return ret;

//     //TODO: maybe add more error return messages... like version "99999.99.99"
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
    int  left;
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

            ret = mbedtls_ssl_read(&ssl, (byte*)recv_buf, RECV_BUF_LEN - 1); //peek
            if (ret > 0) {
                recv_buf[ret]=0; //prevent falling of the end of the buffer when doing string operations
                found_ptr=ota_strstr(recv_buf,"http/1.1 ");
                found_ptr+=9; //flush "HTTP/1.1 "
                slash=atoi(found_ptr);
                UDPLGP("HTTP returns %d\n",slash);
                if (slash!=302) {
                    mbedtls_ssl_session_reset(&ssl);
                    mbedtls_net_free(&socket);
                    return -1;
                }
            } else {
                UDPLGP("failed, return [-0x%x]\n", -ret);
                return -1;
            }
            while (1) {
//                 recv_buf[ret]=0; //prevent falling of the end of the buffer when doing string operations
                found_ptr=ota_strstr(recv_buf,"\nlocation:");
                if (found_ptr) break;
//                 mbedtls_ssl_read(&ssl, (byte*)recv_buf, RECV_BUF_LEN - 12);
//                 ret = mbedtls_ssl_peek(&ssl, recv_buf, RECV_BUF_LEN - 1); //peek
                if (ret <= 0) {
                    UDPLGP("failed, return [-0x%x]\n", -ret);
                    return -1;
                }
            }
//             ret=mbedtls_ssl_read(&ssl, recv_buf, found_ptr-recv_buf + 11); //flush all previous material
//             ret=mbedtls_ssl_read(&ssl, recv_buf, RECV_BUF_LEN - 1); //this starts for sure with the content of "Location: "
//             recv_buf[ret]=0; //prevent falling of the end of the buffer when doing string operations
//             strchr(recv_buf,'\r')[0]=0;
            strchr(found_ptr,'\r')[0]=0;
//             found_ptr=recv_buf;
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
        mbedtls_ssl_session_reset(&ssl);
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
        ret = mbedtls_ssl_write(&ssl, (byte*)recv_buf, send_bytes);
//         if (emergency) ret = lwip_write(socket, recv_buf, send_bytes); else ret = wolfSSL_write(ssl, recv_buf, send_bytes);
        recv_bytes=0;
        if (ret > 0) {
            printf("OK\n");

            header=1;
            memset(recv_buf,0,RECV_BUF_LEN);
            do {
                ret = mbedtls_ssl_read(&ssl, (byte*)recv_buf, RECV_BUF_LEN - 1);
//                 if (emergency) ret = lwip_read(socket, recv_buf, RECV_BUF_LEN - 1); else ret = wolfSSL_read(ssl, recv_buf, RECV_BUF_LEN - 1);
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
                    if (ret && !emergency) UDPLGP("error %d\n",ret);
//                     if (ret && !emergency) {ret=wolfSSL_get_error(ssl,ret); UDPLGP("error %d\n",ret);}
                    if (!ret && collected<length) retc = ota_connect(host2, port, &socket, &ssl); //memory leak?
                    break;
                }
                header=0; //if header and body are separted
            } while(recv_bytes<clength);
            printf(" so far collected %d bytes\n", collected);
//             UDPLGP(" collected %d bytes\r",        collected); //UDPLOG
        } else {
            printf("failed, return [-0x%x]\n", -ret);
            if (!emergency) {
            }
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
            if (err == ESP_ERR_OTA_VALIDATE_FAILED) ESP_LOGE(TAG, "Image validation failed, image is corrupted");
            else ESP_LOGE(TAG, "esp_ota_end failed (%s)!", esp_err_to_name(err));
        }
    }
    if (sector) {//cert_sectors and ota partitions
        printf("data length=%d, sector written=%s\n",collected,sectorlabel[sector]);
    } else {//buffer
        printf("data length=%d, buffer=%02x%02x %02x%02x ... %02x%02x %02x%02x\n",collected,
        buffer[0],buffer[1],buffer[2],buffer[3],buffer[collected-4],
        buffer[collected-3],buffer[collected-2],buffer[collected-1]);
    }

    UDPLGP("\n"); //UDPLOG
    switch (retc) {
        case  0:
        case -1:
        if (!emergency) {
        mbedtls_ssl_session_reset(&ssl);
        }
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

    if (sector>2) {
//         esp_err_t err = esp_ota_set_boot_partition(NAME2SECTOR(sector)); //TODO: verify if this can be removed?
//         if (err != ESP_OK) ESP_LOGE(TAG, "esp_ota_set_boot_partition failed (%s)!", esp_err_to_name(err));
    } else {
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
    //TODO: must setup mbedtls_ssl_conf_ca_chain(&mbedtls_conf, &cacert, NULL); again
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
    rtc_retain_mem_t* rtcmem=bootloader_common_get_rtc_retain_mem(); //access to the memory struct
    bootloader_common_reset_rtc_retain_mem(); //this will clear RTC    
    rtcmem->reboot_counter=1;
    rtcmem->custom[1]=1; //byte one for temp_boot signal (from app to bootloader)
    bootloader_common_update_rtc_retain_mem(NULL,false); //this will update the CRC only
    rtc_write_busy=0;
    vTaskDelete(NULL);
}

void  ota_temp_boot(void) {
    UDPLGP("--- ota_temp_boot\n");
    rtc_write_busy=1;
    xTaskCreatePinnedToCore(ota_rtc_write_task,"rtcw",4096,NULL,1,NULL,0); //CPU_0 PRO_CPU needed for rtc operations
    while (rtc_write_busy) vTaskDelay(1);
    vTaskDelay(20); //allows UDPLOG to flush
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
    esp_restart();
}




//===================================================
// snippets of potentially useful code below
//     const esp_partition_t *configured = esp_ota_get_boot_partition();
//     const esp_partition_t *running = esp_ota_get_running_partition();
// 
//     if (configured != running) {
//         ESP_LOGW(TAG, "Configured OTA boot partition at offset 0x%08x, but running from offset 0x%08x",
//                  configured->address, running->address);
//         ESP_LOGW(TAG, "(This can happen if either the OTA boot data or preferred boot image become corrupted somehow.)");
//     }
//     ESP_LOGI(TAG, "Running partition type %d subtype %d (offset 0x%08x)",
//              running->type, running->subtype, running->address);
// 
//     update_partition = esp_ota_get_next_update_partition(NULL);
//     assert(update_partition != NULL);
//     ESP_LOGI(TAG, "Writing to partition subtype %d at offset 0x%x",
//              update_partition->subtype, update_partition->address);
//     bool image_header_was_checked = false;
//             if (image_header_was_checked == false) {
//                 esp_app_desc_t new_app_info;
//                 if (data_read > sizeof(esp_image_header_t) + sizeof(esp_image_segment_header_t) + sizeof(esp_app_desc_t)) {
//                     // check current version with downloading
//                     memcpy(&new_app_info, &ota_write_data[sizeof(esp_image_header_t) + sizeof(esp_image_segment_header_t)], sizeof(esp_app_desc_t));
//                     ESP_LOGI(TAG, "New firmware version: %s", new_app_info.version);
// 
//                     esp_app_desc_t running_app_info;
//                     if (esp_ota_get_partition_description(running, &running_app_info) == ESP_OK) {
//                         ESP_LOGI(TAG, "Running firmware version: %s", running_app_info.version);
//                     }
// 
//                     const esp_partition_t* last_invalid_app = esp_ota_get_last_invalid_partition();
//                     esp_app_desc_t invalid_app_info;
//                     if (esp_ota_get_partition_description(last_invalid_app, &invalid_app_info) == ESP_OK) {
//                         ESP_LOGI(TAG, "Last invalid firmware version: %s", invalid_app_info.version);
//                     }
// 
//                     // check current version with last invalid partition
//                     if (last_invalid_app != NULL) {
//                         if (memcmp(invalid_app_info.version, new_app_info.version, sizeof(new_app_info.version)) == 0) {
//                             ESP_LOGW(TAG, "New version is the same as invalid version.");
//                             ESP_LOGW(TAG, "Previously, there was an attempt to launch the firmware with %s version, but it failed.", invalid_app_info.version);
//                             ESP_LOGW(TAG, "The firmware has been rolled back to the previous version.");
//                         }
//                     }
//                     if (memcmp(new_app_info.version, running_app_info.version, sizeof(new_app_info.version)) == 0) {
//                         ESP_LOGW(TAG, "Current running version is the same as a new. We will not continue the update.");
//                     }
// 
//                     image_header_was_checked = true;
// 
//                     err = esp_ota_begin(update_partition, OTA_WITH_SEQUENTIAL_WRITES, &update_handle);
//                     if (err != ESP_OK) {
//                         ESP_LOGE(TAG, "esp_ota_begin failed (%s)", esp_err_to_name(err));
//                         esp_ota_abort(update_handle);
//                     }
//                     ESP_LOGI(TAG, "esp_ota_begin succeeded");
//                 }
//             }
// 
//     err = esp_ota_end(update_handle);
//     if (err != ESP_OK) {
//         if (err == ESP_ERR_OTA_VALIDATE_FAILED) {
//             ESP_LOGE(TAG, "Image validation failed, image is corrupted");
//         } else {
//             ESP_LOGE(TAG, "esp_ota_end failed (%s)!", esp_err_to_name(err));
//         }

