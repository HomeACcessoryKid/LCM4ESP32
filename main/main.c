/* (c) 2018-2022 HomeAccessoryKid
 * LCM4ESP32 based on LifeCycleManager dual app
 */

#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_ota_ops.h"
// #include "esp_http_client.h"
#include "esp_flash_partitions.h"
#include "esp_partition.h"
#include "nvs.h"
#include "nvs_flash.h"
// #include "driver/gpio.h"
#include "errno.h"

#define HASH_LEN 32 /* SHA-256 digest length */
static const char *TAG = "native_ota_example";

static void print_sha256 (const uint8_t *image_hash, const char *label)
{
    char hash_print[HASH_LEN * 2 + 1];
    hash_print[HASH_LEN * 2] = 0;
    for (int i = 0; i < HASH_LEN; ++i) {
        sprintf(&hash_print[i * 2], "%02x", image_hash[i]);
    }
    ESP_LOGI(TAG, "%s: %s", label, hash_print);
}


#include "ota.h"
#include "wifi_config.h"

void ota_task(void *arg) {
    int holdoff_time=1; //32bit, in seconds
    char* user_repo=NULL;
    char* user_version=NULL;
    char* user_file=NULL;
    char*  new_version=NULL;
    char*  ota_version=NULL;
    signature_t signature;
    int file_size; //32bit
    int keyid,foundkey=0;
    char keyname[KEYNAMELEN];
    ota_init();
    
    file_size=ota_get_pubkey(active_cert_sector);
    if (ota_boot()) ota_write_status("0.0.0");  //we will have to get user code from scratch if running ota_boot
    if ( !ota_load_user_app(&user_repo, &user_version, &user_file)) { //repo/file must be configured
#ifdef OTABOOT    
        if (ota_boot()) {
            new_version=ota_get_version(user_repo); //check if this repository exists at all
            if (!strcmp(new_version,"404")) {
                UDPLGP("%s does not exist! HALTED TILL NEXT POWERCYCLE!\n",user_repo);
                vTaskDelete(NULL);
            }
        }
#endif
        
        for (;;) { //escape from this loop by continue (try again) or break (boots into slot 0)
            UDPLGP("--- entering the loop\n");
            //UDPLGP("%d\n",sdk_system_get_time()/1000);
            //need for a protection against an electricity outage recovery storm
            vTaskDelay(holdoff_time*(1000/portTICK_PERIOD_MS));
            holdoff_time*=HOLDOFF_MULTIPLIER; holdoff_time=(holdoff_time<HOLDOFF_MAX) ? holdoff_time : HOLDOFF_MAX;
            
            //do we still have a valid internet connexion? dns resolve github... should not be private IP
            
            ota_get_pubkey(active_cert_sector); //in case the LCM update is in a cycle
            
//             ota_set_verify(0); //should work even without certificates
            if (ota_version) free(ota_version);
            ota_version=ota_get_version(OTAREPO);
            if (ota_get_hash(OTAREPO, ota_version, CERTFILE, &signature)) { //no certs.sector.sig exists yet on server
                    continue; //loop and try again later
            }
            if (ota_verify_hash(active_cert_sector,&signature)) { //seems we need to download certificates
                if (ota_verify_signature(&signature)) { //maybe an update on the public key
                    keyid=1;
                    while (sprintf(keyname,KEYNAME,keyid) , !ota_get_hash(OTAREPO, ota_version, keyname, &signature)) {
                        if (!ota_verify_signature(&signature)) {foundkey=1; break;}
                        keyid++;
                    }
                    if (!foundkey) break; //leads to boot=0
                    //we found the head of the chain of pubkeys
                    while (--keyid) {
                        ota_get_file(OTAREPO,ota_version,keyname,backup_cert_sector);
                        if (ota_verify_hash(backup_cert_sector,&signature)) {foundkey=0; break;}
                        ota_get_pubkey(backup_cert_sector); //get one newer pubkey
                        sprintf(keyname,KEYNAME,keyid);
                        if (ota_get_hash(OTAREPO,ota_version,keyname,&signature)) {foundkey=0; break;}
                        if (ota_verify_signature(&signature)) {foundkey=0; break;}
                    }
                    if (!foundkey) break; //leads to boot=0
                }
                ota_get_file(OTAREPO,ota_version,CERTFILE,backup_cert_sector); //CERTFILE=public-1.key
                if (ota_verify_hash(backup_cert_sector,&signature)) break; //leads to boot=0
                ota_swap_cert_sector();
                ota_get_pubkey(active_cert_sector);
            } //certificates are good now
            
#ifdef OTABOOT    
            //now get the latest ota main software in boot sector 1
            if (ota_get_hash(OTAREPO, ota_version, MAINFILE, &signature)) { //no signature yet
                    continue; //loop and try again later
            } else { //we have a signature, maybe also the main file?
                if (ota_verify_signature(&signature)) continue; //signature file is not signed by our key, ABORT
                if (ota_verify_hash(BOOT1SECTOR,&signature)) { //not yet downloaded
                    file_size=ota_get_file(OTAREPO,ota_version,MAINFILE,BOOT1SECTOR);
                    if (file_size<=0) continue; //try again later
                    if (ota_verify_hash(BOOT1SECTOR,&signature)) continue; //download failed
                    ota_finalize_file(BOOT1SECTOR);
                }
            } //now file is here for sure and matches hash
            ota_temp_boot(); //launches the ota software in bootsector 1
/*    
#else //NOT OTABOOT    
            UDPLGP("--- running ota-main software\n");
            //is there a newer version of the bootloader...
            if (new_version) free(new_version);
            new_version=ota_get_version(BTLREPO);
            if (strcmp(new_version,"404")) {
                if (ota_compare(new_version,btl_version)>0) { //can only upgrade
                    UDPLGP("BTLREPO=\'%s\' new_version=\'%s\' BTLFILE=\'%s\'\n",BTLREPO,new_version,BTLFILE);
                    if (!ota_get_hash(BTLREPO, new_version, BTLFILE, &signature)) {
                        if (!ota_verify_signature(&signature)) {
                            file_size=ota_get_file(BTLREPO,new_version,BTLFILE,backup_cert_sector);
                            if (file_size>0 && !ota_verify_hash(backup_cert_sector,&signature)) {
                                ota_finalize_file(backup_cert_sector);
                                ota_copy_bootloader(backup_cert_sector, file_size, new_version); //transfer it to sector zero
                            }
                        }
                    } //else maybe next time more luck for the bootloader
                } //no bootloader update 
            }
            //if there is a newer version of ota-main...
            if (ota_compare(ota_version,OTAVERSION)>0) { //set OTAVERSION when running make and match with github
                ota_get_hash(OTAREPO, ota_version, BOOTFILE, &signature);
                if (ota_verify_signature(&signature)) break; //signature file is not signed by our key, ABORT
                file_size=ota_get_file(OTAREPO,ota_version,BOOTFILE,BOOT0SECTOR);
                if (file_size<=0) continue; //something went wrong, but now boot0 is broken so start over
                if (ota_verify_hash(BOOT0SECTOR,&signature)) continue; //download failed
                ota_finalize_file(BOOT0SECTOR);
                break; //leads to boot=0 and starts self-updating/otaboot-app
            } //ota code is up to date
            ota_set_verify(1); //reject faked server only for user_repo
            if (new_version) free(new_version);
            new_version=ota_get_version(user_repo);
            if (ota_compare(new_version,user_version)>0) { //can only upgrade
                UDPLGP("user_repo=\'%s\' new_version=\'%s\' user_file=\'%s\'\n",user_repo,new_version,user_file);
                if (!ota_get_hash(user_repo, new_version, user_file, &signature)) {
                    file_size=ota_get_file(user_repo,new_version,user_file,BOOT0SECTOR);
                    if (file_size<=0 || ota_verify_hash(BOOT0SECTOR,&signature)) continue; //something went wrong, but now boot0 is broken so start over
                    ota_finalize_file(BOOT0SECTOR); //TODO return status and if wrong, continue
                    ota_write_status(new_version); //we have been successful, hurray!
                } else break; //user did not supply a proper sig file or fake server -> return to boot0
            } //nothing to update
            break; //leads to boot=0 and starts updated user app
*/
#endif //OTABOOT
        }
    }
    ota_reboot(); //boot0, either the user program or the otaboot app
    vTaskDelete(NULL); //just for completeness sake, would never get till here
}


void on_wifi_ready() {
    UDPLGP("--- on_wifi_ready\n");
//     char* ota_srvr=NULL;
// 
//     if (ota_emergency(&ota_srvr)){
//         xTaskCreate(emergency_task,EMERGENCY,4096,ota_srvr,1,NULL);
//     } else {
        xTaskCreate(ota_task,"ota",8192,NULL,5,NULL);
//     }
}


void app_main(void)
{
    uint8_t sha_256[HASH_LEN] = { 0 };
    esp_partition_t partition;

    // get sha256 digest for the partition table
    partition.address   = ESP_PARTITION_TABLE_OFFSET;
    partition.size      = ESP_PARTITION_TABLE_MAX_LEN;
    partition.type      = ESP_PARTITION_TYPE_DATA;
    esp_partition_get_sha256(&partition, sha_256);
    print_sha256(sha_256, "SHA-256 for the partition table: ");

    // get sha256 digest for bootloader
    partition.address   = ESP_BOOTLOADER_OFFSET;
    partition.size      = ESP_PARTITION_TABLE_OFFSET;
    partition.type      = ESP_PARTITION_TYPE_APP;
    esp_partition_get_sha256(&partition, sha_256);
    print_sha256(sha_256, "SHA-256 for bootloader: ");

    // get sha256 digest for running partition
    esp_partition_get_sha256(esp_ota_get_running_partition(), sha_256);
    print_sha256(sha_256, "SHA-256 for current firmware: ");

    const esp_partition_t *running = esp_ota_get_running_partition();
    esp_ota_img_states_t ota_state;
    if (esp_ota_get_state_partition(running, &ota_state) == ESP_OK) {
        if (ota_state == ESP_OTA_IMG_PENDING_VERIFY) {
            ESP_LOGI(TAG, "Diagnostics completed successfully! Continuing execution ...");
            esp_ota_mark_app_valid_cancel_rollback();
        }
    }

    ota_nvs_init();

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    wifi_config_init("LCM", NULL, on_wifi_ready);
}
