/* (c) 2018-2022 HomeAccessoryKid
 * LCM4ESP32 based on LifeCycleManager dual app
 */

#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_app_desc.h"
#include "esp_flash_partitions.h"
#include "esp_partition.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "errno.h"


#include "ota.h"
#include "wifi_config.h"
#include <udplogger.h>

void ota_task(void *arg) {
    int holdoff_time=1; //32bit, in seconds
    char* user_repo=NULL;
    char* user_version=NULL;
    char* user_file=NULL;
    char*  new_version=NULL;
    char*  ota_version=NULL;
    signature_t signature;
    int file_size; //32bit
    uint16_t keyid;
    int foundkey=0;
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
#else //NOT OTABOOT    
            UDPLGP("--- running ota-main software\n");
/*
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
*/
            //if there is a newer version of ota-main...
            if (ota_compare(ota_version,(char*)esp_app_get_description()->version)>0) { //set OTAVERSION when running make and match with github
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
                    //TODO: try to check if actual flash file is already there by cheking hash first
                    file_size=ota_get_file(user_repo,new_version,user_file,BOOT0SECTOR);
                    if (file_size<=0 || ota_verify_hash(BOOT0SECTOR,&signature)) continue; //something went wrong, but now boot0 is broken so start over
                    ota_finalize_file(BOOT0SECTOR); //TODO return status and if wrong, continue
                    ota_write_status(new_version); //we have been successful, hurray!
                } else break; //user did not supply a proper sig file or fake server -> return to boot0
            } //nothing to update
            break; //leads to boot=0 and starts updated user app
#endif //OTABOOT
        }
    } else {
        UDPLGP("Repository details do not exist! Use factory reset (15ps) to start over! HALTED TILL NEXT POWERCYCLE!\n");
        vTaskDelete(NULL);
    }
    ota_reboot(); //boot0, either the user program or the otaboot app
    vTaskDelete(NULL); //just for completeness sake, would never get till here
}

void emergency_task(void *ota_srvr) {
    UDPLGP("--- emergency_task\n");
    signature_t signature;
    
    ota_active_sector();
    ota_get_pubkey(active_cert_sector);
    if (ota_get_hash(ota_srvr,EMERGENCY,BOOTFILE,&signature))       vTaskDelete(NULL);
    if (ota_verify_signature(&signature))                           vTaskDelete(NULL);
    if (ota_get_file(ota_srvr,EMERGENCY,BOOTFILE,BOOT0SECTOR)<=0)   vTaskDelete(NULL);
    if (ota_verify_hash(BOOT0SECTOR,&signature))                    vTaskDelete(NULL);
    //TODO: verify if version in loaded file is higher than otamain version downloading it
    ota_finalize_file(BOOT0SECTOR);
    ota_reboot(); //boot0, the new otaboot app
    vTaskDelete(NULL); //just for completeness sake, would never get till here
}

void on_wifi_ready() {
    UDPLGP("--- on_wifi_ready\n");
    char* ota_srvr=NULL;

    if (ota_emergency(&ota_srvr)){
        xTaskCreate(emergency_task,EMERGENCY,8192,ota_srvr,5,NULL);
    } else {
        xTaskCreate(ota_task,"ota",8192,NULL,5,NULL);
    }
}


void app_main(void) {
    UDPLGP("--- app_main\n");
    udplogger_init(3);
    ota_nvs_init();
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    ota_pre_wifi(); //do stuff like read rtc, check partition table etc.
    wifi_config_init("LCM", NULL, on_wifi_ready); //expanded it with setting repo-details
}
