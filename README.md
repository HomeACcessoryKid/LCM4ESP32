# LCM4ESP32
life-cycle-manager for ESP32

early stages of porting https://github.com/HomeACcessoryKid/life-cycle-manager to ESP32  
do not use before it reaches v1.0.0 unless you feel like experimenting together with me  
All documentation about strategy is at [LCM](https://github.com/HomeACcessoryKid/life-cycle-manager) for now  
Intention to use many native components of ESP32 like esp_http_client and ota concepts  
Initial testing show that they can be useful.  
native_ota_example seems useful too.

you have to apply a fix if you want to compile:  
```
   based on fix for https://github.com/espressif/esp-idf/issues/8873:
   /opt/esp/idf/components/esp_http_client# mv esp_http_client.c esp_http_client.c.0
   /opt/esp/idf/components/esp_http_client# cat esp_http_client.c.0 | \
   sed 's/http_utils_append_string(\&client->location/http_utils_assign_string(\&client->location/' > esp_http_client.c
   root@15550ce5e2b8:/opt/esp/idf/components/esp_http_client# diff esp_http_client.c*
   236c236
   <         http_utils_assign_string(&client->location, at, length);
   ---
   >         http_utils_append_string(&client->location, at, length);
```

to flash, first time:  
```
esptool.py --chip esp32  write_flash --flash_mode dio --flash_size detect --flash_freq 40m \   
0x20d000 build/ota_data_initial.bin 0x300000 build/LCM4ESP32.bin \   
0x1000 build/bootloader/bootloader.bin 0x8000 build/partition_table/partition-table.bin
```

after, for new attempts, so you do not wear out your ESP32 flash sectors in the first 2M:  
```
esptool.py --chip esp32  write_flash --flash_mode dio --flash_size detect --flash_freq 40m \  
0x20d000 build/ota_data_initial.bin 0x300000 build/LCM4ESP32.bin
```

