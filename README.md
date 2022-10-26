# LCM4ESP32
life-cycle-manager for ESP32

Partition table has been changed (need 64k less for ota_0) so reflash the table if you have an alpha deployment.  

Beta stages of porting LCM: https://github.com/HomeACcessoryKid/life-cycle-manager to ESP32.  
All functions* are working by now so it has become useful (*not LED function)

Feedback is welcome, while I think about how to support ESP32S2,S3 and ESP32C3 etc...

Do not use before it reaches v1.0.0 unless you feel like experimenting together with me  

All documentation about strategy is at [LCM](https://github.com/HomeACcessoryKid/life-cycle-manager) for now  

Using many native components of ESP32 like mbedtls, esp_https_client and ota concepts  
However, I do not use the ota_data partition to its intended purpose  
Instead the bootloader uses the powercycle count and RTC memory  

follow instructions in deploy.md for now

also see Changelog.md

# Life Cycle Manager32 Release and SoC Compatibility

The following table shows Life Cycle Manager32 support of Espressif SoCs where ![alt text][preview] and ![alt text][supported] denote preview status and support, respectively.

|Chip         |          Life Cycle Manager32 V0.9.1         |
|:----------- |:---------------------:|
|ESP32        |![alt text][supported] |
|ESP32-S2     |![alt text][supported] |
|ESP32-C3     |![alt text][supported] | 
|ESP32-S3     |![alt text][preview]   |
|ESP32-C2     |![alt text][preview]   |
|ESP32-C6     |![alt text][preview]   |
|ESP32-H2     |![alt text][preview]   | 

[supported]: https://img.shields.io/badge/-supported-green "supported"
[preview]: https://img.shields.io/badge/-preview-orange "preview"
