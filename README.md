# LCM4ESP32
life-cycle-manager for ESP32

Alpha stages of porting LCM: https://github.com/HomeACcessoryKid/life-cycle-manager to ESP32.  
Most functions are working by now so it has become more or less usefull

Do not use before it reaches v1.0.0 unless you feel like experimenting together with me  

All documentation about strategy is at [LCM](https://github.com/HomeACcessoryKid/life-cycle-manager) for now  

Using many native components of ESP32 like esp_http_client and ota concepts  
However, I do not use the ota_data partition to its intended purpose  
Instead the bootloader uses the powercycle count and RTC memory  

follow instructions in deploy.md for now

in release note for 0.1.0 is a list of things that still needed doing at that time  
later releases should be closing those little by little
