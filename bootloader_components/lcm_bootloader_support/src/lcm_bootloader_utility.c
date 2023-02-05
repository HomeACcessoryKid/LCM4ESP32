/*
 * SPDX-FileCopyrightText: 2018-2021 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <sys/param.h>

#include "esp_attr.h"
#include "esp_log.h"

#include "esp_rom_sys.h"
#include "esp_rom_uart.h"
#include "sdkconfig.h"
#if CONFIG_IDF_TARGET_ESP32
#include "soc/dport_reg.h"
#include "esp32/rom/cache.h"
#include "esp32/rom/secure_boot.h"
#elif CONFIG_IDF_TARGET_ESP32S2
#include "esp32s2/rom/secure_boot.h"
#elif CONFIG_IDF_TARGET_ESP32S3
#include "esp32s3/rom/secure_boot.h"
#elif CONFIG_IDF_TARGET_ESP32C3
#include "esp32c3/rom/efuse.h"
#include "esp32c3/rom/crc.h"
#include "esp32c3/rom/uart.h"
#include "esp32c3/rom/gpio.h"
#include "esp32c3/rom/secure_boot.h"
#elif CONFIG_IDF_TARGET_ESP32H2
#include "esp32h2/rom/efuse.h"
#include "esp32h2/rom/crc.h"
#include "esp32h2/rom/uart.h"
#include "esp32h2/rom/gpio.h"
#include "esp32h2/rom/secure_boot.h"
#elif CONFIG_IDF_TARGET_ESP32C2
#include "esp32c2/rom/efuse.h"
#include "esp32c2/rom/crc.h"
#include "esp32c2/rom/rtc.h"
#include "esp32c2/rom/uart.h"
#include "esp32c2/rom/gpio.h"
#include "esp32c2/rom/secure_boot.h"
#else // CONFIG_IDF_TARGET_*
#error "Unsupported IDF_TARGET"
#endif

#include "soc/soc.h"
#include "soc/rtc.h"
#include "soc/gpio_periph.h"
#include "soc/efuse_periph.h"
#include "soc/rtc_periph.h"
#include "soc/timer_periph.h"

#include "esp_image_format.h"
#include "esp_secure_boot.h"
#include "esp_flash_encrypt.h"
#include "esp_flash_partitions.h"
#include "bootloader_flash_priv.h"
#include "bootloader_random.h"
#include "bootloader_config.h"
#include "bootloader_common.h"
#include "lcm_bootloader_utility.h"
#include "bootloader_sha.h"
#include "bootloader_console.h"
#include "bootloader_soc.h"
#include "esp_efuse.h"
#include "esp_fault.h"

#include "hal/gpio_hal.h"

bool lcm_bootloader_rtc(uint32_t count) {
    bool temp_boot=false;
    rtc_retain_mem_t* rtcmem=bootloader_common_get_rtc_retain_mem(); //access to the memory struct
    uint8_t custom1=rtcmem->custom[1];
    if (bootloader_common_get_rtc_retain_mem_reboot_counter()) { //if zero, RTC CRC not valid
        if (custom1) temp_boot=true; //byte one  for temp_boot signal (from app to bootloader)    
    }
    bootloader_common_update_rtc_retain_mem(NULL, true); //prepare RTC memory and increment reboot_counter
    if (count>255) count=255;
    rtcmem->custom[0]=(uint8_t)count;            //byte zero for count,
    rtcmem->custom[1]=0; //reset the temp_boot flag for the next boot
    bootloader_common_update_rtc_retain_mem(NULL,false); //this will update the CRC only
    return temp_boot;
}

// uncomment to add a boot delay, allows you time to connect
// a terminal before rBoot starts to run and output messages
// value is in microseconds
#define BOOT_DELAY_MICROS 50000
// to define the time within a new powercycle/reboot will be counted
#define BOOT_CYCLE_DELAY_MICROS 1000000 //1 second? NO, actually this is ??? seconds but that is OK...
// indicates where the powercycle tracker bits are stored,
// first half for continue-bits, last half for start-bits
// other space between rboot-config and this address can be used for other purposes
#define BOOT_BITS_ADDR 0x40 // target value 0x40 and is relative to start of INactive ota_data sector
#define FIELD_SIZE (SPI_SEC_SIZE-BOOT_BITS_ADDR)/2

uint32_t lcm_bootloader_count(const bootloader_state_t *bs) {
//     ESP_LOGI("BL4LCM32","ota_info: 0x%x  0x%x",bs->ota_info.offset,bs->ota_info.size);
    uint32_t buff0=0,buff1=0;
    bootloader_flash_read(bs->ota_info.offset, &buff0, 4, 0);
    bootloader_flash_read(bs->ota_info.offset+SPI_SEC_SIZE, &buff1, 4, 0);
//     ESP_LOGI("BL4LCM32","0=0x%x  1=0x%x",buff0,buff1);
//     int32_t buff[8];
//     bootloader_flash_read(bs->ota_info.offset, &buff, 32, 0);
//     for (int i=0; i<8; i++) ESP_LOGI("BL4LCM32","%d=0x%x",i,buff[i]);
    if (buff1==UINT32_MAX) buff1=0; //for uninitialized ota_data[1]
    uint32_t offset=(buff1>buff0)?bs->ota_info.offset:bs->ota_info.offset+SPI_SEC_SIZE; //select the INactive part
    //TODO: choose a better algorithm because this on is not perfect

/* --------------------------------------------
Assumptions for the storage of start- and continue-bits
they will be stored in at the end of BOOT_CONFIG_SECTOR after with the rboot parameters and user parameters
the define BOOT_BITS_ADDR indicates where the bits are stored, first half for continue-bits, last half for start-bits
they should be multiples of 8bytes which will assure that the start of the start_bits is at a 32bit address
the last byte will contain the amount of open continue-bits and is a signal for reflash of this sector
  --------------------------------------------- */
    uint32_t last_addr=offset+SPI_SEC_SIZE;
    uint32_t start_bits, continue_bits, help_bits, count;

    //read last byte of BOOT_CONFIG_SECTOR to see if we need to reflash it if we ran out of status bits
    //Important to do it ASAP since it reduces the chance of being interupted by a power cycle
    uint32_t loadAddr=offset+BOOT_BITS_ADDR+FIELD_SIZE;
    bootloader_flash_read(last_addr-4, &count, 4,0);
    if (count<33) { //default value is 0xffffffff
    	uint32_t buffer[BOOT_BITS_ADDR/4];
        bootloader_flash_read(offset, buffer, BOOT_BITS_ADDR,0);
        bootloader_flash_erase_range(offset,SPI_SEC_SIZE);
        bootloader_flash_write(offset, buffer, BOOT_BITS_ADDR,0);
        start_bits=(uint32_t)~0>>count; //clear start-bits based on value of count
        bootloader_flash_write(loadAddr,&start_bits,4,0);
    }

#if defined BOOT_DELAY_MICROS && BOOT_DELAY_MICROS > 0
	// delay to slow boot (help see messages when debugging)
	esp_rom_delay_us(BOOT_DELAY_MICROS);
#endif

    esp_rom_printf("BL4LCM32: 0=0x%x  1=0x%x  offset=0x%x\n",buff0,buff1,offset);
    if (count<33)  esp_rom_printf("BL4LCM32: reformatted start_bits field: %08x count: %d\n",start_bits,count);
    //read the led_pin info from BOOT_BITS_ADDR-4 from both sectors
    bootloader_flash_read(bs->ota_info.offset+            +BOOT_BITS_ADDR-4, &buff0, 4,0);
    bootloader_flash_read(bs->ota_info.offset+SPI_SEC_SIZE+BOOT_BITS_ADDR-4, &buff1, 4,0);
    if (buff0!=buff1) { //out of sync, must correct, lowest value is the target
        if (buff0<buff1) {
            bootloader_flash_write(bs->ota_info.offset+SPI_SEC_SIZE+BOOT_BITS_ADDR-4, &buff0, 4,0);
        } else {
            bootloader_flash_write(bs->ota_info.offset+            +BOOT_BITS_ADDR-4, &buff1, 4,0);
            buff0=buff1;
        }
    } //buff0 contains flash based led_info

    //find the beginning of start-bit-range
    do {bootloader_flash_read(loadAddr,&start_bits,4,0);
        if (start_bits) esp_rom_printf("BL4LCM32:          %08x @ %04x\n",start_bits,loadAddr);
        loadAddr+=4;
    } while (!start_bits && loadAddr<last_addr); //until a non-zero value
    loadAddr-=4; //return to the address where start_bits was read
    
    bootloader_flash_read(loadAddr-FIELD_SIZE,&continue_bits,4,0);
    if (continue_bits!=~0 || loadAddr-FIELD_SIZE<=offset+BOOT_BITS_ADDR) esp_rom_printf("BL4LCM32:          %08x @ %04x",continue_bits,loadAddr-FIELD_SIZE);
    count=1;
    help_bits=~start_bits&continue_bits; //collect the bits that are not in start_bits
    while (help_bits) {help_bits&=(help_bits-1);count++;} //count the bits using Brian Kernighan’s Algorithm
    if (continue_bits==~0 && loadAddr-FIELD_SIZE>offset+BOOT_BITS_ADDR) {
        bootloader_flash_read(loadAddr-FIELD_SIZE-4,&help_bits,4,0); //read the previous word
         esp_rom_printf("BL4LCM32: %08x ffffffff @ %04x",help_bits,loadAddr-FIELD_SIZE-4);
        while (help_bits) {help_bits&=(help_bits-1);count++;} //count more bits
    }
     esp_rom_printf(" => count: %d\n",count);
    
    //clear_start_bit();
    if (loadAddr<last_addr-4) {
        start_bits>>=1; //clear leftmost 1-bit
        bootloader_flash_write(loadAddr,&start_bits,4,0);
    } else { //reflash this sector because we reached the end (encode count in last byte and do in next cycle)
        bootloader_flash_write(last_addr-4,&count,4,0);
    }
    
    int led_pin=0,polarity=0;
    if (buff0!=UINT32_MAX) { //actual value to apply to led_pin
	    polarity=buff0&0x80?1:0; led_pin=buff0&0x7f;
	    if ( led_pin>=6 && led_pin<=11 ) led_pin=0; //do not allow pins 0 and 6-11
	    //TODO: make this chiptype dependent
        esp_rom_printf("BL4LCM32: led_pin=%d,  polarity=%d\n",led_pin,polarity);
    } //else no led, encoded as led_pin=0

    if (count>1 && count<16) { //some devices have trouble to find the right timing for a power cycle so delay*3
        if (led_pin) {
            esp_rom_printf("BL4LCM32: LED ON\n");
            gpio_ll_output_enable (&GPIO, led_pin);
            gpio_ll_set_level (&GPIO, led_pin, 1-polarity);
        }
        esp_rom_delay_us(2*BOOT_CYCLE_DELAY_MICROS);
    }
    if (count<16) esp_rom_delay_us(BOOT_CYCLE_DELAY_MICROS);
//==================================================//if we powercycle, this is where it stops!
    if (led_pin && count>1 && count<16) {
        esp_rom_printf("          and OFF\n");
        gpio_ll_output_disable(&GPIO, led_pin);
    }

    help_bits=0; //clear_all_continue_bits
    if (loadAddr<last_addr-4) {
        if (continue_bits==~0 && loadAddr-FIELD_SIZE>offset+BOOT_BITS_ADDR) bootloader_flash_write(loadAddr-FIELD_SIZE-4,&help_bits,4,0);
        bootloader_flash_write(loadAddr-FIELD_SIZE,&start_bits,4,0);
    } else { //reflash this sector because we reached the end (encode ZERO in last byte and do in next cycle)
        bootloader_flash_write(last_addr-4,&help_bits,4,0);
    }
//  --------------------------------------------
//  End of rboot4lcm key code. count is used further down for choosing rom and stored in rtc for ota-main to interpret
//  ---------------------------------------------
    return count;
}
