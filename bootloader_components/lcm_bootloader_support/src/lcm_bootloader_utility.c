/*
 * SPDX-FileCopyrightText: 2018-2021 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * (c) 2018-2024 HomeAccessoryKid
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

// uncomment to add a boot delay, allows you time to connect
// a terminal before rBoot starts to run and output messages
// value is in microseconds
#define BOOT_DELAY_MICROS 50000
// to define the time within a new powercycle/reboot will be counted
#define BOOT_CYCLE_DELAY_MICROS 1000000 //1 second? NO, actually this is ??? seconds but that is OK...
// indicates where the powercycle tracker bits are stored,
// first half for continue-bits, last half for start-bits
// other space between rboot-config and this address can be used for other purposes
#define OTA_DATA_SIZE  0x40 // target value 0x40 and is relative to start of INactive ota_data sector
#define COUNT_VAL_SIZE 0x10 // the COUNT_VAL area comes first and is 0x2C0 in size
#define COUNT_VAL_ADDR OTA_DATA_SIZE
#define BOOT_BITS_ADDR (COUNT_VAL_ADDR+COUNT_VAL_SIZE) //0x300
#define FIELD_SIZE (SPI_SEC_SIZE-BOOT_BITS_ADDR)/2

static uint32_t offset=0; //global variable to store the address where the LCM bitfields are stored = inactive half of otadata

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
    offset=(buff1>buff0)?bs->ota_info.offset:bs->ota_info.offset+SPI_SEC_SIZE; //select the INactive part
    //TODO: choose a better algorithm because this one is not perfect

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
    	uint32_t buffer[OTA_DATA_SIZE/4];
        bootloader_flash_read(offset, buffer, OTA_DATA_SIZE,0);
        bootloader_flash_erase_range(offset,SPI_SEC_SIZE);
        bootloader_flash_write(offset, buffer, OTA_DATA_SIZE,0);
        start_bits=(uint32_t)~0>>count; //clear start-bits based on value of count
        bootloader_flash_write(loadAddr,&start_bits,4,0);
    }

#if defined BOOT_DELAY_MICROS && BOOT_DELAY_MICROS > 0
	// delay to slow boot (help see messages when debugging)
	esp_rom_delay_us(BOOT_DELAY_MICROS);
#endif

    esp_rom_printf("BL4LCM32: 0=0x%x  1=0x%x  offset=0x%x\n",buff0,buff1,offset);
    if (count<33)  esp_rom_printf("BL4LCM32: reformatted start_bits field: %08x count: %d\n",start_bits,count);
    //read the led_pin info from OTA_DATA_SIZE-4 from both sectors
    bootloader_flash_read(bs->ota_info.offset+            +OTA_DATA_SIZE-4, &buff0, 4,0);
    bootloader_flash_read(bs->ota_info.offset+SPI_SEC_SIZE+OTA_DATA_SIZE-4, &buff1, 4,0);
    if (buff0!=buff1) { //out of sync, must correct, lowest value is the target
        if (buff0<buff1) {
            bootloader_flash_write(bs->ota_info.offset+SPI_SEC_SIZE+OTA_DATA_SIZE-4, &buff0, 4,0);
        } else {
            bootloader_flash_write(bs->ota_info.offset+            +OTA_DATA_SIZE-4, &buff1, 4,0);
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
//  End of rboot4lcm key code. count is used further down for choosing rom and stored in flash for ota-main to interpret
//  ---------------------------------------------
    return count;
}

bool lcm_bootloader_rtc(uint32_t count) {
    bool temp_boot=false;
    // transfer count value and temp_boot flag in flash
    // 1->0000, 2567->0010, 389A->0100, 4BCD->0110, EFG->1000   and temp_boot->1100 in the way back
    int ii,jj,vv,lvv;
    uint32_t val,new,word0,word1,word2;
    
    if (count<=4) { //count can range from 1 to 16
        if      (count== 1) new=0;
        else if (count== 2) new=2;
        else if (count== 3) new=4;
        else                new=6; //count==4
    } else { //otamain
        if      (count<= 7) new=2;
        else if (count<=10) new=4;
        else if (count<=13) new=6;
        else if (count<=16) new=8;
        else if (count<=19) new=10;//unassigned
        else                new=0; //illegal choice
    }
    // if first byte==0xFFFFFFFF initialise with first 4 x 0 bits 0x0FFFFFFF and last byte with 0xFFFFFFFE = last bit 0
    uint32_t count_addr=offset+COUNT_VAL_ADDR;
    bootloader_flash_read(count_addr, &word1, 4, 0);
    if (word1==UINT32_MAX) {
        word1=0x0FFFFFFF; word2=0xFFFFFFFE;
        bootloader_flash_write(count_addr,                 &word1,4,0);
        bootloader_flash_write(count_addr+COUNT_VAL_SIZE-4,&word2,4,0);
    }
    // read 4 bytes at a time (32 bit words)
    uint32_t bytes=0;
    do {bytes+=4; //first word can never fit the end sequence
        bootloader_flash_read(count_addr+bytes, &word2, 4, 0);
    } while ( !(word2==UINT32_MAX || (word2&0xF)==0xE) ); //all bits set or ends in 0b1110
    bytes-=4; //address the word before this as word1
    bootloader_flash_read(count_addr+bytes, &word1, 4, 0);
    //esp_rom_printf("xxxxxxxx %08lx %08lx  ", word1, word2);
    
    if (word2<UINT32_MAX-1) {word1=word2; word2=UINT32_MAX; bytes+=4;} //already started with bits in the last word, shift right
    
    val=0; ii=0;
    if ((word1&0xF)==0xE) { //word1 ends in 0xE
        ii=1; //skip last bit
        esp_rom_printf("will reflash\n");
        word0=0;//write last start-bits-word = 0x00000000 -> provokes flash erase in next boot
        bootloader_flash_write(offset+SPI_SEC_SIZE-4,&word0,4,0);
    }
    word0=0x10000000; // to detect if we need to flash or not
    // extract current value where we first evaluate word1 and conditionally word0 
    while ( (word1>>ii)&1 ) ii++; //find bit number ii for right-most zero
    for (jj=ii+1,vv=1; jj<32&&vv<4; jj++,vv++) if (word1>>jj&1) val+=(1<<vv); // copy three bits to val with index vv
    lvv=vv; // store the val index for later
    if(vv<4) { // we need word0 to complete the reading
        bootloader_flash_read(count_addr+bytes-4,  &word0, 4, 0);
        for (jj=0; vv<4; jj++,vv++)            if (word0>>jj&1) val+=(1<<vv); // fill val up to 3 bits, left are lvv bits
    }
    esp_rom_printf("%08lx %08lx %08lx  ", word0, word1, word2);
    esp_rom_printf("val=%ld, ii=%d, jj=%d, vv=%d, lvv=%d, bytes=%ld, count_addr=%0lx\n",val,ii,jj,vv,lvv,bytes,count_addr);
    
    if ( val==0xC) temp_boot=true; //0b1100, will only be set by external apps to signal temp_boot
    
    if ( val!=new ) { // decide if new value is different, else do nothing
        //reset bits on the left
        for (jj=ii;jj<ii+lvv;jj++) word1&=(~(1<<jj)); //put all lvv leftside bits to zero
        if (ii>28) word0=0; // wipe out previous word when less than 4 bits in this word

        switch (new) { // convert new value to new word(s). Make vv one less than relevant positions
            case 2: //..10
                vv=1; //need 1 bit beside the righthand zero
                break;
            case 4: //.100
            case 6: //.110
                vv=2; //need 2 bits beside the righthand zero
                break;
            case 8: //1000
            case 10://1010  unassigned
                vv=3; //need 3 bits beside the righthand zero
                break;
            default://1110 which is the EOF code, 0000 which is already encoded and 1100 reserved for temp_boot signaling
                vv=-1; // do nothing since not legal/already done
                break;
        }
        
        for (jj=ii-1; jj>=0&&vv>=0; jj--,vv--) if (!(new&(1<<vv))) word1&=(~(1<<jj)); //transfer bits to word1
        if (vv>=0) for (jj=31;vv>=0;jj--,vv--) if (!(new&(1<<vv))) word2&=(~(1<<jj)); //if bits lvv,  to word2
        
        esp_rom_printf("%08lx %08lx %08lx  new=%ld\n", word0, word1, word2, new);
        //write words to flash
        if (word0==0         )  bootloader_flash_write(count_addr+bytes-4,&word0,4,0);
        if (word1!=0x10000000)  bootloader_flash_write(count_addr+bytes  ,&word1,4,0); //stupid compare to shut up compiler
        if (word2!=UINT32_MAX)  bootloader_flash_write(count_addr+bytes+4,&word2,4,0);
    }

    return temp_boot;
}
