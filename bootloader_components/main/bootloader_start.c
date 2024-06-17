/*
 * SPDX-FileCopyrightText: 2015-2021 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * (c) 2018-2024 HomeAccessoryKid
 */
#include <stdbool.h>
#include "sdkconfig.h"
#include "esp_log.h"
#include "bootloader_init.h"
#include "bootloader_utility.h"
#include "lcm_bootloader_utility.h"
#include "bootloader_common.h"

/*
 * We arrive here after the ROM bootloader finished loading this second stage bootloader from flash.
 * The hardware is mostly uninitialized, flash cache is down and the app CPU is in reset.
 * We do have a stack, so we can do the initialization in C.
 */
void __attribute__((noreturn)) call_start_cpu0(void) {
    // 1. Hardware initialization
    if (bootloader_init() != ESP_OK) {
        bootloader_reset();
    }
    
    // 2. Load partition table
    bootloader_state_t bs = {0};
    if (!bootloader_utility_load_partition_table(&bs)) {
        esp_rom_printf("BL4LCM32: load partition table error!\n");
        bootloader_reset();
    }

    // 3. Count the hardware starts
    // it uses bootloader_state to get the address of the inactive half of the ota_data from partition table
    uint32_t count=lcm_bootloader_count(&bs);    
    
    // 4. store count in RTC for LCM to act on it and collect the temp_boot flag
    bool temp_boot=lcm_bootloader_rtc(count);
    esp_rom_printf("BL4LCM32: count=%d temp_boot=%d\n",count,temp_boot);
    
    // 5. based on count and temp_boot, set boot_index to 0 or 1
    #define COUNT4USER 4 //powercycle count that will not yet trigger LCM
    int boot_index=(temp_boot)?1:(count>COUNT4USER)?1:0;

    // 6. Load the app image for booting
    bootloader_utility_load_boot_image(&bs, boot_index);
}

// Return global reent struct if any newlib functions are linked to bootloader
struct _reent *__getreent(void)
{
    return _GLOBAL_REENT;
}
