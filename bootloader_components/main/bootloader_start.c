/*
 * SPDX-FileCopyrightText: 2015-2021 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdbool.h>
#include "sdkconfig.h"
#include "esp_log.h"
#include "bootloader_init.h"
#include "bootloader_utility.h"
#include "lcm_bootloader_utility.h"
#include "bootloader_common.h"

// Select the number of boot partition
static int select_partition_number(bootloader_state_t *bs) {
    // 1. Load partition table
    if (!bootloader_utility_load_partition_table(bs)) {
        ESP_LOGE("BL4LCM32", "load partition table error!");
        return INVALID_INDEX;
    }

    // 2. Select the number of boot partition
    return bootloader_utility_get_selected_boot_partition(bs);
}

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
    // 2. Select the number of boot partition
    bootloader_state_t bs = {0};
    int boot_index = select_partition_number(&bs);
    if (boot_index == INVALID_INDEX) {
        bootloader_reset();
    }

    // 2. Count the hardware starts
    // it uses bootloader_state to get the address of the inactive half of the ota_data from partition table
    uint32_t count=lcm_bootloader_count(&bs);    
    
    // 3. store count in RTC for LCM to act on it and collect the temp_boot flag
    bool temp_boot=lcm_bootloader_rtc(count);
    ESP_LOGI("BL4LCM32","count=%d temp_boot=%d",count,temp_boot);
    
    // 4. based on count and temp_boot, set boot_index to 0 or 1
    #define COUNT4USER 4 //powercycle count that will not yet trigger LCM
    boot_index=(temp_boot)?1:(count>COUNT4USER)?1:0;

    // 5. Load the app image for booting
    bootloader_utility_load_boot_image(&bs, boot_index);
}

// Return global reent struct if any newlib functions are linked to bootloader
struct _reent *__getreent(void)
{
    return _GLOBAL_REENT;
}
