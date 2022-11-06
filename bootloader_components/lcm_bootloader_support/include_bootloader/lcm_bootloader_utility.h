/*
 * SPDX-FileCopyrightText: 2018-2021 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#pragma once

#include "bootloader_config.h"
#include "esp_image_format.h"
#include "bootloader_config.h"


/**
 * @brief count the interrupted resets
 *
 * write to flash early_counter
 * wait (while power reset might happen again)
 * count interupted resets
 * write to flash late_counter
 *
 * @param[in] bs Bootloader state structure.
 * @return       Returns the count 
 */
uint32_t lcm_bootloader_count(const bootloader_state_t *bs);

/**
 * @brief store count in the RTC memory and collect temp_boot from it
 *
 * the uint8_t custom[0] is used to store count
 * the uint8_t custom[1] is used to store temp_boot
 * custom[1] is cleared after reading
 * CRC value is updated
 *
 * @param[in] count Number of resets
 * @return          Returns if temp_boot requested 
 */
bool lcm_bootloader_rtc(uint32_t count);

