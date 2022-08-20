/*
 * SPDX-FileCopyrightText: 2015-2021 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <sys/param.h>
#include "esp_attr.h"
#include <stdbool.h>
#include "sdkconfig.h"
#include "esp_log.h"
#include "bootloader_init.h"
#include "bootloader_utility.h"
#include "bootloader_common.h"


// no header file for these ones, copied local functions below
static void load_image(const esp_image_metadata_t *image_data);
static esp_partition_pos_t index_to_partition(const bootloader_state_t *bs, int index);
static bool check_anti_rollback(const esp_partition_pos_t *partition);
static bool try_load_partition(const esp_partition_pos_t *partition, esp_image_metadata_t *data);


// first it will check if there is RTC info and boot from that, else it will load ota[0], ota[1] or factory
void bootloader_LCM_load_boot_image(const bootloader_state_t *bs, int start_index) {
    ESP_LOGI("BL4LCM32", "This code is called AFTER bootloader initialization: idx=0x%x",start_index);

    int unused = start_index;
    esp_partition_pos_t part;
    esp_image_metadata_t image_data;
    // void bootloader_utility_load_boot_image_from_deep_sleep(void) { //code below partly based on this
    esp_partition_pos_t *partition = bootloader_common_get_rtc_retain_mem_partition();
    if (partition != NULL) {
        bootloader_common_update_rtc_retain_mem(NULL, true);
        if (check_anti_rollback(partition) && try_load_partition(partition, &image_data)) {
            load_image(&image_data);
        }
    }
    ESP_LOGI("BL4LCM32", "RTC booting is not valid. Try to load an app as usual");
    // void bootloader_utility_load_boot_image(const bootloader_state_t *bs, int start_index) { //code below based on this

    //always try ota[0] and then ota[1] and if that failed then factory
    int index[3]={0,1,FACTORY_INDEX};
    for (int idx = 0; idx < 3; idx++) {
        part = index_to_partition(bs, index[idx]);
        if (part.size == 0) {
            continue;
        }
        ESP_LOGI("BL4LCM32", "Trying partition index %d offset 0x%x size 0x%x", index[idx], part.offset, part.size);
        if (check_anti_rollback(&part) && try_load_partition(&part, &image_data)) {
//             set_actual_ota_seq(bs, index);
            load_image(&image_data);
        }
//         log_invalid_app_partition(index);
        ESP_LOGE("BL4LCM32", "App partition slot %d is not bootable", index[idx]);
    }

    if (check_anti_rollback(&bs->test) && try_load_partition(&bs->test, &image_data)) {
        ESP_LOGW("BL4LCM32", "Falling back to test app as only bootable partition");
        load_image(&image_data);
    }

    ESP_LOGE("BL4LCM32", "No bootable app partitions in the partition table");
    bzero(&image_data, sizeof(esp_image_metadata_t));
    bootloader_reset();
}



// ALL BELOW IS COPIED from bootloader_utility.c where it is a local definition and no way to access
// Keep synchronized manually with updating SDKs

#include "esp_rom_sys.h"
#include "esp_rom_uart.h"
#include "sdkconfig.h"
#if CONFIG_IDF_TARGET_ESP32
#include "soc/dport_reg.h"
#include "esp32/rom/cache.h"
#include "esp32/rom/spi_flash.h"
#include "esp32/rom/secure_boot.h"
#elif CONFIG_IDF_TARGET_ESP32S2
#include "esp32s2/rom/cache.h"
#include "esp32s2/rom/spi_flash.h"
#include "esp32s2/rom/secure_boot.h"
#include "soc/extmem_reg.h"
#include "soc/cache_memory.h"
#elif CONFIG_IDF_TARGET_ESP32S3
#include "esp32s3/rom/cache.h"
#include "esp32s3/rom/spi_flash.h"
#include "esp32s3/rom/secure_boot.h"
#include "soc/extmem_reg.h"
#include "soc/cache_memory.h"
#elif CONFIG_IDF_TARGET_ESP32C3
#include "esp32c3/rom/cache.h"
#include "esp32c3/rom/efuse.h"
#include "esp32c3/rom/ets_sys.h"
#include "esp32c3/rom/spi_flash.h"
#include "esp32c3/rom/crc.h"
#include "esp32c3/rom/uart.h"
#include "esp32c3/rom/gpio.h"
#include "esp32c3/rom/secure_boot.h"
#include "soc/extmem_reg.h"
#include "soc/cache_memory.h"
#elif CONFIG_IDF_TARGET_ESP32H2
#include "esp32h2/rom/cache.h"
#include "esp32h2/rom/efuse.h"
#include "esp32h2/rom/ets_sys.h"
#include "esp32h2/rom/spi_flash.h"
#include "esp32h2/rom/crc.h"
#include "esp32h2/rom/uart.h"
#include "esp32h2/rom/gpio.h"
#include "esp32h2/rom/secure_boot.h"
#include "soc/extmem_reg.h"
#include "soc/cache_memory.h"
#else // CONFIG_IDF_TARGET_*
#error "Unsupported IDF_TARGET"
#endif

#include "soc/soc.h"
#include "soc/cpu.h"
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
#include "bootloader_utility.h"
#include "bootloader_sha.h"
#include "bootloader_console.h"
#include "bootloader_soc.h"
#include "esp_efuse.h"
#include "esp_fault.h"


/* Reduce literal size for some generic string literals */
#define MAP_ERR_MSG "Image contains multiple %s segments. Only the last one will be mapped."

static const char *TAG = "boot";
static void unpack_load_app(const esp_image_metadata_t *data);
static void set_cache_and_start_app(uint32_t drom_addr,
                                    uint32_t drom_load_addr,
                                    uint32_t drom_size,
                                    uint32_t irom_addr,
                                    uint32_t irom_load_addr,
                                    uint32_t irom_size,
                                    uint32_t entry_addr);


// Copy loaded segments to RAM, set up caches for mapped segments, and start application.
static void load_image(const esp_image_metadata_t *image_data)
{
    /**
     * Rough steps for a first boot, when encryption and secure boot are both disabled:
     *   1) Generate secure boot key and write to EFUSE.
     *   2) Write plaintext digest based on plaintext bootloader
     *   3) Generate flash encryption key and write to EFUSE.
     *   4) Encrypt flash in-place including bootloader, then digest,
     *      then app partitions and other encrypted partitions
     *   5) Burn EFUSE to enable flash encryption (FLASH_CRYPT_CNT)
     *   6) Burn EFUSE to enable secure boot (ABS_DONE_0)
     *
     * If power failure happens during Step 1, probably the next boot will continue from Step 2.
     * There is some small chance that EFUSEs will be part-way through being written so will be
     * somehow corrupted here. Thankfully this window of time is very small, but if that's the
     * case, one has to use the espefuse tool to manually set the remaining bits and enable R/W
     * protection. Once the relevant EFUSE bits are set and R/W protected, Step 1 will be skipped
     * successfully on further reboots.
     *
     * If power failure happens during Step 2, Step 1 will be skipped and Step 2 repeated:
     * the digest will get re-written on the next boot.
     *
     * If power failure happens during Step 3, it's possible that EFUSE was partially written
     * with the generated flash encryption key, though the time window for that would again
     * be very small. On reboot, Step 1 will be skipped and Step 2 repeated, though, Step 3
     * may fail due to the above mentioned reason, in which case, one has to use the espefuse
     * tool to manually set the remaining bits and enable R/W protection. Once the relevant EFUSE
     * bits are set and R/W protected, Step 3 will be skipped successfully on further reboots.
     *
     * If power failure happens after start of 4 and before end of 5, the next boot will fail
     * (bootloader header is encrypted and flash encryption isn't enabled yet, so it looks like
     * noise to the ROM bootloader). The check in the ROM is pretty basic so if the first byte of
     * ciphertext happens to be the magic byte E9 then it may try to boot, but it will definitely
     * crash (no chance that the remaining ciphertext will look like a valid bootloader image).
     * Only solution is to reflash with all plaintext and the whole process starts again: skips
     * Step 1, repeats Step 2, skips Step 3, etc.
     *
     * If power failure happens after 5 but before 6, the device will reboot with flash
     * encryption on and will regenerate an encrypted digest in Step 2. This should still
     * be valid as the input data for the digest is read via flash cache (so will be decrypted)
     * and the code in secure_boot_generate() tells bootloader_flash_write() to encrypt the data
     * on write if flash encryption is enabled. Steps 3 - 5 are skipped (encryption already on),
     * then Step 6 enables secure boot.
     */

#if defined(CONFIG_SECURE_BOOT) || defined(CONFIG_SECURE_FLASH_ENC_ENABLED)
    esp_err_t err;
#endif

#ifdef CONFIG_SECURE_BOOT_V2_ENABLED
    err = esp_secure_boot_v2_permanently_enable(image_data);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Secure Boot v2 failed (%d)", err);
        return;
    }
#endif

#ifdef CONFIG_SECURE_BOOT_V1_ENABLED
    /* Steps 1 & 2 (see above for full description):
     *   1) Generate secure boot EFUSE key
     *   2) Compute digest of plaintext bootloader
     */
    err = esp_secure_boot_generate_digest();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Bootloader digest generation for secure boot failed (%d).", err);
        return;
    }
#endif

#ifdef CONFIG_SECURE_FLASH_ENC_ENABLED
    /* Steps 3, 4 & 5 (see above for full description):
     *   3) Generate flash encryption EFUSE key
     *   4) Encrypt flash contents
     *   5) Burn EFUSE to enable flash encryption
     */
    ESP_LOGI(TAG, "Checking flash encryption...");
    bool flash_encryption_enabled = esp_flash_encryption_enabled();
    err = esp_flash_encrypt_check_and_update();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Flash encryption check failed (%d).", err);
        return;
    }
#endif

#ifdef CONFIG_SECURE_BOOT_V1_ENABLED
    /* Step 6 (see above for full description):
     *   6) Burn EFUSE to enable secure boot
     */
    ESP_LOGI(TAG, "Checking secure boot...");
    err = esp_secure_boot_permanently_enable();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "FAILED TO ENABLE SECURE BOOT (%d).", err);
        /* Panic here as secure boot is not properly enabled
           due to one of the reasons in above function
        */
        abort();
    }
#endif

#ifdef CONFIG_SECURE_FLASH_ENC_ENABLED
    if (!flash_encryption_enabled && esp_flash_encryption_enabled()) {
        /* Flash encryption was just enabled for the first time,
           so issue a system reset to ensure flash encryption
           cache resets properly */
        ESP_LOGI(TAG, "Resetting with flash encryption enabled...");
        esp_rom_uart_tx_wait_idle(0);
        bootloader_reset();
    }
#endif

    ESP_LOGI(TAG, "Disabling RNG early entropy source...");
    bootloader_random_disable();

    /* Disable glitch reset after all the security checks are completed.
     * Glitch detection can be falsely triggered by EMI interference (high RF TX power, etc)
     * and to avoid such false alarms, disable it.
     */
    bootloader_ana_clock_glitch_reset_config(false);

    // copy loaded segments to RAM, set up caches for mapped segments, and start application
    unpack_load_app(image_data);
}

/* Given a partition index, return the partition position data from the bootloader_state_t structure */
static esp_partition_pos_t index_to_partition(const bootloader_state_t *bs, int index)
{
    if (index == FACTORY_INDEX) {
        return bs->factory;
    }

    if (index == TEST_APP_INDEX) {
        return bs->test;
    }

    if (index >= 0 && index < MAX_OTA_SLOTS && index < (int)bs->app_count) {
        return bs->ota[index];
    }

    esp_partition_pos_t invalid = { 0 };
    return invalid;
}

static bool check_anti_rollback(const esp_partition_pos_t *partition)
{
#ifdef CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK
    esp_app_desc_t app_desc = {};
    esp_err_t err = bootloader_common_get_partition_description(partition, &app_desc);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to get partition description %d", err);
        return false;
    }
    bool sec_ver = esp_efuse_check_secure_version(app_desc.secure_version);
    /* Anti FI check */
    ESP_FAULT_ASSERT(sec_ver == esp_efuse_check_secure_version(app_desc.secure_version));
    return sec_ver;
#else
    return true;
#endif
}

/* Return true if a partition has a valid app image that was successfully loaded */
static bool try_load_partition(const esp_partition_pos_t *partition, esp_image_metadata_t *data)
{
    if (partition->size == 0) {
        ESP_LOGD(TAG, "Can't boot from zero-length partition");
        return false;
    }
#ifdef BOOTLOADER_BUILD
    esp_err_t err = bootloader_load_image(partition, data);
ESP_LOGI("IL","2");
//     if (bootloader_load_image(partition, data) == ESP_OK) {
    if (err==ESP_OK) {
ESP_LOGI("IL","3");
        ESP_LOGI(TAG, "Loaded app from partition at offset 0x%x",
                 partition->offset);
        return true;
    }
#endif

    return false;
}

static void unpack_load_app(const esp_image_metadata_t *data)
{
    uint32_t drom_addr = 0;
    uint32_t drom_load_addr = 0;
    uint32_t drom_size = 0;
    uint32_t irom_addr = 0;
    uint32_t irom_load_addr = 0;
    uint32_t irom_size = 0;

    // Find DROM & IROM addresses, to configure cache mappings
    for (int i = 0; i < data->image.segment_count; i++) {
        const esp_image_segment_header_t *header = &data->segments[i];
        if (header->load_addr >= SOC_DROM_LOW && header->load_addr < SOC_DROM_HIGH) {
            if (drom_addr != 0) {
                ESP_LOGE(TAG, MAP_ERR_MSG, "DROM");
            } else {
                ESP_LOGD(TAG, "Mapping segment %d as %s", i, "DROM");
            }
            drom_addr = data->segment_data[i];
            drom_load_addr = header->load_addr;
            drom_size = header->data_len;
        }
        if (header->load_addr >= SOC_IROM_LOW && header->load_addr < SOC_IROM_HIGH) {
            if (irom_addr != 0) {
                ESP_LOGE(TAG, MAP_ERR_MSG, "IROM");
            } else {
                ESP_LOGD(TAG, "Mapping segment %d as %s", i, "IROM");
            }
            irom_addr = data->segment_data[i];
            irom_load_addr = header->load_addr;
            irom_size = header->data_len;
        }
    }

    ESP_LOGD(TAG, "calling set_cache_and_start_app");
    set_cache_and_start_app(drom_addr,
                            drom_load_addr,
                            drom_size,
                            irom_addr,
                            irom_load_addr,
                            irom_size,
                            data->image.entry_addr);
}

static void set_cache_and_start_app(
    uint32_t drom_addr,
    uint32_t drom_load_addr,
    uint32_t drom_size,
    uint32_t irom_addr,
    uint32_t irom_load_addr,
    uint32_t irom_size,
    uint32_t entry_addr)
{
    int rc __attribute__((unused));

    ESP_LOGD(TAG, "configure drom and irom and start");
#if CONFIG_IDF_TARGET_ESP32
    Cache_Read_Disable(0);
    Cache_Flush(0);
#elif CONFIG_IDF_TARGET_ESP32S2
    uint32_t autoload = Cache_Suspend_ICache();
    Cache_Invalidate_ICache_All();
#elif CONFIG_IDF_TARGET_ESP32S3
    uint32_t autoload = Cache_Suspend_DCache();
    Cache_Invalidate_DCache_All();
#elif CONFIG_IDF_TARGET_ESP32C3
    uint32_t autoload = Cache_Suspend_ICache();
    Cache_Invalidate_ICache_All();
#elif CONFIG_IDF_TARGET_ESP32H2
    uint32_t autoload = Cache_Suspend_ICache();
    Cache_Invalidate_ICache_All();
#endif

    /* Clear the MMU entries that are already set up,
     * so the new app only has the mappings it creates.
     */
#if CONFIG_IDF_TARGET_ESP32
    for (int i = 0; i < DPORT_FLASH_MMU_TABLE_SIZE; i++) {
        DPORT_PRO_FLASH_MMU_TABLE[i] = DPORT_FLASH_MMU_TABLE_INVALID_VAL;
    }
#else
    for (size_t i = 0; i < FLASH_MMU_TABLE_SIZE; i++) {
        FLASH_MMU_TABLE[i] = MMU_TABLE_INVALID_VAL;
    }
#endif
    uint32_t drom_load_addr_aligned = drom_load_addr & MMU_FLASH_MASK;
    uint32_t drom_addr_aligned = drom_addr & MMU_FLASH_MASK;
    uint32_t drom_page_count = bootloader_cache_pages_to_map(drom_size, drom_load_addr);
    ESP_LOGV(TAG, "d mmu set paddr=%08x vaddr=%08x size=%d n=%d",
             drom_addr_aligned, drom_load_addr_aligned, drom_size, drom_page_count);
#if CONFIG_IDF_TARGET_ESP32
    rc = cache_flash_mmu_set(0, 0, drom_load_addr_aligned, drom_addr_aligned, 64, drom_page_count);
#elif CONFIG_IDF_TARGET_ESP32S2
    rc = Cache_Ibus_MMU_Set(MMU_ACCESS_FLASH, drom_load_addr_aligned, drom_addr_aligned, 64, drom_page_count, 0);
#elif CONFIG_IDF_TARGET_ESP32S3
    rc = Cache_Dbus_MMU_Set(MMU_ACCESS_FLASH, drom_load_addr_aligned, drom_addr_aligned, 64, drom_page_count, 0);
#elif CONFIG_IDF_TARGET_ESP32C3
    rc = Cache_Dbus_MMU_Set(MMU_ACCESS_FLASH, drom_load_addr_aligned, drom_addr_aligned, 64, drom_page_count, 0);
#elif CONFIG_IDF_TARGET_ESP32H2
    rc = Cache_Dbus_MMU_Set(MMU_ACCESS_FLASH, drom_load_addr_aligned, drom_addr_aligned, 64, drom_page_count, 0);
#endif
    ESP_LOGV(TAG, "rc=%d", rc);
#if CONFIG_IDF_TARGET_ESP32
    rc = cache_flash_mmu_set(1, 0, drom_load_addr_aligned, drom_addr_aligned, 64, drom_page_count);
    ESP_LOGV(TAG, "rc=%d", rc);
#endif
    uint32_t irom_load_addr_aligned = irom_load_addr & MMU_FLASH_MASK;
    uint32_t irom_addr_aligned = irom_addr & MMU_FLASH_MASK;
    uint32_t irom_page_count = bootloader_cache_pages_to_map(irom_size, irom_load_addr);
    ESP_LOGV(TAG, "i mmu set paddr=%08x vaddr=%08x size=%d n=%d",
             irom_addr_aligned, irom_load_addr_aligned, irom_size, irom_page_count);
#if CONFIG_IDF_TARGET_ESP32
    rc = cache_flash_mmu_set(0, 0, irom_load_addr_aligned, irom_addr_aligned, 64, irom_page_count);
#elif CONFIG_IDF_TARGET_ESP32S2
    uint32_t iram1_used = 0;
    if (irom_load_addr + irom_size > IRAM1_ADDRESS_LOW) {
        iram1_used = 1;
    }
    if (iram1_used) {
        rc = Cache_Ibus_MMU_Set(MMU_ACCESS_FLASH, IRAM0_ADDRESS_LOW, 0, 64, 64, 1);
        rc = Cache_Ibus_MMU_Set(MMU_ACCESS_FLASH, IRAM1_ADDRESS_LOW, 0, 64, 64, 1);
        REG_CLR_BIT(EXTMEM_PRO_ICACHE_CTRL1_REG, EXTMEM_PRO_ICACHE_MASK_IRAM1);
    }
    rc = Cache_Ibus_MMU_Set(MMU_ACCESS_FLASH, irom_load_addr_aligned, irom_addr_aligned, 64, irom_page_count, 0);
#elif CONFIG_IDF_TARGET_ESP32S3
    rc = Cache_Ibus_MMU_Set(MMU_ACCESS_FLASH, irom_load_addr_aligned, irom_addr_aligned, 64, irom_page_count, 0);
#elif CONFIG_IDF_TARGET_ESP32C3
    rc = Cache_Ibus_MMU_Set(MMU_ACCESS_FLASH, irom_load_addr_aligned, irom_addr_aligned, 64, irom_page_count, 0);
#elif CONFIG_IDF_TARGET_ESP32H2
    rc = Cache_Ibus_MMU_Set(MMU_ACCESS_FLASH, irom_load_addr_aligned, irom_addr_aligned, 64, irom_page_count, 0);
#endif
    ESP_LOGV(TAG, "rc=%d", rc);
#if CONFIG_IDF_TARGET_ESP32
    rc = cache_flash_mmu_set(1, 0, irom_load_addr_aligned, irom_addr_aligned, 64, irom_page_count);
    ESP_LOGV(TAG, "rc=%d", rc);
    DPORT_REG_CLR_BIT( DPORT_PRO_CACHE_CTRL1_REG,
                       (DPORT_PRO_CACHE_MASK_IRAM0) | (DPORT_PRO_CACHE_MASK_IRAM1 & 0) |
                       (DPORT_PRO_CACHE_MASK_IROM0 & 0) | DPORT_PRO_CACHE_MASK_DROM0 |
                       DPORT_PRO_CACHE_MASK_DRAM1 );
    DPORT_REG_CLR_BIT( DPORT_APP_CACHE_CTRL1_REG,
                       (DPORT_APP_CACHE_MASK_IRAM0) | (DPORT_APP_CACHE_MASK_IRAM1 & 0) |
                       (DPORT_APP_CACHE_MASK_IROM0 & 0) | DPORT_APP_CACHE_MASK_DROM0 |
                       DPORT_APP_CACHE_MASK_DRAM1 );
#elif CONFIG_IDF_TARGET_ESP32S2
    REG_CLR_BIT( EXTMEM_PRO_ICACHE_CTRL1_REG, (EXTMEM_PRO_ICACHE_MASK_IRAM0) | (EXTMEM_PRO_ICACHE_MASK_IRAM1 & 0) | EXTMEM_PRO_ICACHE_MASK_DROM0 );
#elif CONFIG_IDF_TARGET_ESP32S3
    REG_CLR_BIT(EXTMEM_DCACHE_CTRL1_REG, EXTMEM_DCACHE_SHUT_CORE0_BUS);
#if !CONFIG_FREERTOS_UNICORE
    REG_CLR_BIT(EXTMEM_DCACHE_CTRL1_REG, EXTMEM_DCACHE_SHUT_CORE1_BUS);
#endif
#elif CONFIG_IDF_TARGET_ESP32C3
    REG_CLR_BIT(EXTMEM_ICACHE_CTRL1_REG, EXTMEM_ICACHE_SHUT_IBUS);
    REG_CLR_BIT(EXTMEM_ICACHE_CTRL1_REG, EXTMEM_ICACHE_SHUT_DBUS);
#elif CONFIG_IDF_TARGET_ESP32H2
    REG_CLR_BIT(EXTMEM_ICACHE_CTRL1_REG, EXTMEM_ICACHE_SHUT_IBUS);
    REG_CLR_BIT(EXTMEM_ICACHE_CTRL1_REG, EXTMEM_ICACHE_SHUT_DBUS);
#endif
#if CONFIG_IDF_TARGET_ESP32
    Cache_Read_Enable(0);
#elif CONFIG_IDF_TARGET_ESP32S2
    Cache_Resume_ICache(autoload);
#elif CONFIG_IDF_TARGET_ESP32S3
    Cache_Resume_DCache(autoload);
#elif CONFIG_IDF_TARGET_ESP32C3
    Cache_Resume_ICache(autoload);
#elif CONFIG_IDF_TARGET_ESP32H2
    Cache_Resume_ICache(autoload);
#endif
    // Application will need to do Cache_Flush(1) and Cache_Read_Enable(1)

    ESP_LOGD(TAG, "start: 0x%08x", entry_addr);
    bootloader_atexit();
    typedef void (*entry_t)(void) __attribute__((noreturn));
    entry_t entry = ((entry_t) entry_addr);

    // TODO: we have used quite a bit of stack at this point.
    // use "movsp" instruction to reset stack back to where ROM stack starts.
    (*entry)();
}


// END OF COPIED SECTION

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

    // 3. Load the app image for booting
    bootloader_LCM_load_boot_image(&bs, boot_index);
}

// Return global reent struct if any newlib functions are linked to bootloader
struct _reent *__getreent(void)
{
    return _GLOBAL_REENT;
}
