set(srcs
    "src/lcm_bootloader_utility.c"
    )

if(BOOTLOADER_BUILD)
    set(include_dirs    "${IDF_PATH}/components/bootloader_support/include" 
                        "include_bootloader"
                        "${IDF_PATH}/components/bootloader_support/bootloader_flash/include"
                        "${IDF_PATH}/components/bootloader_support/private_include")
    set(priv_requires micro-ecc spi_flash efuse esp_app_format)
    list(APPEND priv_requires hal)
else()
    set(include_dirs    "${IDF_PATH}/components/bootloader_support/include" 
                        "include_bootloader"
                        "${IDF_PATH}/components/bootloader_support/bootloader_flash/include")
    set(priv_include_dirs "${IDF_PATH}/components/bootloader_support/private_include")
    # heap is required for `heap_memory_layout.h` header
    set(priv_requires spi_flash mbedtls efuse heap esp_app_format)
endif()


set(requires soc) #unfortunately the header directly uses SOC registers

idf_component_register(SRCS "${srcs}"
                    INCLUDE_DIRS "${include_dirs}"
                    PRIV_INCLUDE_DIRS "${priv_include_dirs}"
                    REQUIRES "${requires}"
                    PRIV_REQUIRES "${priv_requires}")

if(CONFIG_SECURE_SIGNED_APPS AND (CONFIG_SECURE_BOOT_V1_ENABLED OR CONFIG_SECURE_SIGNED_APPS_ECDSA_SCHEME))
    if(BOOTLOADER_BUILD)
        # Whether CONFIG_SECURE_BOOT_BUILD_SIGNED_BINARIES or not, we need verification key to embed
        # in the library.
        if(CONFIG_SECURE_BOOT_BUILD_SIGNED_BINARIES)
            # We generate the key from the signing key. The signing key is passed from the main project.
            get_filename_component(secure_boot_signing_key
                "${SECURE_BOOT_SIGNING_KEY}"
                ABSOLUTE BASE_DIR "${project_dir}")
            get_filename_component(secure_boot_verification_key
                "signature_verification_key.bin"
                ABSOLUTE BASE_DIR "${CMAKE_CURRENT_BINARY_DIR}")
            add_custom_command(OUTPUT "${secure_boot_verification_key}"
                COMMAND ${ESPSECUREPY}
                extract_public_key --keyfile "${secure_boot_signing_key}"
                "${secure_boot_verification_key}"
                DEPENDS ${secure_boot_signing_key}
                VERBATIM)
        else()
            # We expect to 'inherit' the verification key passed from main project.
            get_filename_component(secure_boot_verification_key
                ${SECURE_BOOT_VERIFICATION_KEY}
                ABSOLUTE BASE_DIR "${project_dir}")
        endif()
    else()  # normal app build
        idf_build_get_property(project_dir PROJECT_DIR)

        if(CONFIG_SECURE_BOOT_VERIFICATION_KEY)
            # verification-only build supplies verification key
            set(secure_boot_verification_key ${CONFIG_SECURE_BOOT_VERIFICATION_KEY})
            get_filename_component(secure_boot_verification_key
                ${secure_boot_verification_key}
                ABSOLUTE BASE_DIR "${project_dir}")
        else()
            # sign at build time, extracts key from signing key
            set(secure_boot_verification_key "${CMAKE_BINARY_DIR}/signature_verification_key.bin")
            get_filename_component(secure_boot_signing_key
                ${CONFIG_SECURE_BOOT_SIGNING_KEY}
                ABSOLUTE BASE_DIR "${project_dir}")

            add_custom_command(OUTPUT "${secure_boot_verification_key}"
                COMMAND ${ESPSECUREPY}
                extract_public_key --keyfile "${secure_boot_signing_key}"
                "${secure_boot_verification_key}"
                WORKING_DIRECTORY ${project_dir}
                DEPENDS ${secure_boot_signing_key}
                VERBATIM)
        endif()
    endif()

    # Embed the verification key in the binary (app & bootloader)
    #
    target_add_binary_data(${COMPONENT_LIB} "${secure_boot_verification_key}" "BINARY"
        RENAME_TO signature_verification_key_bin)
    set_property(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        APPEND PROPERTY ADDITIONAL_MAKE_CLEAN_FILES
        "${secure_boot_verification_key}")
endif()

if(BOOTLOADER_BUILD)
    target_link_libraries(${COMPONENT_LIB} INTERFACE "-u abort")
endif()
