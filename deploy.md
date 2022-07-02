EXTRA_CFLAGS=-DOTABOOT
export EXTRA_CFLAGS
idf.py fullclean
idf.py all

EXTRA_CFLAGS=
export EXTRA_CFLAGS
idf.py fullclean
idf.py all

works, but painfull


idf.py reconfigure re-runs CMake even if it doesn’t seem to need re-running.
This isn’t necessary during normal usage, but can be useful after adding/removing files from the source tree,
or when modifying CMake cache variables.
For example, `idf.py -DNAME='VALUE' reconfigure` can be used to set variable NAME in CMake cache to value VALUE


to flash use this command
    esptool.py --chip esp32 --port /dev/cu.usbserial* --baud 460800 --before default_reset --after hard_reset \
    write_flash -z --flash_mode dio --flash_freq 40m --flash_size detect \
    0x8000 build/partition_table/partition-table.bin 0x20c000 certs.sector 0x209000 build/ota_data_initial.bin 0x300000 build/LCM4ESP32.bin

    esptool.py --chip esp32 --port /dev/cu.usbserial* --baud 460800 --before default_reset --after hard_reset \
    write_flash -z --flash_mode dio --flash_freq 40m --flash_size detect \
    0x209000 build/ota_data_initial.bin 0x300000 build/LCM4ESP32.bin
    
    esptool.py --chip esp32 --port /dev/cu.usbserial* --baud 460800 --before default_reset --after hard_reset \
    write_flash -z --flash_mode dio --flash_freq 40m --flash_size detect \
    0x300000 build/LCM4ESP32.bin


get vi in the container
apt-get update
apt-get install vim

depending less of mapped container volume for much faster compilation:
idf.py fullclean (only once)
ln -s /mnt build/esp-idf
idf.py fullclean
rm -rd /mnt/*

idf.py -B <dir> allows overriding the build directory from the default build subdirectory of the project directory