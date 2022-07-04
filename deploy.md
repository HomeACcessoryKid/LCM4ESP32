(c) 2018-2022 HomeAccessoryKid

### Instructions for end users:
TBD

### Instructions if you own the private key:
```
cd LCM4ESP32
```
- initial steps to be expanded

#### These are the steps if not introducing a new key pair
- create/update the file versions1/latest-pre-release without new-line and setup 0.0.3 version folder
```
echo 0.0.3 > version.txt
mkdir versions1/0.0.3v
echo -n 0.0.3 > versions1/0.0.3v/latest-pre-release
cp versions1/certs.sector versions1/certs.sector.sig versions1/0.0.3v
cp versions1/public*key*   versions1/0.0.3v
```
- create the ota-main program
```
export -n EXTRA_CFLAGS
idf.py fullclean ; rm -rf /mnt/main
idf.py app
mv build/LCM4ESP32.bin versions1/0.0.3v/otamain.bin
```
- create the ota-boot programs
```
EXTRA_CFLAGS=-DOTABOOT
export EXTRA_CFLAGS
idf.py fullclean ; rm -rf /mnt/main
idf.py app
mv build/LCM4ESP32.bin versions1/0.0.3v/otaboot.bin

EXTRA_CFLAGS="-DOTABOOT -DOTABETA"
export EXTRA_CFLAGS
idf.py fullclean ; rm -rf /mnt/main
idf.py app
cp build/LCM4ESP32.bin versions1/0.0.3v/otabootbeta.bin
```
- remove the older version files
#
- update Changelog
- if you can sign the binaries locally, do so, else follow later steps
- test otaboot for basic behaviour
- commit and sync submodules
- commit and sync this as version 0.0.3  
- set up a new github release 0.0.3 as a pre-release using the just commited master...  
- upload the certs and binaries to the pre-release assets on github  
#
- erase the flash and upload the privatekey
```
esptool.py -p /dev/cu.usbserial-* --baud 230400 erase_flash 
esptool.py -p /dev/cu.usbserial-* --baud 230400 write_flash 0xf9000 versions1-privatekey.der
```
- upload the ota-boot BETA program to the device that contains the private key
```
make flash OTAVERSION=0.0.3 OTABETA=1
```
- power cycle to prevent the bug for software reset after flash  
- setup wifi and select the ota-demo repo without pre-release checkbox  
- create the 2 signature files next to the bin file and upload to github one by one  
- verify the hashes on the computer  
```
openssl sha384 versions1/0.0.3v/otamain.bin
xxd versions1/0.0.3v/otamain.bin.sig
```

- upload the file versions1/0.0.3v/latest-pre-release to the 'latest release' assets on github










EXTRA_CFLAGS=-DOTABOOT
export EXTRA_CFLAGS
idf.py fullclean
idf.py all

export -n EXTRA_CFLAGS
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




~/bin/ecc_signer otaboot.bin ../secp384r1prv.der ../secp384r1pub.der
printf "%08x" `cat otaboot.bin | wc -c`| xxd -r -p > len
cat hash len sign > otaboot.bin.sig
~/bin/ecc_signer otamain.bin ../secp384r1prv.der ../secp384r1pub.der
printf "%08x" `cat otamain.bin | wc -c`| xxd -r -p > len
cat hash len sign > otamain.bin.sig
rm hash len sign
