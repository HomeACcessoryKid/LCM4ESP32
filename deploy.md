(c) 2018-2022 HomeAccessoryKid

### Instructions for end users:

You must have compiled your code in a very normal way, without OTA etc. just basic binary  
BUT you must NOT set the wifi in your code.  
(That means manipulating the example_connect if you are still using that!)  
You must sign that binary with the below two commands
```
openssl sha384 -binary -out build/main.bin.sig build/main.bin
printf "%08x" `cat build/main.bin | wc -c`| xxd -r -p >>build/main.bin.sig
```
Then you create a release on GitHub.com with a version number x.y.z and add these two files to it.

#### Getting the ESP ready

You will start with erasing the flash complete
```
esptool.py --port /dev/cu.usbserial* --baud 460800 erase_flash
```
Then you must flash the Bootloader, PartitionTable and otaboot.bin
```
cd to-where-you-downloaded-the-below-three-files
esptool.py --chip esp32 --port /dev/cu.usbserial* --baud 460800 --before default_reset --after hard_reset \
write_flash -z --flash_mode dio --flash_freq 40m --flash_size detect \
0x01000 bootloader.bin \
0x08000 partition-table.bin \
0xf0000 otaboot.bin
```
When this is done, it is recommended to monitor the serial output, but it is not essential.  
If you do not use serial input of the initial input, otamain will start a softAP LCM-xxxx  
You select the wifi network, and define your repo to be used.

In ~5 minutes, the software will set up everything and download your code.

You should be able to monitor progress on the wifi network you configured by  
using this command or the UDPlogger client binary.
```
nc -kulnw0 45678
```

ENJOY!

If you want to practice, the default settings are to load an app called lcm-demo.
It will show some basic info and reset every 30s.
If you use 3 powercycles, it will start otamain after those 30s.
You can learn from how this app is created how you can include this behaviour in your own app.
It will evolve, so this description could get outdated.  

Considering that LCM4EP32 is getting in a useful state, beta versions are fixed in release 0.1.3  
There is no more otabootbeta.bin anymore. Use 12 powercycles instead.



### Instructions if you own the private key:
```
cd LCM4ESP32
```
- initial steps to be expanded

#### These are the steps if not introducing a new key pair
- create/update the file versions1/latest-pre-release without new-line and setup 0.1.4 version folder
```
echo 0.1.4 > version.txt
mkdir versions1/0.1.4v
echo -n 0.1.4 > versions1/0.1.4v/latest-pre-release
cp versions1/certs.sector versions1/certs.sector.sig versions1/0.1.4v
cp versions1/public*key*   versions1/0.1.4v
```
- create the ota-main program
```
export -n EXTRA_CFLAGS
idf.py fullclean >/dev/null 2>&1; rm -rf /mnt/main
idf.py app
mv build/LCM4ESP32.bin versions1/0.1.4v/otamain.bin
```
- create the ota-boot program.  
use 12 powercycles to get into lcm beta mode
```
EXTRA_CFLAGS=-DOTABOOT
export EXTRA_CFLAGS
idf.py fullclean >/dev/null 2>&1; rm -rf /mnt/main
idf.py all
cp build/LCM4ESP32.bin versions1/0.1.4v/otaboot.bin
cp build/partition_table/partition-table.bin versions1/0.1.4v
cp build/bootloader/bootloader.bin versions1/0.1.4v
```
- remove the older version files
#
- update Changelog
- if you can sign the binaries locally, do so, else follow later steps
- test otaboot for basic behaviour
- commit and sync submodules
- commit and sync this as version 0.1.4  
- set up a new github release 0.1.4 as a pre-release using the just commited master...  
- upload the certs and binaries to the pre-release assets on github  
#
- erase the flash and upload the privatekey
```
esptool.py -p /dev/cu.usbserial-* --baud 230400 erase_flash 
esptool.py -p /dev/cu.usbserial-* --baud 230400 write_flash 0xf9000 versions1-privatekey.der
```
- upload the ota-boot BETA program to the device that contains the private key
```
make flash OTAVERSION=0.1.4 OTABETA=1
```
- power cycle to prevent the bug for software reset after flash  
- setup wifi and select the ota-demo repo without pre-release checkbox  
- create the 2 signature files next to the bin file and upload to github one by one  
- verify the hashes on the computer  
```
openssl sha384 versions1/0.1.4v/otamain.bin
xxd versions1/0.1.4v/otamain.bin.sig
```

- upload the file versions1/0.1.4v/latest-pre-release to the 'latest release' assets on github










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

more practical
idf.py fullclean >/dev/null 2>&1;rm -rd /mnt/*

idf.py -B <dir> allows overriding the build directory from the default build subdirectory of the project directory




~/bin/ecc_signer otaboot.bin ../secp384r1prv.der ../secp384r1pub.der
printf "%08x" `cat otaboot.bin | wc -c`| xxd -r -p > len
cat hash len sign > otaboot.bin.sig
~/bin/ecc_signer otamain.bin ../secp384r1prv.der ../secp384r1pub.der
printf "%08x" `cat otamain.bin | wc -c`| xxd -r -p > len
cat hash len sign > otamain.bin.sig
rm hash len sign
