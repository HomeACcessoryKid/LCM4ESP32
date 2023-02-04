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
*CHECK WHICH CHIP YOU ARE USING*  
_ESP32_:
```
cd to-where-you-downloaded-the-below-three-files
esptool.py --chip esp32 --port /dev/cu.usb* --baud 460800 --before default_reset --after hard_reset \
write_flash -z --flash_mode dio --flash_freq 40m --flash_size detect \
0x01000 32bootloader.bin \
0x08000 32partition-table.bin \
0xf0000 32otaboot.bin
```
_ESP32S2_:
```
cd to-where-you-downloaded-the-below-three-files
esptool.py --chip esp32s2 --port /dev/cu.usb* --baud 460800 --before default_reset --after hard_reset \
write_flash --flash_mode dio --flash_freq 80m --flash_size detect \
0x01000 s2bootloader.bin \
0x08000 s2partition-table.bin \
0xf0000 s2otaboot.bin
```
_ESP32C3_:
```
cd to-where-you-downloaded-the-below-three-files
esptool.py --chip esp32c3 --port /dev/cu.usb* --baud 460800 --before default_reset --after hard_reset \
write_flash --flash_mode dio --flash_freq 80m --flash_size detect \
0x000000 c3bootloader.bin \
0x008000 c3partition-table.bin \
0x100000 c3otaboot.bin
```
When this is done, it is recommended to monitor the serial output, but it is not essential.  
If you do not use serial input of the initial input, otamain will start a softAP LCM-xxxx  
You select the wifi network, and define your repo to be used, set an extra string to  
personalise your app and set the LED if you want visual feedback.

In ~5 minutes, the software will set up everything and download your code.

You should be able to monitor progress on the wifi network you configured by  
using this command or the UDPlogger client binary.
```
nc -kulnw0 45678
```

ENJOY!

If you want to practice, the default settings are to load an app called (lcm-demo)[https://github.com/HomeACcessoryKid/lcm-demo].
It will show some basic info and reset every 30s.
In a menu you can change nvs fields and test all of the features of LCM.
Also, if you use 3 powercycles, it will start otamain after those 30s.
If you use 4 powercycles, it will also reset otaversion to 0.0.0 which forces a new laod of the user app.
You can learn from how this app is created how you can include this behaviour in your own app.

PS. There is no more otabootbeta.bin anymore. Use 12 powercycles instead.

<br>
<br>
<br>
<br>
<br>

## Instructions if you own the private key:
```
cd LCM4ESP32
```
- initial steps to be expanded

#### These are the steps if not introducing a new key pair
- create/update the file versions1/latest-pre-release without new-line and setup 0.9.9 version folder
```
echo 0.9.9 > version.txt
mkdir versions1/0.9.9v
echo -n 0.9.9 > versions1/0.9.9v/latest-pre-release
cp versions1/certs.sector versions1/certs.sector.sig versions1/0.9.9v
cp versions1/public*key*   versions1/0.9.9v
```
_for esp32s2_
```
../switchto.sh s2
y
cp x-s2partitions.csv partitions.csv
```
- create the ota-main program
```
export -n EXTRA_CFLAGS
idf.py fullclean >/dev/null 2>&1; rm -rf /mnt/main
idf.py app
mv build/LCM4ESP32.bin versions1/0.9.9v/s2otamain.bin
```
- create the ota-boot program.  
```
EXTRA_CFLAGS=-DOTABOOT
export EXTRA_CFLAGS
idf.py fullclean >/dev/null 2>&1; rm -rf /mnt/main
idf.py all
cp build/LCM4ESP32.bin versions1/0.9.9v/s2otaboot.bin
cp build/partition_table/partition-table.bin versions1/0.9.9v/s2partition-table.bin
cp build/bootloader/bootloader.bin versions1/0.9.9v/s2bootloader.bin
```
_for esp32c3_
```
../switchto.sh c3
y
cp x-c3partitions.csv partitions.csv
```
- create the ota-main program
```
export -n EXTRA_CFLAGS
idf.py fullclean >/dev/null 2>&1; rm -rf /mnt/main
idf.py app
mv build/LCM4ESP32.bin versions1/0.9.9v/c3otamain.bin
```
- create the ota-boot program.  
```
EXTRA_CFLAGS=-DOTABOOT
export EXTRA_CFLAGS
idf.py fullclean >/dev/null 2>&1; rm -rf /mnt/main
idf.py all
cp build/LCM4ESP32.bin versions1/0.9.9v/c3otaboot.bin
cp build/partition_table/partition-table.bin versions1/0.9.9v/c3partition-table.bin
cp build/bootloader/bootloader.bin versions1/0.9.9v/c3bootloader.bin
```
_for esp32_
```
../switchto.sh 32
y
cp x-32partitions.csv partitions.csv
```
- create the ota-main program
```
export -n EXTRA_CFLAGS
idf.py fullclean >/dev/null 2>&1; rm -rf /mnt/main
idf.py app
mv build/LCM4ESP32.bin versions1/0.9.9v/32otamain.bin
```
- create the ota-boot program.  
```
EXTRA_CFLAGS=-DOTABOOT
export EXTRA_CFLAGS
idf.py fullclean >/dev/null 2>&1; rm -rf /mnt/main
idf.py all
cp build/LCM4ESP32.bin versions1/0.9.9v/32otaboot.bin
cp build/partition_table/partition-table.bin versions1/0.9.9v/32partition-table.bin
cp build/bootloader/bootloader.bin versions1/0.9.9v/32bootloader.bin
```

- remove the older version files
#
- update Changelog
- if you can sign the binaries locally, do so, else follow later steps
```
~/bin/ecc_signer s2otaboot.bin ../secp384r1prv.der ../secp384r1pub.der
printf "%08x" `cat s2otaboot.bin | wc -c`| xxd -r -p > len
cat hash len sign > s2otaboot.bin.sig
~/bin/ecc_signer s2otamain.bin ../secp384r1prv.der ../secp384r1pub.der
printf "%08x" `cat s2otamain.bin | wc -c`| xxd -r -p > len
cat hash len sign > s2otamain.bin.sig
rm hash len sign
```
```
~/bin/ecc_signer c3otaboot.bin ../secp384r1prv.der ../secp384r1pub.der
printf "%08x" `cat c3otaboot.bin | wc -c`| xxd -r -p > len
cat hash len sign > c3otaboot.bin.sig
~/bin/ecc_signer c3otamain.bin ../secp384r1prv.der ../secp384r1pub.der
printf "%08x" `cat c3otamain.bin | wc -c`| xxd -r -p > len
cat hash len sign > c3otamain.bin.sig
rm hash len sign
```
```
~/bin/ecc_signer 32otaboot.bin ../secp384r1prv.der ../secp384r1pub.der
printf "%08x" `cat 32otaboot.bin | wc -c`| xxd -r -p > len
cat hash len sign > 32otaboot.bin.sig
~/bin/ecc_signer 32otamain.bin ../secp384r1prv.der ../secp384r1pub.der
printf "%08x" `cat 32otamain.bin | wc -c`| xxd -r -p > len
cat hash len sign > 32otamain.bin.sig
rm hash len sign
```

### _use 12 powercycles to get into lcm beta mode if that is what you want_
- test otaboot for basic behaviour
- commit and sync submodules (not applicable for now)
- commit this locally with the description of version 0.9.9 taken from Changelog
- add the version tag and push to github
```
git tag 0.9.9 HEAD
git push --tags origin HEAD
```
- on Github website, set up a new github release 0.9.9 as a pre-release using the just commited master...  
- upload the certs and binaries to the pre-release assets on github  
#
- erase the flash and upload the privatekey
```
esptool.py -p /dev/cu.usbserial-* --baud 230400 erase_flash 
esptool.py -p /dev/cu.usbserial-* --baud 230400 write_flash 0xf9000 versions1-privatekey.der
```
- upload the ota-boot BETA program to the device that contains the private key
```
make flash OTAVERSION=0.9.9 OTABETA=1
```
- setup wifi and select the ota-demo repo without pre-release checkbox  
- create the 2 signature files next to the bin file and upload to github one by one  
- verify the hashes on the computer  
```
openssl sha384 versions1/0.9.9v/otamain.bin
xxd versions1/0.9.9v/otamain.bin.sig
```

- upload the file versions1/0.9.9v/latest-pre-release to the 'latest release' assets on github

<br>
<br>
<br>
<br>


For your information:

switchto.sh is run from the repo
```
#!/bin/sh
if [[ $1 == 32 ]]; then
  target=esp32
else
  target=esp32${1}
fi
### no input parameter
if [[ x$1 == x ]]; then
  echo "usage ../switchto.sh <target postfix>"
  echo "postfix: 32, s2, s3, c3, h2"
  exit
fi
### no sdkconfig, so starting from scratch
if [[ ! -f sdkconfig ]]; then
  echo Run idf.py set-target ${target}
  exit
fi
old=`awk '/CONFIG_IDF_TARGET=/{print substr($0,length-2,2)}' sdkconfig`
### old and new are the same
if [[ x$1 == x$old ]]; then
  echo new and old=${old} are the same, no action
  exit
else
  echo switching from $old to $1

  echo mv build x-${old}build
  echo mv sdkconfig x-${old}sdkconfig 
  ### no existing source files
  if [[ ! -f x-${1}sdkconfig ]]; then
    echo idf.py set-target ${target}
  else
    echo mv x-${1}build build
    echo mv x-${1}sdkconfig sdkconfig
  fi

  read -p "Are you sure? " -n 1 -r
  echo
  if [[ $REPLY =~ ^[Yy]$ ]]
  then
    mv build x-${old}build
    mv sdkconfig x-${old}sdkconfig 
    if [[ ! -f x-${1}sdkconfig ]]; then
      echo Run: idf.py set-target ${target}
    else
      mv x-${1}build build
      mv x-${1}sdkconfig sdkconfig
      echo Target now `awk '/CONFIG_IDF_TARGET=/{print substr($0,length-2,2)}' sdkconfig`
    fi
  else
    echo aborted
  fi
fi
```
<br>
<br>
<br>
<br>
<br>



Some random stuff that sometimes comes in handy

```
EXTRA_CFLAGS=-DOTABOOT
export EXTRA_CFLAGS
idf.py fullclean
idf.py all

export -n EXTRA_CFLAGS
idf.py fullclean
idf.py all
```
works, but painfull


idf.py reconfigure re-runs CMake even if it doesn’t seem to need re-running.
This isn’t necessary during normal usage, but can be useful after adding/removing files from the source tree,
or when modifying CMake cache variables.
For example, `idf.py -DNAME='VALUE' reconfigure` can be used to set variable NAME in CMake cache to value VALUE


some flash command templates
```
    esptool.py --chip esp32 --port /dev/cu.usbserial* --baud 460800 --before default_reset --after hard_reset \
    write_flash -z --flash_mode dio --flash_freq 40m --flash_size detect \
    0x8000 build/partition_table/partition-table.bin 0x20c000 certs.sector 0x209000 build/ota_data_initial.bin 0x300000 build/LCM4ESP32.bin

    esptool.py --chip esp32 --port /dev/cu.usbserial* --baud 460800 --before default_reset --after hard_reset \
    write_flash -z --flash_mode dio --flash_freq 40m --flash_size detect \
    0x209000 build/ota_data_initial.bin 0x300000 build/LCM4ESP32.bin
    
    esptool.py --chip esp32 --port /dev/cu.usbserial* --baud 460800 --before default_reset --after hard_reset \
    write_flash -z --flash_mode dio --flash_freq 40m --flash_size detect \
    0x300000 build/LCM4ESP32.bin
```

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

`idf.py -B <dir>` allows overriding the build directory from the default build subdirectory of the project directory

