# Changelog

## 0.9.8 release candidate for 1.0
- made a first version of the README
- take care led is off after download
- moved to esp idf 4.4.3
- partition sizes increased for future expansion
- ledinfo on webconfig fixed (inverted)
- removed unused files from bootloader

## 0.9.2 support for LED in bootloader and LCM
- select LED pin in serial or web interface
- from count>1 LED will light in bootloader
- once otamain or otaboot run, fast blink
- factory reset will also wipe otadata partition
- cleanup of stale code in many places
- cosmetic fixes in deploy.md

## 0.9.1 Forking out to ESP32S2 and ESP32C3
- renaming binaries to reflect processor
- introduced a script to switch between processors
- .gitignore for the different files involved
- fixed certs.h file so it matches the hash ;-)
- NOT BACKWARD COMPATIBLE (because the name change)

## 0.9.0 Beta mode reached, all functions ported
- CONFIG_NEWLIB_NANO_FORMAT, saves 40k of flash size
- partition table, lean and mean
- certs files now final
- cert file swapping implemented and tested

## previous alpha releases
- see commit notes
