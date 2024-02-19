# ArmbootNow

Basic utility to launch an ARM binary from the SD card of a Wii console on the
Starlet security co-processor, using an IOS exploit to avoid the need for
installing BootMii or the Homebrew Channel to the NAND.

This will load from `/bootmii/armboot.bin` on the SD card.

Confirmed working on a retail Wii, a Wii U's vWii and an RVT-H Reader devkit.

It does not rely on any hardcoded offsets or require any installation to the
NAND, so should work across all hardware and IOS revisions that can run any
homebrew code.

## Exploit

The IOS exploit was discovered by [mkwcat](https://github.com/mkwcat) and more
information about it is available in the
[saoirse](https://github.com/mkwcat/saoirse/blob/master/channel/Main/IOSBoot.cpp#L85)
repo, and on [WiiBrew](https://wiibrew.org/wiki/Wii_system_flaws#IOS) (see IOS
-> "/dev/sha does not correctly validate the destination vector").

The implementation here uses shellcode from saoirse, licensed under the MIT
license.

## License

MIT license, see LICENSE.txt.
