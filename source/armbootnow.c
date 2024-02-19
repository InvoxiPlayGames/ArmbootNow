#include <stdio.h>
#include <stdlib.h>
#include <gccore.h>
#include <malloc.h>
#include <fat.h>
#include "ios_hax.h"

static void *xfb = NULL;
static GXRModeObj *rmode = NULL;

int main(int argc, char **argv) {
	// video and console init
	VIDEO_Init();
	rmode = VIDEO_GetPreferredMode(NULL);
	xfb = MEM_K0_TO_K1(SYS_AllocateFramebuffer(rmode));
	console_init(xfb,20,20,rmode->fbWidth,rmode->xfbHeight,rmode->fbWidth*VI_DISPLAY_PIX_SZ);
	VIDEO_Configure(rmode);
	VIDEO_SetNextFramebuffer(xfb);
	VIDEO_SetBlack(FALSE);
	VIDEO_Flush();
	VIDEO_WaitVSync();
	if(rmode->viTVMode&VI_NON_INTERLACE) VIDEO_WaitVSync();
	printf("\x1b[2;0H");

	// load armboot.bin from the SD card
	printf("loading armboot.bin\n");
	if (!fatInitDefault()) {
		printf("failed to mount SD card\n");
		exit(0);
	}
	FILE *fp = fopen("/bootmii/armboot.bin", "r");
	if (fp == NULL) {
		printf("/bootmii/armboot.bin not found\n");
		exit(0);
	}
	fseek(fp, 0, SEEK_END);
	int filesize = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	uint32_t *armbuf = (uint32_t *)0x91000000;//memalign(0x20, filesize);
	if (armbuf == NULL) {
		printf("armbuf couldn't be allocated (0x%x)\n", filesize);
		exit(0);
	}
	int r = fread(armbuf, 1, 0x20000, fp);
	printf("loaded 0x%x bytes from /bootmii/armboot.bin\n", r);
	DCFlushRange(armbuf, 0x10000);
	fclose(fp);

	// reload IOS to give us a clean slate
	// if this fails, it doesn't matter
	printf("reloading IOS...\n");
	IOS_ReloadIOS(58);

	// run IOS exploit to get permissions
	if (IOSHAX_ClaimPPCKERN()) {
		uint32_t *sram_ffff = (uint32_t *)0xCD410000; // start of IOS SRAM

		// find the "mov pc, r0" trampoline used to launch a new IOS image
		uint32_t trampoline_addr = 0;
		for (int i = 0; i < 0x1000; i++) {
			if (sram_ffff[i] == 0xE1A0F000) {
				trampoline_addr = 0xFFFF0000 + (i * 4);
				printf("found LaunchIOS trampoline at %08x\n", trampoline_addr);
				break;
			}
		}

		// if we found it, find the pointer to aforementioned trampoline
		// this is called in the function that launches the next kernel
		uint32_t trampoline_pointer = 0;
		int trampoline_off = 0;
		if (trampoline_addr != 0) {
			for (int i = 0; i < 0x1000; i++) {
				if (sram_ffff[i] == trampoline_addr) {
					trampoline_pointer = 0xFFFF0000 + (i * 4);
					trampoline_off = i;
					printf("found LaunchIOS trampoline pointer at %08x/%p\n", trampoline_pointer, &sram_ffff[i]);
					break;
				}
			}
		}
		// write the pointer to our code there instead
		sram_ffff[trampoline_off] = (uint32_t)MEM_K0_TO_PHYSICAL(armbuf) + armbuf[0];
		printf("set trampoline ptr to %08x\n", sram_ffff[trampoline_off]);

		// take the plunge...
		printf("launching...");
		sleep(2);
		printf("bye!\n");
		IOS_ReloadIOS(IOS_GetVersion());
	}

	printf("something didn't work right! exiting in 10 seconds\n");
	
	sleep(10);
	exit(0);
	return 0;
}
