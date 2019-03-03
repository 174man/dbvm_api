#include <stdio.h>
#include <windows.h>

#include "dbvm_x86.h"

int main() {
	MessageBox(0, 0, 0, 0);
	DBVM d(0x765a3212, 0xfed2ba92);

	d.EPT_Reset();

	DWORD64 PA = d.GetPhysicalAddress(0x401000);

	BYTE buf[0x1000];

	printf("%I64X\n", PA);
	printf("%d deactivate\n", d.CloakDeactivate(PA));
	printf("%d activate\n", d.CloakActivate(PA));
	printf("%d read\n", d.CloakReadOriginal(PA, buf));
	buf[0] = 0xC3;
	printf("%d write\n", d.CloakWriteOriginal(PA, buf));
	printf("%d read\n", d.CloakReadOriginal(PA, buf));

	printf("%02X %02X\n", buf[0], *PBYTE(0x401000));


	MessageBox(0, 0, 0, 0);
	printf("%d deactivate\n", d.CloakDeactivate(PA));

	
	Sleep(INFINITE);
	return 0;
}