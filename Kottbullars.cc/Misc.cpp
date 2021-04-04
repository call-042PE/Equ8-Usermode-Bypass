#include "includes.h"

uintptr_t baseAddr = (uintptr_t)GetModuleHandleA("diabotical.exe");

void CMisc::UnlimitedAmmo()
{
	DWORD oldProtect;
	VirtualProtect((BYTE*)((baseAddr + 0x4DA897)), 0x400, PAGE_EXECUTE_READWRITE, &oldProtect);
	memset((BYTE*)(baseAddr + 0x4DA897), 0x90, 2);
	VirtualProtect((BYTE*)((baseAddr + 0x4DA897)), 0x400, oldProtect, &oldProtect);
}

void CMisc::RapidFire()
{
	*(double*)(baseAddr + 0x122C2D0) = 9999;
}