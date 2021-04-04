#include "includes.h"


DWORD GetProcId(const wchar_t* procName)
{
	DWORD procId = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap != INVALID_HANDLE_VALUE)
	{
		PROCESSENTRY32 procEntry;
		procEntry.dwSize = sizeof(procEntry);
		//loop through all process
		if (Process32First(hSnap, &procEntry))
		{

			do
			{
				//compare current lopping process name with procName parameters
				if (!_wcsicmp(procEntry.szExeFile, procName))
				{
					procId = procEntry.th32ProcessID;
					break;
				}
			} while (Process32Next(hSnap, &procEntry));
		}
	}
	//close handle and return the procId of the process
	CloseHandle(hSnap);
	return procId;
}

uintptr_t GetModuleBaseAddress(DWORD procId, const wchar_t* modName)
{
	uintptr_t modBaseAddr = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId);
	if (hSnap != INVALID_HANDLE_VALUE)
	{
		MODULEENTRY32 modEntry;
		modEntry.dwSize = sizeof(modEntry);
		if (Module32First(hSnap, &modEntry))
		{
			do
			{
				//same thing that GetProcId but for module
				if (!_wcsicmp(modEntry.szModule, modName))
				{
					modBaseAddr = (uintptr_t)modEntry.modBaseAddr;
					break;
				}


			} while (Module32Next(hSnap, &modEntry));
		}
	}
	//close handle and return moduleBaseAddress
	CloseHandle(hSnap);
	return modBaseAddr;
}

void PatchMem(BYTE* lpAddress, BYTE* src, unsigned int sizeofinstruction, HANDLE hProcess)
{
	//variable for stock the old protection
	DWORD oldProtection;
	//change the memory protection
	VirtualProtectEx(hProcess, lpAddress, 0x400, PAGE_EXECUTE_READWRITE, &oldProtection);
	//write instruction
	WriteProcessMemory(hProcess, lpAddress, src, sizeofinstruction, 0);
	//set the old protection
	VirtualProtectEx(hProcess, lpAddress, 0x400, oldProtection, &oldProtection);
}

template <typename Type>
Type ReadMem(HANDLE handle, LPVOID addr)
{
	Type cRead;
	ReadProcessMemory(handle, addr, &cRead, sizeof(cRead), nullptr);
	return cRead;
}
template <typename Type>
void WriteMem(HANDLE handle, LPVOID addr, Type data)
{
	WriteProcessMemory(handle, addr, &data, sizeof(data), 0);
}

int main()
{
	const wchar_t* procName = L"Diabotical-Launcher.exe";
	while (true)
	{
		DWORD procId = GetProcId(procName);
		while (!procId)
		{
			procId = GetProcId(procName);
		}
		std::cout << "Process Id: " << procId << std::endl;
		uintptr_t modBase = GetModuleBaseAddress(procId, procName);
		while (!modBase)
		{
			procId = GetProcId(procName);
			modBase = GetModuleBaseAddress(procId, procName);
		}
		HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procId);
		std::cout << "ModuleBase Address " << (FARPROC)modBase << std::endl;
		if (hProc && hProc != INVALID_HANDLE_VALUE)
		{

			//You have to rename your diabotical.exe to Diabotical-Launcher.exe in order for the bypass to work ( it's because epic games launch Diabotical-Launcher with args and after that Diabotical Launcher launch diabotical with these args
			PatchMem((BYTE*)(modBase + 0x104482), (BYTE*)"\x75\x67", 2, hProc); // l33t bypass equ8 it's just jmp over the error msg after equ8 initialisation and launch the game
			/*
			
			If you want to find this offset open the game without passing by the launcher and open it in a debugger search for the string anticheat and if above this string you can find error you're on the good place now just patch the good jmp
			You can also put a breakpoint on equ8_client_init
			
			*/
			PatchMem((BYTE*)(modBase + 0x4D2897), (BYTE*)"\x83\x3D\x2E\x8F\xD4\x00\x01", 7, hProc); // patch hitbox cmp
			//pattern 83 3D ?? ?? ?? ?? 00 0F 84 ?? ?? ?? ?? 48 8B ?? ?? ?? ?? ?? 48 8B ?? 80 7B 19 ?? ?? 85 31 ?? ?? ?? 33 FF
			DWORD oldProtection;
			VirtualProtectEx(hProc, (LPVOID)(modBase + 0x941C78), 0x400, PAGE_EXECUTE_READWRITE, &oldProtection);
			WriteMem<double>(hProc, (LPVOID)(modBase + 0x941C78), 3.0); // transparency of the hitbox
			VirtualProtectEx(hProc, (LPVOID)(modBase + 0x941C78), 0x400, oldProtection, &oldProtection);
			break;
		}
		Sleep(1);
	}
}