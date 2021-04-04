#include "main.h"
#pragma warning(disable : 4100)
#pragma warning(disable : 4152)
#pragma warning(disable : 4242)
#pragma warning(disable : 4047)
#pragma warning(disable : 4244)


static uintptr_t OriginalAddr;
UNICODE_STRING uObRegisterCallbacks;
POB_CALLBACK_REGISTRATION lastCallbackRegistration;


NTSTATUS fake_ObRegisterCallbacks(POB_CALLBACK_REGISTRATION CallbackRegistration,PVOID* RegistrationHandle) {
	DbgPrintEx(0, 0, "Calling ObRegisterCallbacks");
	return STATUS_SUCCESS;
}

PVOID hk_MmGetSystemRoutineAddress(PUNICODE_STRING SystemRoutineName)
{
	if (RtlEqualUnicodeString(SystemRoutineName, &uObRegisterCallbacks, TRUE))
	{
		return &fake_ObRegisterCallbacks;
	}
	return MmGetSystemRoutineAddress(SystemRoutineName);
}

void* Iat_Hook(void* BaseAddress, const char* importToHook, void* FuncAddr)
{
	if (!BaseAddress || *(short*)BaseAddress != 0x5A4D || !importToHook || !FuncAddr)
		return NULL;

	DbgPrintEx(0, 0, "BaseAddress Seems Good !");

	PIMAGE_DOS_HEADER dos_Header = (PIMAGE_DOS_HEADER)(BaseAddress);
	PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((DWORD_PTR)BaseAddress + dos_Header->e_lfanew);
	IMAGE_DATA_DIRECTORY import_dir = nt_headers->OptionalHeader.DataDirectory[1];
	PIMAGE_IMPORT_DESCRIPTOR import_des = (PIMAGE_IMPORT_DESCRIPTOR)(import_dir.VirtualAddress + (DWORD_PTR)BaseAddress);


	LPCSTR libName = NULL;
	PVOID result = NULL;
	PIMAGE_IMPORT_BY_NAME func_name = NULL;

	if (!import_des)
		return NULL;

	while (import_des != NULL)
	{
		libName = (LPCSTR)import_des->Name + (DWORD_PTR)BaseAddress;
		PIMAGE_THUNK_DATA thunk, ori_thunk;
		ori_thunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)BaseAddress + import_des->OriginalFirstThunk);
		thunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)BaseAddress + import_des->FirstThunk);
		while (ori_thunk->u1.AddressOfData != NULL)
		{
			func_name = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)BaseAddress + ori_thunk->u1.AddressOfData);
			if (strcmp(func_name->Name, importToHook) == 0)
			{
				result = (PVOID)(thunk->u1.Function);
				OriginalAddr = (uintptr_t)result;

				_disable();
				ULONGLONG cr0 = __readcr0();
				__writecr0(cr0 & 0xfffffffffffeffff);
				//do write

				thunk->u1.Function = (ULONG64)(FuncAddr);

				__writecr0(cr0);
				_enable();
				DbgPrintEx(0, 0, "Hooked !\n");
				return result;
			}
			++ori_thunk;
			++thunk;
		}
		++import_des;
	}
	return NULL;
}

void load(PUNICODE_STRING path, HANDLE pid, PIMAGE_INFO info)
{
	PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((uintptr_t)info->ImageBase + ((PIMAGE_DOS_HEADER)info->ImageBase)->e_lfanew);// get the pe headers by using ImageBase + e_lfanew
    //e_lfanew is the offset of where the peheader is located
	if (ntHeaders->FileHeader.TimeDateStamp == 0x5f5a187b) // EQU8 AntiCheat timestamp
	{
		DbgPrintEx(0, 0, "Found EQU8 AntiChair !");
		Iat_Hook(info->ImageBase, "MmGetSystemRoutineAddress", &hk_MmGetSystemRoutineAddress);
	}
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObj, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);
	pDriverObj->DriverUnload = DriverUnload;
	DbgPrintEx(0, 0, "Eh yo wassup.\n");
	RtlInitUnicodeString(&uObRegisterCallbacks,L"ObRegisterCallbacks");
	PsSetLoadImageNotifyRoutine(load);
	return STATUS_SUCCESS;
}

NTSTATUS DriverUnload(PDRIVER_OBJECT pDriverObj)
{
	UNREFERENCED_PARAMETER(pDriverObj);
	PsRemoveLoadImageNotifyRoutine(load);
	return STATUS_SUCCESS;
}