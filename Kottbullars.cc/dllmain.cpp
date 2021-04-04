#include "includes.h"

CMisc* pCMisc;

DWORD WINAPI MainThread(HMODULE hModule)
{
    AllocConsole();
    FILE* f;
    freopen_s(&f, "CONOUT$", "w", stdout);
    while (true)
    {
        if (GetAsyncKeyState(VK_NUMPAD1) & 1)
            Vars::bUnlimitedAmmo = !Vars::bUnlimitedAmmo;
        if (GetAsyncKeyState(VK_NUMPAD2) & 1)
            Vars::bRapidFire = !Vars::bRapidFire;
        if (Vars::bUnlimitedAmmo)
        {
            pCMisc->UnlimitedAmmo();
        }
        if (Vars::bRapidFire)
            pCMisc->RapidFire();
    }
    if (kiero::init(kiero::RenderType::D3D11) == kiero::Status::Success)
    {
        //wallhacks hook here
    }
    CloseHandle(hModule);
    FreeLibraryAndExitThread(hModule, 0);
    return 0;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        CreateThread(0, 0, (LPTHREAD_START_ROUTINE)MainThread, hModule, 0, 0);
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

