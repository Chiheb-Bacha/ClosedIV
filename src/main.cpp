#include "main.h"

static bool bInited = false;
void (*origGetSystemTimeAsFileTime)(LPFILETIME lpSystemTimeAsFileTime);
DWORD APIENTRY HookGetSystemTimeAsFileTime(LPVOID/*LPFILETIME lpSystemTimeAsFileTime*/)
{
	if (!bInited)
	{
		bInited = true;
		memory::init();

		// Don't hide the console
		if (IsEnhanced()) {
			auto addr = memory::scan("ff 15 ? ? ? ? 48 85 c0 74 ? 48 89 c1 31 d2", true);
			if (addr.address != 0) {
				addr.add(16).nop(6);
			}
		}
		else {
			// This is kept for backwards compatibility, as I don't know when this pattern stopped working.
			auto addr = memory::scan("FF 15 ? ? ? ? E8 ? ? ? ? 65 48 8B 0C 25 ? ? ? ? 8B 05 ? ? ? ? 48 8B 04 C1 BA ? ? ? ? 83 24 02 00 E8", true);
			if (addr.address == 0) {
				addr = memory::scan("ff 15 ? ? ? ? 65 48 8b 0c 25 ? ? ? ? 8b 05 ? ? ? ? ba");
				if (addr.address != 0) {
					addr.nop(6);
				}
			}
		}

		// rpf cache check skip
		if (IsEnhanced()) {
			auto addr = memory::scan("e8 ? ? ? ? 48 8d 0d ? ? ? ? 48 8d 15 ? ? ? ? 48 8d 35");
			if (addr.address != 0) {
				addr.add(1).rip().put<uint16_t>(0x90c3);
			}
		}		

		memory::InitFuncs::run();

		logger::write("info", "ClosedIV Inited!");
	}
	//GetSystemTimeAsFileTime(lpSystemTimeAsFileTime);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  dwReason, LPVOID lpReserved)
{
	if (dwReason == DLL_PROCESS_ATTACH)
	{
		DisableThreadLibraryCalls(hModule);

		config::load();

		logger::init();

		if (config::get_config<bool>("console"))
		{
			AllocConsole();

			FILE* unused = nullptr;
			freopen_s(&unused, "CONIN$", "r", stdin);
			freopen_s(&unused, "CONOUT$", "w", stdout);
			freopen_s(&unused, "CONOUT$", "w", stderr);
		}

		// Hook IAT fails for some reason. Just create a thread and hook.

		//compatibility for any asi loader, as OpenIV supports only the one made by Alexander Blade
	/*	if (!memory::HookIAT("kernel32.dll", "GetSystemTimeAsFileTime", (PVOID)HookGetSystemTimeAsFileTime, (PVOID*)&origGetSystemTimeAsFileTime)) {
			logger::write("info", "Hooking failed error (%ld)", GetLastError());
		}*/
		CreateThread(nullptr, 0, HookGetSystemTimeAsFileTime, nullptr, 0, nullptr);
		
	}
	return TRUE;
}