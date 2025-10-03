#include "main.h"

static bool bInited = false;
void (*origGetSystemTimeAsFileTime)(LPFILETIME lpSystemTimeAsFileTime);
void HookGetSystemTimeAsFileTime(LPFILETIME lpSystemTimeAsFileTime)
{
	if (!bInited)
	{
		bInited = true;
		memory::init();

		// Don't hide the console
		auto addr = memory::scan("FF 15 ? ? ? ? E8 ? ? ? ? 65 48 8B 0C 25 ? ? ? ? 8B 05 ? ? ? ? 48 8B 04 C1 BA ? ? ? ? 83 24 02 00 E8", true); // This is kept for backwards compatibility, as I don't know when this pattern stopped working.
		if (addr.address == 0) {
			addr = memory::scan("ff 15 ? ? ? ? 65 48 8b 0c 25 ? ? ? ? 8b 05 ? ? ? ? ba");
		}
		addr.nop(6);

		memory::InitFuncs::run();

		logger::write("info", "ClosedIV Inited!");
	}
	GetSystemTimeAsFileTime(lpSystemTimeAsFileTime);
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

		//compatibility for any asi loader, as OpenIV supports only the one made by Alexander Blade
		if (!memory::HookIAT("kernel32.dll", "GetSystemTimeAsFileTime", (PVOID)HookGetSystemTimeAsFileTime, (PVOID*)&origGetSystemTimeAsFileTime)) {
			logger::write("info", "Hooking failed error (%ld)", GetLastError());
		}
	}
	return TRUE;
}