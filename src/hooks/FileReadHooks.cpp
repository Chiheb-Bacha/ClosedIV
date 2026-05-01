#include "main.h"

using OpenBulkFn = HANDLE(*)(void*, const char*, __int64*);
using GetFileTimeFn = FILETIME(*)(void*, const char*);
using GetFileSizeFn = uint64_t(*)(void*, const char*);
using GetAttributesFn = uint64_t(*)(void*, const char*);

inline OpenBulkFn g_origOpenBulk2 = nullptr;
inline GetFileTimeFn g_origGetFileTime2 = nullptr;
inline GetFileSizeFn g_origGetFileSize2 = nullptr;
inline GetAttributesFn g_origGetAttributes2 = nullptr;

HANDLE OpenBulkHook2(void* device, const char* path, __int64* a3)
{
	logger::write("info", "[%s] Called with path /%s", __FUNCTION__, path);
	return g_origOpenBulk2(device, path, a3);
}

FILETIME GetFileTimeHook2(void* device, const char* path)
{
	logger::write("info", "[%s] Called with path /%s", __FUNCTION__, path);
	return g_origGetFileTime2(device, path);
}

uint64_t GetFileSizeHook2(void* device, const char* path)
{
	logger::write("info", "[%s] Called with path /%s", __FUNCTION__, path);
	return g_origGetFileSize2(device, path);
}

uint64_t GetAttributesHook2(void* device, const char* path)
{
	logger::write("info", "[%s] Called with path /%s", __FUNCTION__, path);
	return g_origGetAttributes2(device, path);
}

HANDLE OpenBulkHook(void* device, const char* path, __int64* a3)
{
	HANDLE FileW;
	WCHAR WideCharStr[256];

	*a3 = 0;

	logger::write("info", "[%s] Called with path /%s", __FUNCTION__, path);

	MultiByteToWideChar(0xFDE9u, 0, path, -1, WideCharStr, 256);

	FileW = CreateFileW((L"mods/" + std::wstring(WideCharStr)).c_str(), 0x80000000, 1u, 0, 3, 0x80, 0);

	if (FileW == (HANDLE)-1)
		FileW = CreateFileW(WideCharStr, 0x80000000, 1u, 0, 3, 0x80, 0);
	else
	{
		logger::write("mods", "[%s] Found mods/%s", __FUNCTION__, path);
	}

	return FileW;
}

FILETIME GetFileTimeHook(void* device, const char* path)
{
	WCHAR WideCharStr[256];
	WIN32_FILE_ATTRIBUTE_DATA FileInformation;

	logger::write("info", "[%s] Called with path /%s", __FUNCTION__, path);

	MultiByteToWideChar(0xFDE9u, 0, path, -1, WideCharStr, 256);

	if (GetFileAttributesExW((L"mods/" + std::wstring(WideCharStr)).c_str(), GetFileExInfoStandard, &FileInformation))
	{
		logger::write("mods", "[%s] Found mods/%s", __FUNCTION__, path);
		return FileInformation.ftLastWriteTime;
	}
	else if (GetFileAttributesExW(WideCharStr, GetFileExInfoStandard, &FileInformation))
		return FileInformation.ftLastWriteTime;
	else
		return (FILETIME)0;
}

uint64_t GetFileSizeHook(void* device, const char* path)
{
	WCHAR WideCharStr[256];
	WIN32_FILE_ATTRIBUTE_DATA FileInformation;

	logger::write("info", "[%s] Called with path /%s", __FUNCTION__, path);

	MultiByteToWideChar(0xFDE9u, 0, path, -1, WideCharStr, 256);

	if (GetFileAttributesExW((L"mods/" + std::wstring(WideCharStr)).c_str(), GetFileExInfoStandard, &FileInformation))
	{
		logger::write("mods", "[%s] Found mods/%s", __FUNCTION__, path);
		return FileInformation.nFileSizeLow | (static_cast<size_t>(FileInformation.nFileSizeHigh) << 32);
	}
	else if (GetFileAttributesExW(WideCharStr, GetFileExInfoStandard, &FileInformation))
		return FileInformation.nFileSizeLow | (static_cast<size_t>(FileInformation.nFileSizeHigh) << 32);
	else
		return 0;
}

uint64_t GetAttributesHook(void* device, const char* path)
{
	WCHAR WideCharStr[256];
	DWORD FileAttributesW;

	logger::write("info", "[%s] Called with path /%s", __FUNCTION__, path);

	MultiByteToWideChar(0xFDE9u, 0, path, -1, WideCharStr, 256);

	FileAttributesW = GetFileAttributesW((L"mods/" + std::wstring(WideCharStr)).c_str());

	if (FileAttributesW == -1)
		FileAttributesW = GetFileAttributesW(WideCharStr);
	else
	{
		logger::write("mods", "[%s] Found mods/%s", __FUNCTION__, path);
	}
	return FileAttributesW;
}

static memory::InitFuncs FileReadHooks([] {
	//hooks for reading files

	// These are equivalent to those used in legacy
	if (IsEnhanced()) {
		memory::scan("41 56 56 57 53 48 81 ec ? ? ? ? 4c 89 c7 66 c7 ? ? ? ? ? 4c 8d 74 24")
			.make_jmp_ret(OpenBulkHook);

		memory::scan("66 c7 01 ? ? 29 d9 d1 e9 66 89 4c 24 ? 31 ff 4c 8d 44 ? ? 48 89 d9 31 d2 ff 15 ? ? ? ? 85 c0").add(-0x10d)
			.make_jmp_ret(GetFileTimeHook);

		memory::scan("66 c7 01 ? ? 29 d9 d1 e9 66 89 4c 24 ? 31 ff 4c 8d 44 24 ? 48 89 d9 31 d2 ff 15 ? ? ? ? 8b 4c 24").add(-0x10d)
			.make_jmp_ret(GetFileSizeHook);

		memory::scan("41 56 56 57 53 48 81 ec ? ? ? ? 66 c7 ? ? ? ? ? 4c 8d 74 24")
			.make_jmp_ret(GetAttributesHook);
		
		// from another vtable, at the same offsets though
		// these are only called if directStorage is activated. If you deactivate it with -forcewin32, the ones above are called instead
		memory::scan("41 57 41 56 56 57 53 48 81 ec 60 02 00 00 48 89 d3 48 89 cf").hook(OpenBulkHook2, &g_origOpenBulk2);

		memory::scan("66 c7 01 00 00 29 d9 d1 e9 66 89 4c 24 70 4c 8d 44 24 48 48 89 d9 31 d2 ff 15 ? ? ? ? 85 c0 74 14 8b 44 24 64 8b 4c 24 68 48 c1 e0 20 48 09 c1 48 89 4c 24 38")
			.add(-0x15d).hook(GetFileTimeHook2, &g_origGetFileTime2);

		memory::scan("66 c7 01 00 00 29 d9 d1 e9 66 89 4c 24 70 4c 8d 44 24 48 48 89 d9 31 d2 ff 15 ? ? ? ? 85 c0 74 0a 48 8b 44 24 5c 48 89 44 24 38")
			.add(-0x15d).hook(GetFileSizeHook2, &g_origGetFileSize2);

		memory::scan("56 57 53 48 81 ec 60 02 00 00 48 89 d7 48 89 ce c7 44 24 3c ff ff ff ff 48 89 d1 ba 3a 00 00 00")
			.hook(GetAttributesHook2, &g_origGetAttributes2);
	}
	else {
		memory::scan("40 53 48 81 EC ? ? ? ? 49 8B D8 4C 8B C2 48 8D 4C 24 ? BA ? ? ? ? E8 ? ? ? ? 48 83 64 24")
			.make_jmp_ret(OpenBulkHook);

		memory::scan("48 81 EC ? ? ? ? 4C 8B C2 48 8D 4C 24 ? BA ? ? ? ? E8 ? ? ? ? 4C 8D 44 24 ? 33 D2 48 8B C8 FF 15 ? ? ? ? 85 C0 75 04 33 C0 EB 0F 8B 44 24 38 8B 4C 24 34 48 C1 E0 20 48 0B C1 48 81 C4")
			.make_jmp_ret(GetFileTimeHook);

		memory::scan("48 81 EC ? ? ? ? 4C 8B C2 48 8D 4C 24 ? BA ? ? ? ? E8 ? ? ? ? 4C 8D 44 24 ? 33 D2 48 8B C8 FF 15 ? ? ? ? 85 C0 75 04 33 C0 EB 0F 8B 44 24 3C 8B 4C 24 40 48 C1 E0 20 48 0B C1 48 81 C4")
			.make_jmp_ret(GetFileSizeHook);

		memory::scan("48 89 5C 24 ? 57 48 81 EC ? ? ? ? 4C 8B C2 48 8D 4C 24 ? BA ? ? ? ? E8 ? ? ? ? 48 8B C8 FF 15 ? ? ? ? 83 CF FF 8B D8 3B C7 74 0F 48 8D 4C 24")
			.make_jmp_ret(GetAttributesHook);
	}
	});