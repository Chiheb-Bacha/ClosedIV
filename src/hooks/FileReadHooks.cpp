#include "main.h"
#include <unordered_map>
#include <shared_mutex>

using OpenBulkFn = HANDLE(*)(void*, const char*, __int64*);
using GetFileTimeFn = FILETIME(*)(void*, const char*);
using GetFileSizeFn = uint64_t(*)(void*, const char*);
using GetAttrsFn = uint64_t(*)(void*, const char*);

inline OpenBulkFn g_origOpenBulk1 = nullptr, g_origOpenBulk2 = nullptr;
inline GetFileTimeFn g_origGetFileTime1 = nullptr, g_origGetFileTime2 = nullptr;
inline GetFileSizeFn g_origGetFileSize1 = nullptr, g_origGetFileSize2 = nullptr;
inline GetAttrsFn g_origGetAttribs1 = nullptr, g_origGetAttribs2 = nullptr;

static const uint8_t EXISTS = 1;
static const uint8_t NOT_EXISTS = 2;
static std::unordered_map<std::string, uint8_t> g_modsCache;
static std::shared_mutex g_modsCacheMutex;

static bool TryModsPath(const char* path, std::string& outModsPath)
{
    outModsPath = std::string("mods/") + path;

    // Used a hashmap for lookups so that we don't call GetFileAttributeA every time
    {
        std::shared_lock lock(g_modsCacheMutex);
        auto it = g_modsCache.find(outModsPath);
        if (it != g_modsCache.end())
            return it->second == EXISTS;
    }

    bool exists = GetFileAttributesA(outModsPath.c_str()) != INVALID_FILE_ATTRIBUTES;
    {
        std::unique_lock lock(g_modsCacheMutex);
        g_modsCache[outModsPath] = exists ? EXISTS : NOT_EXISTS;
    }
    return exists;
}

static HANDLE OpenBulkImpl(void* device, const char* path, __int64* a3, OpenBulkFn orig)
{
    logger::log("info", "[%s] Called with path /%s", __FUNCTION__, path);

    std::string modsPath;
    if (path && TryModsPath(path, modsPath))
    {
        logger::log("mods", "[%s] Redirecting to /%s", __FUNCTION__, modsPath.c_str());
        HANDLE result = orig(device, modsPath.c_str(), a3);
        if (result && result != INVALID_HANDLE_VALUE)
            return result;
    }
    return orig(device, path, a3);
}

static FILETIME GetFileTimeImpl(void* device, const char* path, GetFileTimeFn orig)
{
    logger::log("info", "[%s] Called with path /%s", __FUNCTION__, path);

    std::string modsPath;
    if (path && TryModsPath(path, modsPath))
    {
        logger::log("mods", "[%s] Redirecting to /%s", __FUNCTION__, modsPath.c_str());
        return orig(device, modsPath.c_str());
    }
    return orig(device, path);
}

static uint64_t GetFileSizeImpl(void* device, const char* path, GetFileSizeFn orig)
{
    logger::log("info", "[%s] Called with path /%s", __FUNCTION__, path);

    std::string modsPath;
    if (path && TryModsPath(path, modsPath))
    {
        logger::log("mods", "[%s] Redirecting to /%s", __FUNCTION__, modsPath.c_str());
        return orig(device, modsPath.c_str());
    }
    return orig(device, path);
}

static uint64_t GetAttribsImpl(void* device, const char* path, GetAttrsFn orig)
{
    logger::log("info", "[%s] Called with path /%s", __FUNCTION__, path);

    std::string modsPath;
    if (path && TryModsPath(path, modsPath))
    {
        logger::log("mods", "[%s] Redirecting to /%s", __FUNCTION__, modsPath.c_str());
        return orig(device, modsPath.c_str());
    }
    return orig(device, path);
}

// Vtable 1 (non-DS)
HANDLE OpenBulkHook1(void* d, const char* p, __int64* a3) { 
    return OpenBulkImpl(d, p, a3, g_origOpenBulk1); 
}

FILETIME GetFileTimeHook1(void* d, const char* p) { 
    return GetFileTimeImpl(d, p, g_origGetFileTime1); 
}

uint64_t GetFileSizeHook1(void* d, const char* p) { 
    return GetFileSizeImpl(d, p, g_origGetFileSize1); 
}

uint64_t GetAttribsHook1(void* d, const char* p) { 
    return GetAttribsImpl(d, p, g_origGetAttribs1); 
}

// Vtable 2 (DS)
HANDLE OpenBulkHook2(void* d, const char* p, __int64* a3) { 
    return OpenBulkImpl(d, p, a3, g_origOpenBulk2); 
}

FILETIME GetFileTimeHook2(void* d, const char* p) { 
    return GetFileTimeImpl(d, p, g_origGetFileTime2); 
}

uint64_t GetFileSizeHook2(void* d, const char* p) { 
    return GetFileSizeImpl(d, p, g_origGetFileSize2); 
}

uint64_t GetAttribsHook2(void* d, const char* p) { 
    return GetAttribsImpl(d, p, g_origGetAttribs2); 
}

static memory::InitFuncs FileReadHooks([] {
    if (IsEnhanced()) {
        memory::scan("41 56 56 57 53 48 81 ec ? ? ? ? 4c 89 c7 66 c7 ? ? ? ? ? 4c 8d 74 24")
            .hook(OpenBulkHook1, &g_origOpenBulk1);

        memory::scan("66 c7 01 ? ? 29 d9 d1 e9 66 89 4c 24 ? 31 ff 4c 8d 44 ? ? 48 89 d9 31 d2 ff 15 ? ? ? ? 85 c0").add(-0x10d)
            .hook(GetFileTimeHook1, &g_origGetFileTime1);

        memory::scan("66 c7 01 ? ? 29 d9 d1 e9 66 89 4c 24 ? 31 ff 4c 8d 44 24 ? 48 89 d9 31 d2 ff 15 ? ? ? ? 8b 4c 24").add(-0x10d)
            .hook(GetFileSizeHook1, &g_origGetFileSize1);

        memory::scan("41 56 56 57 53 48 81 ec ? ? ? ? 66 c7 ? ? ? ? ? 4c 8d 74 24")
            .hook(GetAttribsHook1, &g_origGetAttribs1);

        memory::scan("41 57 41 56 56 57 53 48 81 ec 60 02 00 00 48 89 d3 48 89 cf")
            .hook(OpenBulkHook2, &g_origOpenBulk2);

        memory::scan("66 c7 01 00 00 29 d9 d1 e9 66 89 4c 24 70 4c 8d 44 24 48 48 89 d9 31 d2 ff 15 ? ? ? ? 85 c0 74 14 8b 44 24 64 8b 4c 24 68 48 c1 e0 20 48 09 c1 48 89 4c 24 38").add(-0x15d)
            .hook(GetFileTimeHook2, &g_origGetFileTime2);

        memory::scan("66 c7 01 00 00 29 d9 d1 e9 66 89 4c 24 70 4c 8d 44 24 48 48 89 d9 31 d2 ff 15 ? ? ? ? 85 c0 74 0a 48 8b 44 24 5c 48 89 44 24 38").add(-0x15d)
            .hook(GetFileSizeHook2, &g_origGetFileSize2);

        memory::scan("56 57 53 48 81 ec 60 02 00 00 48 89 d7 48 89 ce c7 44 24 3c ff ff ff ff 48 89 d1 ba 3a 00 00 00")
            .hook(GetAttribsHook2, &g_origGetAttribs2);
    }
    else {
        memory::scan("40 53 48 81 EC ? ? ? ? 49 8B D8 4C 8B C2 48 8D 4C 24 ? BA ? ? ? ? E8 ? ? ? ? 48 83 64 24")
            .hook(OpenBulkHook1, &g_origOpenBulk1);

        memory::scan("48 81 EC ? ? ? ? 4C 8B C2 48 8D 4C 24 ? BA ? ? ? ? E8 ? ? ? ? 4C 8D 44 24 ? 33 D2 48 8B C8 FF 15 ? ? ? ? 85 C0 75 04 33 C0 EB 0F 8B 44 24 38 8B 4C 24 34 48 C1 E0 20 48 0B C1 48 81 C4")
            .hook(GetFileTimeHook1, &g_origGetFileTime1);

        memory::scan("48 81 EC ? ? ? ? 4C 8B C2 48 8D 4C 24 ? BA ? ? ? ? E8 ? ? ? ? 4C 8D 44 24 ? 33 D2 48 8B C8 FF 15 ? ? ? ? 85 C0 75 04 33 C0 EB 0F 8B 44 24 3C 8B 4C 24 40 48 C1 E0 20 48 0B C1 48 81 C4")
            .hook(GetFileSizeHook1, &g_origGetFileSize1);

        memory::scan("48 89 5C 24 ? 57 48 81 EC ? ? ? ? 4C 8B C2 48 8D 4C 24 ? BA ? ? ? ? E8 ? ? ? ? 48 8B C8 FF 15 ? ? ? ? 83 CF FF 8B D8 3B C7 74 0F 48 8D 4C 24")
            .hook(GetAttribsHook1, &g_origGetAttribs1);
    }
    });