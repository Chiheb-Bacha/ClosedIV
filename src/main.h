#pragma once

#include <Windows.h>
#include <algorithm>
#include <iostream>
#include <string>
#include <thread>
#include <filesystem>
#include <vector>

#include "utils/log.h"
#include "utils/memory.h"
#include "utils/rpf.h"
#include "utils/config.h"

#include "gtav/rage/fiDevice.h"
#include "gtav/rage/fiPackfile.h"

inline bool IsEnhanced() {
    static const bool isEnhanced = []() -> bool
        {
            char path[MAX_PATH];
            GetModuleFileNameA(GetModuleHandleA(nullptr), path, MAX_PATH);

            const char* filename = strrchr(path, '\\');
            filename = filename ? filename + 1 : path;

            return (_stricmp(filename, "GTA5_Enhanced.exe") == 0);
        }();
    return isEnhanced;
}