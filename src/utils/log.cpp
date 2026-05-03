#include "main.h"
#include <iomanip>
#include <sstream>
#include <string>

void logger::init()
{
	if(std::filesystem::exists("RageOpenV.log"))
	{
		std::filesystem::remove("RageOpenV.log");
	}
}

void logger::vwrite(const char* type, const char* msg, va_list args)
{
    char buffer[256]{ 0 };
    char timeBuffer[32]{ 0 };

    SYSTEMTIME st;
    GetLocalTime(&st);

    snprintf(timeBuffer, sizeof(timeBuffer),
        "%02d:%02d:%02d.%03d",
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    int offset = snprintf(buffer, sizeof(buffer), "[%s][%s]", timeBuffer, type);

    if (offset < 0 || offset >= (int)sizeof(buffer))
        offset = sizeof(buffer) - 1;

    vsnprintf(buffer + offset, sizeof(buffer) - offset, msg, args);

    if (config::get_log(type))
    {
        std::ofstream logFile("RageOpenV.log", std::ofstream::out | std::ofstream::app);
        logFile << buffer << '\n';
    }
}

// This function will log things that happen rarely
void logger::write(const char* type, const char* msg, ...)
{
    va_list args;
    va_start(args, msg);
    vwrite(type, msg, args);
    va_end(args);
}

// If targeting ReleaseWithLogs, this function will log inside hooks that are on hot paths
void logger::log(const char* type, const char* msg, ...)
{
#ifdef _LOG
    va_list args;
    va_start(args, msg);
    vwrite(type, msg, args);
    va_end(args);
#endif
}