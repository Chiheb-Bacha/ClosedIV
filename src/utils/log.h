#pragma once

namespace logger
{
	void init();
	void write(const char* type, const char* msg, ...);
	void log(const char* type, const char* msg, ...);
	void vwrite(const char* type, const char* msg, va_list args);
}