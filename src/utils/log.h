#pragma once

namespace logger
{
	void init();
	void write(const char* type, const char* msg, ...);
	void log_bytes(uint8_t* address, int n, bool spaced = true);
	std::string hexStr(const uint8_t* data, int len, bool spaced = true);
}