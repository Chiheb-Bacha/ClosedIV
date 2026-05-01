#include "main.h"
#include <iomanip>
#include <sstream>
#include <string>

void logger::init()
{
	if(std::filesystem::exists("ClosedIV.log"))
	{
		std::filesystem::remove("ClosedIV.log");
	}
}

void logger::write(const char* type, const char* msg, ...)
{
	char buffer[256]{ 0 };

	va_list args;
	va_start(args, msg);

	sprintf(buffer, "[%s]", type);
	vsprintf(&buffer[strlen(buffer)], msg, args);
	//vprintf(msg, args);
	printf("%s\n", buffer);
	va_end(args);

	if (config::get_log(type))
	{
		std::ofstream logFile("ClosedIV.log", std::ofstream::out | std::ofstream::app);
		logFile.write(buffer, strlen(buffer));
		logFile.write("\n", 1);
		logFile.flush();
		logFile.close();
	}
}

// Just used them to see if MPDLCMAPHooks patches were written correctly
void logger::log_bytes(uint8_t* address, int n, bool spaced) {
	auto buf = hexStr(address, n, spaced);
	write("info", buf.c_str());
}


std::string logger::hexStr(const uint8_t* data, int len, bool spaced)
{
	std::stringstream ss;
	ss << std::hex;

	for (int i(0); i < len; ++i)
		ss << std::setw(2) << std::setfill('0') << (int)data[i] << (spaced ? " " : "");

	return ss.str();
}