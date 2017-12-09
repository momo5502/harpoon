#pragma once

namespace utils
{
	class logger
	{
	public:
		static void set_title(std::string title);

		static void info(const char* message, ...);
		static void success(const char* message, ...);
		static void warn(const char* message, ...);
		static void error(const char* message, ...);
		static void debug(const char* message, ...);

		static void reset_color();

#ifdef _WIN32
		static void set_color(WORD color);
#elif defined(_POSIX)
		static void set_color(const char* color);
#endif

		static void set_verbose(bool enabled);

	private:
		static bool verbose;

#ifdef _WIN32
		static HANDLE get_console_handle();
#endif

		static const char* format(va_list* ap, const char* message);
	};
}
