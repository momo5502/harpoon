#pragma once

#ifdef _WIN32
#define COLOR_LOG_INFO 11//15
#define COLOR_LOG_SUCCESS 10
#define COLOR_LOG_WARN 14
#define COLOR_LOG_ERROR 12
#define COLOR_LOG_DEBUG 15//7
#elif defined(_POSIX)
#define COLOR_LOG_INFO "\033[1;36;24;27m"//"\033[1;37;24;27m"
#define COLOR_LOG_SUCCESS "\033[1;92;24;27m"
#define COLOR_LOG_WARN "\033[1;33;24;27m"
#define COLOR_LOG_ERROR "\033[1;31;24;27m"
#define COLOR_LOG_DEBUG "\033[0m\033[1m"
#endif

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
		static std::recursive_mutex mutex;
		static bool verbose;

#ifdef _WIN32
		static HANDLE get_console_handle();
#endif

		static const char* format(va_list* ap, const char* message);
	};
}
