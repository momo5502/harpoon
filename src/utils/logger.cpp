#include "std_include.hpp"

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
	bool logger::verbose = false;

	void logger::set_verbose(bool enabled)
	{
		logger::verbose = enabled;
	}

	void logger::set_title(std::string title)
	{
#ifdef _WIN32
		SetConsoleTitleA(title.data());
#elif defined(_POSIX)
		printf("\033]0;%s\007", title.data());
		fflush(stdout);
#endif
	}

	void logger::info(const char* message, ...)
	{
		va_list ap;
		va_start(ap, message);

		logger::set_color(COLOR_LOG_INFO);
		printf("[*] %s\n", logger::format(&ap, message));

		va_end(ap);
	}

	void logger::success(const char* message, ...)
	{
		va_list ap;
		va_start(ap, message);

		logger::set_color(COLOR_LOG_SUCCESS);
		printf("[+] %s\n", logger::format(&ap, message));

		va_end(ap);
	}

	void logger::warn(const char* message, ...)
	{
		va_list ap;
		va_start(ap, message);

		logger::set_color(COLOR_LOG_WARN);
		printf("[!] %s\n", logger::format(&ap, message));

		va_end(ap);
	}

	void logger::error(const char* message, ...)
	{
		va_list ap;
		va_start(ap, message);

		logger::set_color(COLOR_LOG_ERROR);
		printf("[-] %s\n", logger::format(&ap, message));

		va_end(ap);
	}

	void logger::debug(const char* message, ...)
	{
		if (logger::verbose)
		{
			va_list ap;
			va_start(ap, message);

			logger::set_color(COLOR_LOG_DEBUG);
			printf("[*] %s\n", logger::format(&ap, message));

			va_end(ap);
		}
	}

#ifdef _WIN32
	HANDLE logger::get_console_handle()
	{
		return GetStdHandle(STD_OUTPUT_HANDLE);
	}
#endif

#ifdef _WIN32
	void logger::set_color(WORD color)
	{
		SetConsoleTextAttribute(logger::get_console_handle(), color);
	}
#elif defined(_POSIX)
	void logger::set_color(const char* color)
	{
		printf("%s", color);
	}
#endif

	void logger::reset_color()
	{
#ifdef _WIN32
		SetConsoleTextAttribute(logger::get_console_handle(), 7);
#elif defined(_POSIX)
		printf("\033[0m");
#endif

		fflush(stdout);
	}

	const char* logger::format(va_list* ap, const char* message)
	{
		static thread_local char buffer[0x1000];

#ifdef _WIN32
		_vsnprintf_s(buffer, sizeof(buffer), sizeof(buffer), message, *ap);
#else
		vsnprintf(buffer, sizeof(buffer), message, *ap);
#endif

		return buffer;
	}
}
