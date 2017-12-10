#include "std_include.hpp"

namespace utils
{
	std::recursive_mutex logger::mutex;
	bool logger::verbose = false;

	void logger::set_verbose(bool enabled)
	{
		std::lock_guard<std::recursive_mutex> _(logger::mutex);
		logger::verbose = enabled;
	}

	void logger::set_title(std::string title)
	{
		std::lock_guard<std::recursive_mutex> _(logger::mutex);

#ifdef _WIN32
		SetConsoleTitleA(title.data());
#elif defined(_POSIX)
		printf("\033]0;%s\007", title.data());
		fflush(stdout);
#endif
	}

	void logger::info(const char* message, ...)
	{
		std::lock_guard<std::recursive_mutex> _(logger::mutex);

		va_list ap;
		va_start(ap, message);

		logger::set_color(COLOR_LOG_INFO);
		printf("[*] %s\n", logger::format(&ap, message));

		va_end(ap);

		fflush(stdout);
	}

	void logger::success(const char* message, ...)
	{
		std::lock_guard<std::recursive_mutex> _(logger::mutex);

		va_list ap;
		va_start(ap, message);

		logger::set_color(COLOR_LOG_SUCCESS);
		printf("[+] %s\n", logger::format(&ap, message));

		va_end(ap);

		fflush(stdout);
	}

	void logger::warn(const char* message, ...)
	{
		std::lock_guard<std::recursive_mutex> _(logger::mutex);

		va_list ap;
		va_start(ap, message);

		logger::set_color(COLOR_LOG_WARN);
		printf("[!] %s\n", logger::format(&ap, message));

		va_end(ap);

		fflush(stdout);
	}

	void logger::error(const char* message, ...)
	{
		std::lock_guard<std::recursive_mutex> _(logger::mutex);

		va_list ap;
		va_start(ap, message);

		logger::set_color(COLOR_LOG_ERROR);
		printf("[-] %s\n", logger::format(&ap, message));

		va_end(ap);

		fflush(stdout);
	}

	void logger::debug(const char* message, ...)
	{
		std::lock_guard<std::recursive_mutex> _(logger::mutex);

		if (logger::verbose)
		{
			va_list ap;
			va_start(ap, message);

			logger::set_color(COLOR_LOG_DEBUG);
			printf("[*] %s\n", logger::format(&ap, message));

			va_end(ap);

			fflush(stdout);
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
		fflush(stdout);
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
