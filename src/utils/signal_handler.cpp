#include "std_include.hpp"

namespace utils
{
	std::mutex signal_handler::mutex;
	signal_handler* signal_handler::instance;

#ifdef _WIN32
	BOOL WINAPI signal_handler::handler(DWORD signal)
	{
		if ((signal == CTRL_C_EVENT || signal == CTRL_CLOSE_EVENT) && signal_handler::instance && signal_handler::instance->callback)
		{
			signal_handler::instance->callback();
		}

		return TRUE;
	}

#elif defined(_POSIX)
	void signal_handler::handler(int signal)
	{
		if (signal == SIGINT && signal_handler::instance && signal_handler::instance->callback)
		{
			signal_handler::instance->callback();
		}
	}
#endif

	signal_handler::signal_handler(std::function<void()> _callback) : std::lock_guard<std::mutex>(signal_handler::mutex), callback(_callback)
	{
#ifdef _WIN32
		SetConsoleCtrlHandler(signal_handler::handler, TRUE);
#elif defined(_POSIX)
		signal(SIGINT, signal_handler::handler);
#endif

		signal_handler::instance = this;
	}

	signal_handler::~signal_handler()
	{
#ifdef _WIN32
		SetConsoleCtrlHandler(signal_handler::handler, FALSE);
#elif defined(_POSIX)
		signal(SIGINT, SIG_DFL);
#endif

		signal_handler::instance = nullptr;
	}
}
