#pragma once

#ifndef STD_INCLUDED
#error "Missing standard header"
#endif

namespace utils
{
	class signal_handler : std::lock_guard<std::mutex>
	{
	public:
		signal_handler(std::function<void()> callback);
		~signal_handler();

	private:
		std::function<void()> callback;

		static std::mutex mutex;
		static signal_handler* instance;

#ifdef _WIN32
		static BOOL WINAPI handler(DWORD signal);
#elif defined(_POSIX)
		static void handler(int signal);
#endif
	};
}
