#include "std_include.hpp"

namespace utils
{
	void set_environment()
	{
		wchar_t exeName[512];
		GetModuleFileName(GetModuleHandle(nullptr), exeName, sizeof(exeName) / 2);

		wchar_t* exeBaseName = wcsrchr(exeName, L'\\');
		exeBaseName[0] = L'\0';

		SetCurrentDirectory(exeName);
	}
}
