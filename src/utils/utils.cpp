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

#ifdef _WIN32
	std::string load_resource(int resId)
	{
		HRSRC res = FindResource(GetModuleHandleA(nullptr), MAKEINTRESOURCE(resId), RT_RCDATA);
		if (!res) return "";

		HGLOBAL handle = LoadResource(nullptr, res);
		if (!handle) return "";

		return std::string(LPSTR(LockResource(handle)), SizeofResource(nullptr, res));
	}
#endif
}
