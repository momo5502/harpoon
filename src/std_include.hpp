#pragma once

#define STD_INCLUDED

#ifndef RC_INVOKED

#define _HAS_CXX17 1
#define VC_EXTRALEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <assert.h>
#include <conio.h>

#include <WinSock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "ntdll.lib")

#elif defined(_LINUX) || defined(_MACOSX)

#define _POSIX

#include <stdio.h>
#include <stdarg.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/ip.h>

typedef void* PVOID;
typedef unsigned short WORD;
typedef unsigned long DWORD, ULONG;
typedef unsigned char BYTE;
typedef bool BOOL;
typedef unsigned int* PUINT32;
typedef int INT;
typedef unsigned int UINT, SOCKET;
typedef unsigned long long UINT64;
typedef char* LPSTR;

#define ARRAYSIZE(x) (sizeof(x) / sizeof(x[0]))

#define TRUE true
#define FALSE false

#define SOCKET_ERROR -1

#define ZeroMemory(src, size) memset(src, 0, size)

#endif

#include <string>
#include <mutex>
#include <fstream>

#include <../win32/libnet.h>

#include "utils/nt.hpp"
#include "utils/utils.hpp"
#include "utils/logger.hpp"
#include "utils/memory.hpp"
#include "utils/signal_handler.hpp"

using namespace std::literals;

#endif

// Resource stuff
#ifdef APSTUDIO_INVOKED
#ifndef APSTUDIO_READONLY_SYMBOLS
// Defines below make accessing the resources from the code easier.
#define _APS_NEXT_RESOURCE_VALUE        102
#define _APS_NEXT_COMMAND_VALUE         40001
#define _APS_NEXT_CONTROL_VALUE         1001
#define _APS_NEXT_SYMED_VALUE           101
#endif
#endif

// Resources
#define IDI_ICON            102
