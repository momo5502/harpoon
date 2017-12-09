#pragma once

#define STD_INCLUDED

#ifndef RC_INVOKED

#define _HAS_CXX17 1
#define VC_EXTRALEAN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <assert.h>
#include <conio.h>

#include <WinSock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "ntdll.lib")

#include <string>
#include <mutex>
#include <fstream>

#include <../win32/libnet.h>

#include "utils/nt.hpp"
#include "utils/utils.hpp"
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
