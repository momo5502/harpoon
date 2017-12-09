depsBasePath = "./deps"

require "premake/npcap"
require "premake/libnet"

npcap.setup
{
	source = path.join(depsBasePath, "npcap"),
}
libnet.setup
{
	defines = {
		"BPF_MAJOR_VERSION",
		"WIN32_ALTERNATE_INCLUDES"
	},
	source = path.join(depsBasePath, "libnet"),
}

-- cppdialect but with a fix for GCC for C++17
function cppdialect_fixed(dialect)
	if dialect == "C++17" then
		filter "toolset:gcc*"
			buildoptions {
				"-std=c++17"
			}
		filter "toolset:msc*"
			buildoptions {
				"/std:c++latest"
			}
		filter {}
	else
		cppdialect(dialect)
	end
end

workspace "harpoon"
	configurations { "Debug", "Release" }
	platforms { "Win32", "Win64", "WinARM" }

	filter "action:not vs*"
		platforms { "Linux32", "Linux64", "LinuxARM", "MacOSX32", "MacOSX64" }
	filter {}
		
	project "harpoon"
		kind "ConsoleApp"
		language "C++"
		cppdialect_fixed "C++17"
		files {
			"./src/**.hpp",
			"./src/**.cpp",
		}
		includedirs {
			"%{prj.location}/src",
			"./src",
			"./src",
		}

		filter "system:windows"
			files {
				"./src/node/**.rc",
			}
			resincludedirs {
				"$(ProjectDir)src" -- fix for VS IDE
			}
			links {
				"ws2_32",
				"shell32",
				"ntdll",
				"iphlpapi"
			}
		filter {}
		
		filter "action:vs*"
			linkoptions {
				"/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\""
			}
		filter {}

		-- Pre-compiled header
		pchheader "std_include.hpp" -- must be exactly same as used in #include directives
		pchsource "src/std_include.cpp" -- real path

		-- Specific configurations
		flags { "UndefinedIdentifiers" }
		warnings "Extra"
		symbols "On"

		configuration "Release*"
			flags {
				"FatalCompileWarnings",
				"FatalLinkWarnings",
			}
		configuration {}
		
		npcap.import()
		libnet.import()
		
	group "External dependencies"
		npcap.project()
		libnet.project()

workspace "*"
	location "./build"
	objdir "%{wks.location}/obj"
	targetdir "%{wks.location}/bin/%{cfg.platform}/%{cfg.buildcfg}"
	buildlog "%{wks.location}/obj/%{cfg.architecture}/%{cfg.buildcfg}/%{prj.name}/%{prj.name}.log"

	largeaddressaware "on"
	
	if _OPTIONS["toolset"] then
		toolset(_OPTIONS["toolset"])
	end

	filter "toolset:msc*"
		buildoptions { "/utf-8", "/Zm200" }

	filter "toolset:gcc*"
		links {
			"stdc++fs"
		}
	
	filter "platforms:*32"
		architecture "x86"
	
	filter "platforms:*64"
		architecture "x86_64"
	
	filter "platforms:*ARM"
		architecture "arm"
	
	filter "platforms:Win*"
		system "windows"
		defines { "_WINDOWS" }
	
	filter "platforms:linux*"
		system "linux"
		defines { "_LINUX" }
	
	filter "platforms:macos*"
		system "macosx"
		defines { "_MACOSX" }

	filter {}

	flags {
		"StaticRuntime",
		"NoIncrementalLink",
		"NoMinimalRebuild",
		"MultiProcessorCompile",
		"No64BitChecks",
	}
	editandcontinue "Off"

	configuration "Release*"
		defines { "NDEBUG" }
		optimize "On"

	configuration "Debug*"
		defines { "DEBUG", "_DEBUG" }
		optimize "Debug"
		symbols "On"