depsBasePath = "./deps"

require "premake/divert"

divert.setup
{
	source = path.join(depsBasePath, "divert"),
}

workspace "harpoon"
	location "./build"
	objdir "%{wks.location}/obj"
	targetdir "%{wks.location}/bin/%{cfg.architecture}/%{cfg.buildcfg}"
	buildlog "%{wks.location}/obj/%{cfg.architecture}/%{cfg.buildcfg}/%{prj.name}/%{prj.name}.log"
	configurations { "Debug", "Release" }
	platforms { "x86", "x64" }
	
	buildoptions { "/std:c++latest", "/utf-8", "/Zm200" }
	systemversion "10.0.15063.0"

	flags { "StaticRuntime", "NoIncrementalLink", "NoEditAndContinue", "NoMinimalRebuild", "MultiProcessorCompile", "No64BitChecks" }

	configuration "windows"
		defines { "_WINDOWS", "WIN32" }

	configuration "Release*"
		defines { "NDEBUG" }
		optimize "On"

	configuration "Debug*"
		defines { "DEBUG", "_DEBUG" }
		optimize "Debug"
		symbols "On"
		
	project "harpoon"
		kind "ConsoleApp"
		language "C++"
		files {
			"./src/**.rc",
			"./src/**.hpp",
			"./src/**.cpp",
		}
		includedirs {
			"%{prj.location}/src",
			"./src",
			"./src",
		}
		resincludedirs {
			"$(ProjectDir)src" -- fix for VS IDE
		}
		
		filter "platforms:x64"
			defines { "X64" }
		filter {}

		-- Pre-compiled header
		pchheader "std_include.hpp" -- must be exactly same as used in #include directives
		pchsource "src/std_include.cpp" -- real path
		
		linkoptions {
			"/LARGEADDRESSAWARE",
			"/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\""
		}

		-- fix vpaths for protobuf sources
		vpaths
		{
			["*"] = { "./src/**" },
		}

		-- Specific configurations
		flags { "UndefinedIdentifiers" }
		warnings "Extra"

		if symbols ~= nil then
			symbols "On"
		else
			flags { "Symbols" }
		end

		configuration "Release*"
			flags {
				"FatalCompileWarnings",
				"FatalLinkWarnings",
			}
		configuration {}
		
		divert.import()
		
	group "External dependencies"
		divert.project()
