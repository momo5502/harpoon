libnet = {
	settings = nil
}

function libnet.setup(settings)
	if not settings.source then error("Missing source.") end

	libnet.settings = settings

	if not libnet.settings.defines then libnet.settings.defines = {} end
end

function libnet.import()
	if not libnet.settings then error("You need to call libnet.setup first") end

	links { "libnet" }
	libnet.includes()
end

function libnet.includes()
	if not libnet.settings then error("You need to call libnet.setup first") end

	includedirs {
		path.join(libnet.settings.source, "libnet/include"),
	}
	defines(libnet.settings.defines)
end

function libnet.project()
	if not libnet.settings then error("You need to call libnet.setup first") end
	
	project "libnet"
		language "C"

		libnet.includes()
		npcap.includes()
		files
		{
			path.join(libnet.settings.source, "libnet/src/*.c"),
		}
		removefiles
		{
			path.join(libnet.settings.source, "libnet/src/libnet_dll.c"),
			path.join(libnet.settings.source, "libnet/src/libnet_link_snoop.c"),
			path.join(libnet.settings.source, "libnet/src/libnet_link_snit.c"),
			path.join(libnet.settings.source, "libnet/src/libnet_link_nit.c"),
			path.join(libnet.settings.source, "libnet/src/libnet_link_pf.c"),
			path.join(libnet.settings.source, "libnet/src/libnet_link_bpf.c"),
			path.join(libnet.settings.source, "libnet/src/libnet_link_dlpi.c"),
			path.join(libnet.settings.source, "libnet/src/libnet_link_none.c"),
		}
		
		filter "platforms:Win*"
			removefiles
			{
				path.join(libnet.settings.source, "libnet/src/libnet_link_linux.c"),
			}
		filter "platforms:not Win*"
			removefiles
			{
				path.join(libnet.settings.source, "libnet/src/libnet_link_win32.c"),
			}
		filter {}
		
		-- not our code, ignore POSIX usage warnings for now
		warnings "Off"

		kind "StaticLib"
end