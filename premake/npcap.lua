npcap = {
	settings = nil
}

function npcap.setup(settings)
	if not settings.source then error("Missing source.") end

	npcap.settings = settings

	if not npcap.settings.defines then npcap.settings.defines = {} end
end

function npcap.import()
	if not npcap.settings then error("You need to call npcap.setup first") end

	filter "architecture:x86"
		libdirs { path.join(npcap.settings.source, "Lib") }
		
	filter "architecture:x64"
		libdirs { path.join(npcap.settings.source, "Lib/x64") }
	filter {}
	
	links { "wpcap", "Packet" }
	npcap.includes()
end

function npcap.includes()
	if not npcap.settings then error("You need to call npcap.setup first") end

	includedirs { path.join(npcap.settings.source, "Include") }
	defines(npcap.settings.defines)
end

function npcap.project()
	if not npcap.settings then error("You need to call npcap.setup first") end
end