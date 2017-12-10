nuklear = {
	settings = nil
}

function nuklear.setup(settings)
	if not settings.source then error("Missing source.") end

	nuklear.settings = settings

	if not nuklear.settings.defines then nuklear.settings.defines = {} end
end

function nuklear.import()
	if not nuklear.settings then error("You need to call nuklear.setup first") end

	nuklear.includes()
end

function nuklear.includes()
	if not nuklear.settings then error("You need to call nuklear.setup first") end

	includedirs {
		nuklear.settings.source,
		path.join(nuklear.settings.source, "demo/d3d11")
	}
	defines(nuklear.settings.defines)
end

function nuklear.project()
	if not nuklear.settings then error("You need to call nuklear.setup first") end
end