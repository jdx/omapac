PLUGIN = {
    name = "tool-channel",
    version = "0.1.0",
    description = "Installs vendor tools from a vetted omapac tool channel",
    author = "jdx",
}

-- Global flags for `omapac tools` from the options and environment.
function PLUGIN:channel_flags(options)
    local flags = ""
    local base = options.base or os.getenv("OMAPAC_TOOLS_BASE")
    if base and base ~= "" then
        flags = flags .. " --base " .. self:quote(base)
    end
    local pubkey = options.pubkey or os.getenv("OMAPAC_TOOLS_PUBKEY")
    if pubkey and pubkey ~= "" then
        flags = flags .. " --pubkey " .. self:quote(pubkey)
    end
    return flags
end

function PLUGIN:quote(value)
    return "'" .. tostring(value):gsub("'", "'\\''") .. "'"
end
