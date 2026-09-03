-- Vetted versions of a tool, oldest first, from `omapac tools list`.
--
-- Options (mise.toml tool options, or the environment as a fallback):
--   channel  edge | rc | stable (default stable); OMAPAC_TOOLS_CHANNEL
--   base     the channel store URL; OMAPAC_TOOLS_BASE; else omapac's own
--            [channel] tools_base setting
--   pubkey   a minisign public key file; OMAPAC_TOOLS_PUBKEY; else the
--            keys under /etc/omapac/keys
function PLUGIN:BackendListVersions(ctx)
    local cmd = require("cmd")
    local strings = require("strings")
    local options = ctx.options or {}

    local channel = options.channel or os.getenv("OMAPAC_TOOLS_CHANNEL") or "stable"
    local command = "omapac tools" .. self:channel_flags(options)
        .. " list " .. self:quote(ctx.tool) .. " --channel " .. self:quote(channel)
    local ok, output = pcall(cmd.exec, command)
    if not ok then
        error("tool channel: " .. tostring(output))
    end

    local versions = {}
    for _, line in ipairs(strings.split(output, "\n")) do
        local version = strings.trim_space(line)
        if version ~= "" then
            table.insert(versions, version)
        end
    end
    if #versions == 0 then
        error("tool channel: no vetted versions of " .. ctx.tool .. " in " .. channel)
    end
    return { versions = versions }
end

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
