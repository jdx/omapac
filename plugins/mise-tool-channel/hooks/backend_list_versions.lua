-- Vetted versions of a tool, oldest first, from `pacvamp tools list`.
--
-- Options (mise.toml tool options, or the environment as a fallback):
--   channel  edge | rc | stable (default stable); PACVAMP_TOOLS_CHANNEL
--   base     the channel store URL; PACVAMP_TOOLS_BASE; else pacvamp's own
--            [channel] tools_base setting
--   pubkey   a minisign public key file; PACVAMP_TOOLS_PUBKEY; else the
--            keys under /etc/pacvamp/keys
function PLUGIN:BackendListVersions(ctx)
    local cmd = require("cmd")
    local strings = require("strings")
    local options = ctx.options or {}

    local channel = options.channel or os.getenv("PACVAMP_TOOLS_CHANNEL") or "stable"
    local command = "pacvamp tools" .. self:channel_flags(options)
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
