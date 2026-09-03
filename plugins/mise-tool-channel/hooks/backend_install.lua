-- Fetch a vetted artifact through `omapac tools fetch`, which verifies the
-- index signature, the digest, the vendor packslip, and the channel
-- provenance, then lay it out for mise.
--
-- Options:
--   platform  override the mise platform, such as linux-x64
--   exe       the executable inside the archive to expose as the tool
--             name (default: a file named after the tool, or the only
--             executable at the root or under bin/)
--   strip     strip this many leading path components when extracting
--             (default 1 when the archive has a single top-level directory)
function PLUGIN:BackendInstall(ctx)
    local cmd = require("cmd")
    local json = require("json")
    local file = require("file")
    local archiver = require("archiver")
    local options = ctx.options or {}

    local platform = options.platform or self:platform()
    local command = "omapac tools" .. self:channel_flags(options)
        .. " fetch " .. self:quote(ctx.tool) .. " " .. self:quote(ctx.version)
        .. " --platform " .. self:quote(platform)
        .. " --dest " .. self:quote(ctx.download_path) .. " --json"
    local ok, output = pcall(cmd.exec, command)
    if not ok then
        error("tool channel: " .. tostring(output))
    end
    local report = json.decode(output)
    local artifact = report.path
    local name = report.name or ""

    local bin_dir = file.join_path(ctx.install_path, "bin")
    if self:is_archive(name) then
        local strip = options.strip
        if strip == nil then
            strip = 1
        else
            strip = tonumber(strip)
            if strip ~= 0 and strip ~= 1 then
                error("tool channel: strip must be 0 or 1")
            end
        end
        archiver.decompress(artifact, ctx.install_path, { strip_components = strip })
        local exe = options.exe or self:find_executable(ctx.install_path, ctx.tool)
        if exe == nil then
            error("tool channel: no executable named " .. ctx.tool .. " in " .. name .. "; set the exe option")
        end
        local target = file.join_path(bin_dir, ctx.tool)
        if options.exe ~= nil then
            cmd.exec("mkdir -p " .. self:quote(bin_dir))
            if file.exists(target) then
                cmd.exec("rm -f -- " .. self:quote(target))
            end
            file.symlink(file.join_path(ctx.install_path, exe), target)
        elseif not file.exists(target) then
            cmd.exec("mkdir -p " .. self:quote(bin_dir))
            file.symlink(file.join_path(ctx.install_path, exe), target)
        end
        cmd.exec("chmod +x " .. self:quote(target))
    else
        -- A bare binary.
        cmd.exec("mkdir -p " .. self:quote(bin_dir))
        local target = file.join_path(bin_dir, ctx.tool)
        file.move(artifact, target)
        cmd.exec("chmod +x " .. self:quote(target))
    end
    return {}
end

function PLUGIN:platform()
    local os_type = string.lower(RUNTIME.osType or "")
    if os_type == "darwin" then
        os_type = "macos"
    end
    local arch = string.lower(RUNTIME.archType or "")
    if arch == "amd64" or arch == "x86_64" then
        arch = "x64"
    elseif arch == "aarch64" then
        arch = "arm64"
    end
    return os_type .. "-" .. arch
end

function PLUGIN:is_archive(name)
    for _, suffix in ipairs({ ".tar.gz", ".tgz", ".tar.xz", ".tar.bz2", ".tar.zst", ".tzst", ".zip" }) do
        if name:sub(-#suffix) == suffix then
            return true
        end
    end
    return false
end

-- A path relative to install_path: <tool>, bin/<tool>, or the only file
-- under bin/.
function PLUGIN:find_executable(install_path, tool)
    local file = require("file")
    for _, candidate in ipairs({ tool, file.join_path("bin", tool) }) do
        if file.exists(file.join_path(install_path, candidate)) then
            return candidate
        end
    end
    local bin = file.join_path(install_path, "bin")
    if file.exists(bin) then
        local entries = file.list(bin)
        if #entries == 1 then
            -- file.list returns the full path. Convert it back to the path
            -- relative to install_path expected by the symlink code above.
            local entry = entries[1]
            if entry:sub(1, #install_path) == install_path then
                return entry:sub(#install_path + 1):gsub("^[/\\]+", "")
            end
            -- Retain compatibility with runtimes that return basenames.
            return file.join_path("bin", entry)
        end
    end
    return nil
end
