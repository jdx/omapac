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
            local source = file.join_path(ctx.install_path, exe)
            -- The requested executable can already be bin/<tool>. In that
            -- case it is the target itself, so replacing it would delete the
            -- artifact and create a self-referential symlink.
            if source ~= target then
                if file.exists(target) then
                    cmd.exec("rm -f -- " .. self:quote(target))
                end
                file.symlink(source, target)
            end
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
        if self:is_regular_file(file.join_path(install_path, candidate)) then
            return candidate
        end
    end
    local bin = file.join_path(install_path, "bin")
    local bin_stat = file.stat(bin)
    if bin_stat ~= nil and bin_stat.is_dir then
        local entries = file.list(bin)
        if #entries == 1 then
            -- file.list returns the full path. Convert it back to the path
            -- relative to install_path expected by the symlink code above.
            local entry = entries[1]
            local entry_path = entry
            if entry:sub(1, #install_path) ~= install_path then
                entry_path = file.join_path(bin, entry)
            end
            if not self:is_regular_file(entry_path) then
                return nil
            end
            if entry:sub(1, #install_path) == install_path then
                return entry:sub(#install_path + 1):gsub("^[/\\]+", "")
            end
            -- Retain compatibility with runtimes that return basenames.
            return file.join_path("bin", entry)
        end
    end
    return nil
end

-- Follow symlinks when checking an executable candidate. mise's file.stat
-- reports symlink metadata, so its is_file field is false for common vendor
-- layouts such as bin/npm -> ../lib/node_modules/npm/bin/npm-cli.js.
function PLUGIN:is_regular_file(path)
    local cmd = require("cmd")
    return pcall(cmd.exec, "test -f " .. self:quote(path))
end
