/*
 * Copyright (c) Atmosphère-NX
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <stratosphere.hpp>
#include "hactool_options.hpp"

namespace ams::fssrv::impl {

    const char *GetWorkingDirectoryPath();

}

namespace ams::hactool {

    namespace {

        bool CreateFilePath(const char **out, const char *argument) {
            /* Allocate buffer for path. */
            const auto dst_size = std::strlen(argument) + fs::EntryNameLengthMax + 1;
            char *dst = static_cast<char *>(std::malloc(dst_size));
            ON_SCOPE_EXIT { std::free(dst); };
            if (dst == nullptr) {
                printf("Error: failed to allocate memory to hold path (%s)\n", argument);
                return false;
            }

            /* Print to path. */
            if (fs::IsPathAbsolute(argument)) {
                util::SNPrintf(dst, dst_size, "%s", argument);
            } else {
                util::SNPrintf(dst, dst_size, "%s%s", fssrv::impl::GetWorkingDirectoryPath(), argument);
            }

            /* Normalize path. */
            char *normalized = static_cast<char *>(std::malloc(dst_size));
            if (normalized == nullptr) {
                printf("Error: failed to allocate memory to hold path (%s)\n", argument);
                return false;
            }

            /* Check that the path is valid. */
            fs::PathFlags flags;
            flags.AllowWindowsPath();
            if (const auto res = fs::PathFormatter::Normalize(normalized, dst_size, dst, std::strlen(dst) + 1, flags); R_FAILED(res)) {
                printf("Error: failed to normalize path (%s): 2%03d-%04d\n", dst, res.GetModule(), res.GetDescription());
                return false;
            }

            /* Set output. */
            *out = normalized;
            return true;
        }

        bool ParseIntegerArgument(int *out, const char *argument) {
            char *parse_end = nullptr;
            const auto val = std::strtol(argument, std::addressof(parse_end), 0);
            if (parse_end != nullptr && parse_end != argument) {
                *out = val;
                return true;
            } else {
                return false;
            }
        }

        using OptionHandlerFunction = util::IFunction<bool(Options &, const char *)>;

        struct OptionHandler {
            char short_name;
            bool takes_arg;
            const char *name;
            u8 handler_storage[0x20];
            const OptionHandlerFunction &handler;

            OptionHandler(const char *n, char sn, bool ta, auto f) : short_name(sn), takes_arg(ta), name(n), handler(*reinterpret_cast<const decltype(OptionHandlerFunction::Make(f)) *>(handler_storage)) {
                using FunctionType = decltype(OptionHandlerFunction::Make(f));
                static_assert(sizeof(this->handler_storage) >= sizeof(FunctionType));
                std::construct_at(reinterpret_cast<FunctionType *>(this->handler_storage), OptionHandlerFunction::Make(f));
            }
        };

        template<typename T>
        concept NotCharacterOverloadHelper = !std::convertible_to<char, T>;

        OptionHandler MakeOptionHandler(const char *s, char sn, auto f) {
            if constexpr (requires { f(std::declval<Options &>(), std::declval<const char *>()); }) {
                if constexpr (std::convertible_to<decltype(f(std::declval<Options &>(), std::declval<const char *>())), bool>) {
                    return OptionHandler(s, sn, true, f);
                } else {
                    return OptionHandler(s, sn, true, [&] (Options &options, const char *arg) -> bool { f(options, arg); return true; });
                }
            } else {
                if constexpr (std::convertible_to<decltype(f(std::declval<Options &>())), bool>) {
                    return OptionHandler(s, sn, false, [&] (Options &options, const char *) -> bool { return f(options); });
                } else {
                    return OptionHandler(s, sn, false, [&] (Options &options, const char *) -> bool { f(options); return true; });
                }
            }
        }

        OptionHandler MakeOptionHandler(const char *s, NotCharacterOverloadHelper auto f) {
            return MakeOptionHandler(s, 0, f);
        }

        const OptionHandler OptionHandlers[] = {
            MakeOptionHandler("intype", 't', [] (Options &options, const char *arg) {
                if (std::strcmp(arg, "npdm") == 0) {
                    options.file_type = FileType::Npdm;
                } else if (std::strcmp(arg, "nca") == 0) {
                    options.file_type = FileType::Nca;
                } else if (std::strcmp(arg, "xci") == 0) {
                    options.file_type = FileType::Xci;
                } else if (std::strcmp(arg, "appfs") == 0) {
                    options.file_type = FileType::AppFs;
                } else if (std::strcmp(arg, "pfs") == 0 || std::strcmp(arg, "pfs0") == 0 || std::strcmp(arg, "nsp") == 0) {
                    options.file_type = FileType::Pfs;
                } else {
                    return false;
                }

                return true;
            }),
            MakeOptionHandler("dev", 'd', [] (Options &options) { options.dev = true; }),
            MakeOptionHandler("verify", 'y', [] (Options &options) { options.verify = true; }),
            MakeOptionHandler("raw", 'r', [] (Options &options) { options.raw = true; }),
            MakeOptionHandler("enablehash", 'h', [] (Options &options) { options.enable_hash = true; }),
            MakeOptionHandler("disablekeywarns", [] (Options &options) { options.disable_key_warns = true; }),
            MakeOptionHandler("onlyupdated", [] (Options &options) { options.only_updated = true; }),
            MakeOptionHandler("keyset", 'k', [] (Options &options, const char *arg) { return CreateFilePath(std::addressof(options.key_file_path), arg); }),
            MakeOptionHandler("titlekeys", [] (Options &options, const char *arg) { return CreateFilePath(std::addressof(options.titlekey_path), arg); }),
            MakeOptionHandler("consolekeys", [] (Options &options, const char *arg) { return CreateFilePath(std::addressof(options.consolekey_path), arg); }),
            MakeOptionHandler("section0", [] (Options &options, const char *arg) { return CreateFilePath(std::addressof(options.section_out_file_paths[0]), arg); }),
            MakeOptionHandler("section1", [] (Options &options, const char *arg) { return CreateFilePath(std::addressof(options.section_out_file_paths[1]), arg); }),
            MakeOptionHandler("section2", [] (Options &options, const char *arg) { return CreateFilePath(std::addressof(options.section_out_file_paths[2]), arg); }),
            MakeOptionHandler("section3", [] (Options &options, const char *arg) { return CreateFilePath(std::addressof(options.section_out_file_paths[3]), arg); }),
            MakeOptionHandler("section0dir", [] (Options &options, const char *arg) { return CreateFilePath(std::addressof(options.section_out_dir_paths[0]), arg); }),
            MakeOptionHandler("section1dir", [] (Options &options, const char *arg) { return CreateFilePath(std::addressof(options.section_out_dir_paths[1]), arg); }),
            MakeOptionHandler("section2dir", [] (Options &options, const char *arg) { return CreateFilePath(std::addressof(options.section_out_dir_paths[2]), arg); }),
            MakeOptionHandler("section3dir", [] (Options &options, const char *arg) { return CreateFilePath(std::addressof(options.section_out_dir_paths[3]), arg); }),
            MakeOptionHandler("header", [] (Options &options, const char *arg) { return CreateFilePath(std::addressof(options.header_out_path), arg); }),
            MakeOptionHandler("exefs", [] (Options &options, const char *arg) { return CreateFilePath(std::addressof(options.exefs_out_file_path), arg); }),
            MakeOptionHandler("romfs", [] (Options &options, const char *arg) { return CreateFilePath(std::addressof(options.romfs_out_file_path), arg); }),
            MakeOptionHandler("exefsdir", [] (Options &options, const char *arg) { return CreateFilePath(std::addressof(options.exefs_out_dir_path), arg); }),
            MakeOptionHandler("romfsdir", [] (Options &options, const char *arg) { return CreateFilePath(std::addressof(options.romfs_out_dir_path), arg); }),
            MakeOptionHandler("outdir", [] (Options &options, const char *arg) { return CreateFilePath(std::addressof(options.default_out_dir_path), arg); }),
            MakeOptionHandler("outfile", [] (Options &options, const char *arg) { return CreateFilePath(std::addressof(options.default_out_file_path), arg); }),
            MakeOptionHandler("plaintext", [] (Options &options, const char *arg) { return CreateFilePath(std::addressof(options.plaintext_out_path), arg); }),
            MakeOptionHandler("ciphertext", [] (Options &options, const char *arg) { return CreateFilePath(std::addressof(options.ciphertext_out_path), arg); }),
            MakeOptionHandler("json", [] (Options &options, const char *arg) { return CreateFilePath(std::addressof(options.json_out_file_path), arg); }),
            MakeOptionHandler("rootdir", [] (Options &options, const char *arg) { return CreateFilePath(std::addressof(options.root_partition_out_dir), arg); }),
            MakeOptionHandler("securedir", [] (Options &options, const char *arg) { return CreateFilePath(std::addressof(options.secure_partition_out_dir), arg); }),
            MakeOptionHandler("normaldir", [] (Options &options, const char *arg) { return CreateFilePath(std::addressof(options.normal_partition_out_dir), arg); }),
            MakeOptionHandler("updatedir", [] (Options &options, const char *arg) { return CreateFilePath(std::addressof(options.update_partition_out_dir), arg); }),
            MakeOptionHandler("logodir", [] (Options &options, const char *arg) { return CreateFilePath(std::addressof(options.logo_partition_out_dir), arg); }),
            MakeOptionHandler("basenca", [] (Options &options, const char *arg) { return CreateFilePath(std::addressof(options.base_nca_path), arg); }),
            MakeOptionHandler("basexci", [] (Options &options, const char *arg) { return CreateFilePath(std::addressof(options.base_xci_path), arg); }),
            MakeOptionHandler("basepfs", [] (Options &options, const char *arg) { return CreateFilePath(std::addressof(options.base_pfs_path), arg); }),
            MakeOptionHandler("basensp", [] (Options &options, const char *arg) { return CreateFilePath(std::addressof(options.base_pfs_path), arg); }),
            MakeOptionHandler("baseappfs", [] (Options &options, const char *arg) { return CreateFilePath(std::addressof(options.base_appfs_path), arg); }),
            MakeOptionHandler("listromfs", [] (Options &options) { options.list_romfs = true; }),
            MakeOptionHandler("listupdate", [] (Options &options) { options.list_update = true; }),
            MakeOptionHandler("appindex", [] (Options &options, const char *arg) { return ParseIntegerArgument(std::addressof(options.preferred_app_index), arg); }),
            MakeOptionHandler("programindex", [] (Options &options, const char *arg) { return ParseIntegerArgument(std::addressof(options.preferred_program_index), arg); }),
            MakeOptionHandler("appversion", [] (Options &options, const char *arg) { return ParseIntegerArgument(std::addressof(options.preferred_version), arg); }),
            MakeOptionHandler("updatedsince", [] (Options &options, const char *arg) { return ParseIntegerArgument(std::addressof(options.updated_generation), arg); }),
        };

    }

    void PrintUsage() {
        printf("hac2l (c) SciresM/Atmosphere-NX\n");
        printf("\n");
        printf("Usage: hac2l [options...] path\n");
        printf("Full usage print remains TODO\n");
    }

    const char *GetKeysFilePath(const char *fn) {
        /* Declare path buffers. */
        fs::Path path;

        /* Try to find an environment variable. */
        char *home = getenv("HOME");
        if (home == nullptr) {
            home = getenv("USERPROFILE");
        }
        if (home != nullptr) {
            if (!fs::IsPathAbsolute(home)) {
                printf("Warning: home path (%s) is not absolute, ignoring.\n", home);
                return nullptr;
            }

            if (const auto res = path.Initialize(home); R_FAILED(res)) {
                printf("Warning: Failed to initialize home path (%s): 2%03d-%04d\n", home, res.GetModule(), res.GetDescription());
                return nullptr;
            }

            /* Normalize the path. */
            fs::PathFlags flags;
            flags.AllowWindowsPath();
            if (const auto res = path.Normalize(flags); R_FAILED(res)) {
                printf("Warning: Failed to normalize home path (%s): 2%03d-%04d\n", home, res.GetModule(), res.GetDescription());
                return nullptr;
            }

            /* Append .switch. */
            if (const auto res = path.AppendChild(".switch"); R_FAILED(res)) {
                printf("Warning: failed to append .switch to path (%s): 2%03d-%04d\n", path.GetString(), res.GetModule(), res.GetDescription());
                return nullptr;
            }

            /* Append fn. */
            if (const auto res = path.AppendChild(fn); R_FAILED(res)) {
                printf("Warning: failed to append %s to path (%s): 2%03d-%04d\n", fn, path.GetString(), res.GetModule(), res.GetDescription());
                return nullptr;
            }
        }

        /* If the path isn't empty, check if the file exists. */
        if (!path.IsEmpty()) {
            bool has_file = false;
            if (const auto res = fs::HasFile(std::addressof(has_file), path.GetString()); R_FAILED(res)) {
                printf("Warning: failed to check if path exists (%s): 2%03d-%04d\n", path.GetString(), res.GetModule(), res.GetDescription());
            } else if (has_file) {
                return ::strdup(path.GetString());
            }
        }

        /* We couldn't use {home}/.switch/{fn}. Try using xdg home. */
        char *xdg = getenv("XDG_CONFIG_HOME");
        if (xdg != nullptr) {
            if (!fs::IsPathAbsolute(xdg)) {
                printf("Warning: xdg path (%s) is not absolute, ignoring.\n", xdg);
                return nullptr;
            }

            if (const auto res = path.Initialize(xdg); R_FAILED(res)) {
                printf("Warning: Failed to initialize xdg path (%s): 2%03d-%04d\n", xdg, res.GetModule(), res.GetDescription());
                return nullptr;
            }

            /* Normalize the path. */
            fs::PathFlags flags;
            flags.AllowWindowsPath();
            if (const auto res = path.Normalize(flags); R_FAILED(res)) {
                printf("Warning: Failed to normalize xdg path (%s): 2%03d-%04d\n", xdg, res.GetModule(), res.GetDescription());
                return nullptr;
            }
        } else if (!path.IsEmpty()) {
            /* Path is already initialized with <home>/.switch/<fn>, try <home>/.config/switch/<fn>. */
            R_ABORT_UNLESS(path.RemoveChild());
            R_ABORT_UNLESS(path.RemoveChild());

            /* Append .config. */
            if (const auto res = path.AppendChild(".config"); R_FAILED(res)) {
                printf("Warning: failed to append .config to path (%s): 2%03d-%04d\n", path.GetString(), res.GetModule(), res.GetDescription());
                return nullptr;
            }
        }

        /* If the path isn't empty, format the remaining path segments and check if the file exists. */
        if (!path.IsEmpty()) {
            /* Append switch. */
            if (const auto res = path.AppendChild("switch"); R_FAILED(res)) {
                printf("Warning: failed to append switch to path (%s): 2%03d-%04d\n", path.GetString(), res.GetModule(), res.GetDescription());
                return nullptr;
            }

            /* Append fn. */
            if (const auto res = path.AppendChild(fn); R_FAILED(res)) {
                printf("Warning: failed to append %s to path (%s): 2%03d-%04d\n", fn, path.GetString(), res.GetModule(), res.GetDescription());
                return nullptr;
            }

            bool has_file = false;
            if (const auto res = fs::HasFile(std::addressof(has_file), path.GetString()); R_FAILED(res)) {
                printf("Warning: failed to check if path exists (%s): 2%03d-%04d\n", path.GetString(), res.GetModule(), res.GetDescription());
            } else if (has_file) {
                return ::strdup(path.GetString());
            }
        }

        /* We couldn't find a path. */
        return nullptr;
    }

    Options ParseOptionsFromCommandLine() {
        /* Create default options. */
        Options options{};

        /* Get argc/argv. */
        const auto argc = os::GetHostArgc();
        const auto argv = os::GetHostArgv();

        /* Parse all arguments. */
        for (auto i = 1; i < argc; ++i) {
            /* Get the current argument length. */
            const auto *arg    = argv[i];
            const auto arg_len = std::strlen(arg);

            bool success = false;
            if (arg[0] == '-' && arg[1] != '-') {
                for (const auto &o : OptionHandlers) {
                    if (arg[1] != o.short_name) {
                        continue;
                    }

                    if (o.takes_arg) {
                        if (arg_len > 2) {
                            success = o.handler(options, arg + 2);
                        } else {
                            ++i;
                            success = i < argc && o.handler(options, argv[i]);
                        }
                    } else {
                        success = o.handler(options, nullptr);
                    }

                    break;
                }
            } else if (arg[0] == '-' && arg[1] == '-') {
                for (const auto &o : OptionHandlers) {
                    const auto o_len = std::strlen(o.name);
                    if (arg_len < o_len + 2 || std::memcmp(arg + 2, o.name, o_len) != 0 || (arg[2 + o_len] != 0 && arg[2 + o_len] != '=')) {
                        continue;
                    }

                    if (o.takes_arg) {
                        if (arg[2 + o_len] == '=') {
                            success = o.handler(options, arg + 2 + o_len + 1);
                        } else {
                            ++i;
                            success = i < argc && o.handler(options, argv[i]);
                        }
                    } else {
                        success = o.handler(options, nullptr);
                    }

                    break;
                }
            } else if (options.in_file_path == nullptr) {
                success = CreateFilePath(std::addressof(options.in_file_path), arg);
            }

            if (!success) {
                fprintf(stderr, "[Warning]: An error occurred while parsing option (%s)\n", arg);
                return options;
            }
        }

        /* Try to ensure key files are valid. */
        if (options.key_file_path == nullptr) {
            options.key_file_path = GetKeysFilePath(options.dev ? "dev.keys" : "prod.keys");
        }
        if (options.titlekey_path == nullptr) {
            options.titlekey_path = GetKeysFilePath("title.keys");
        }
        if (options.consolekey_path == nullptr) {
            options.consolekey_path = GetKeysFilePath("console.keys");
        }

        /* If we have an input file, we're valid. */
        options.valid = options.in_file_path != nullptr;
        return options;
    }
}