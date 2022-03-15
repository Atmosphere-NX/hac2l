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
#pragma once
#include <stratosphere.hpp>

namespace ams::hactool {

    enum class FileType {
        Nca,
        Pfs,
        Romfs,
        Nax,
        Xci,
        Keygen,
        Pk11,
        Pk21,
        Kip,
        Ini,
        Npdm,
    };

    struct Options {
        const char *in_file_path = nullptr;
        FileType file_type = FileType::Nca;
        bool valid = false;
        bool raw = false;
        bool verify = false;
        bool dev = false;
        bool enable_hash = false;
        bool disable_key_warns = false;
        const char *key_file_path = nullptr;
        const char *titlekey_path = nullptr;
        const char *consolekey_path = nullptr;
        const char *section_out_file_paths[4] = { nullptr, nullptr, nullptr, nullptr };
        const char *section_out_dir_paths[4] = { nullptr, nullptr, nullptr, nullptr };
        const char *header_out_path = nullptr;
        const char *exefs_out_file_path = nullptr;
        const char *exefs_out_dir_path = nullptr;
        const char *romfs_out_file_path = nullptr;
        const char *romfs_out_dir_path = nullptr;
        const char *ini_out_dir_path = nullptr;
        const char *default_out_dir_path = nullptr;
        const char *default_out_file_path = nullptr;
        const char *plaintext_out_path = nullptr;
        const char *ciphertext_out_path = nullptr;
        const char *uncompressed_out_path = nullptr;
        const char *json_out_file_path = nullptr;
        const char *root_partition_out_dir = nullptr;
        const char *update_partition_out_dir = nullptr;
        const char *normal_partition_out_dir = nullptr;
        const char *logo_partition_out_dir = nullptr;
        const char *secure_partition_out_dir = nullptr;
        bool list_romfs = false;
        bool list_update = false;
        /* TODO: More things. */
    };

    void PrintUsage();

    Options ParseOptionsFromCommandLine();


}