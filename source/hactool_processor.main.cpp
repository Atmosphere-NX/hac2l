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
#include "hactool_processor.hpp"
#include "hactool_fs_utils.hpp"

namespace ams::hactool {

    Processor::Processor(const Options &options) : m_options(options), m_base_nca_ctx{}, m_base_xci_ctx{}, m_base_nsp_ctx{}, m_base_appfs_ctx{} {
        /* Default to no bases. */
        m_has_base_nca   = false;
        m_has_base_xci   = false;
        m_has_base_nsp   = false;
        m_has_base_appfs = false;

        /* Create local file system for host root. */
        fssrv::fscreator::LocalFileSystemCreator local_fs_creator(true);
        fs::Path normalized_path;
        R_ABORT_UNLESS(normalized_path.InitializeAsEmpty());
        R_ABORT_UNLESS(static_cast<fssrv::fscreator::ILocalFileSystemCreator &>(local_fs_creator).Create(std::addressof(m_local_fs), normalized_path, false));

        std::memset(m_indent_buffer, 0, sizeof(m_indent_buffer));
    }

    Result Processor::Process() {
        /* Setup our internal keys. */
        this->PresetInternalKeys();

        /* Open any bases we've been provided. */
        {
            if (m_options.base_nca_path != nullptr) {
                std::shared_ptr<fs::IStorage> storage = nullptr;
                if (const auto open_res = OpenFileStorage(std::addressof(storage), m_local_fs, m_options.base_nca_path); R_SUCCEEDED(open_res)) {
                    if (const auto proc_res = this->ProcessAsNca(std::move(storage), std::addressof(m_base_nca_ctx)); R_SUCCEEDED(proc_res)) {
                        m_has_base_nca = true;
                    } else {
                        fprintf(stderr, "Failed to process base nca (%s): 2%03d-%04d\n", m_options.base_nca_path, proc_res.GetModule(), proc_res.GetDescription());
                    }
                } else {
                    fprintf(stderr, "Failed to open base nca (%s): 2%03d-%04d\n", m_options.base_nca_path, open_res.GetModule(), open_res.GetDescription());
                }
            }

            if (m_options.base_xci_path != nullptr) {
                std::shared_ptr<fs::IStorage> storage = nullptr;
                if (const auto open_res = OpenFileStorage(std::addressof(storage), m_local_fs, m_options.base_xci_path); R_SUCCEEDED(open_res)) {
                    if (const auto proc_res = this->ProcessAsXci(std::move(storage), std::addressof(m_base_xci_ctx)); R_SUCCEEDED(proc_res)) {
                        m_has_base_xci = true;
                    } else {
                        fprintf(stderr, "Failed to process base xci (%s): 2%03d-%04d\n", m_options.base_xci_path, proc_res.GetModule(), proc_res.GetDescription());
                    }
                } else {
                    fprintf(stderr, "Failed to open base xci (%s): 2%03d-%04d\n", m_options.base_xci_path, open_res.GetModule(), open_res.GetDescription());
                }
            }

            if (m_options.base_nsp_path != nullptr) {
                std::shared_ptr<fs::IStorage> storage = nullptr;
                if (const auto open_res = OpenFileStorage(std::addressof(storage), m_local_fs, m_options.base_nsp_path); R_SUCCEEDED(open_res)) {
                    if (const auto proc_res = this->ProcessAsNsp(std::move(storage), std::addressof(m_base_nsp_ctx)); R_SUCCEEDED(proc_res)) {
                        m_has_base_nsp = true;
                    } else {
                        fprintf(stderr, "Failed to process base nsp (%s): 2%03d-%04d\n", m_options.base_nsp_path, proc_res.GetModule(), proc_res.GetDescription());
                    }
                } else {
                    fprintf(stderr, "Failed to open base nsp (%s): 2%03d-%04d\n", m_options.base_nsp_path, open_res.GetModule(), open_res.GetDescription());
                }
            }

            if (m_options.base_appfs_path != nullptr) {
                std::shared_ptr<fs::fsa::IFileSystem> fs = nullptr;
                if (const auto open_res = OpenSubDirectoryFileSystem(std::addressof(fs), m_local_fs, m_options.base_appfs_path); R_SUCCEEDED(open_res)) {
                    if (const auto proc_res = this->ProcessAsApplicationFileSystem(std::move(fs), std::addressof(m_base_appfs_ctx)); R_SUCCEEDED(proc_res)) {
                        m_has_base_appfs = true;
                    } else {
                        fprintf(stderr, "Failed to process base app fs (%s): 2%03d-%04d\n", m_options.base_appfs_path, proc_res.GetModule(), proc_res.GetDescription());
                    }
                } else {
                    fprintf(stderr, "Failed to open base app fs (%s): 2%03d-%04d\n", m_options.base_appfs_path, open_res.GetModule(), open_res.GetDescription());
                }
            }
        }

        if (m_options.file_type == FileType::AppFs) {
            /* Open the filesystem. */
            std::shared_ptr<fs::fsa::IFileSystem> input = nullptr;
            if (m_options.in_file_path != nullptr) {
                R_TRY(OpenSubDirectoryFileSystem(std::addressof(input), m_local_fs, m_options.in_file_path));
            }

            R_TRY(this->ProcessAsApplicationFileSystem(std::move(input)));
        } else {
            /* Open the file storage. */
            std::shared_ptr<fs::IStorage> input = nullptr;
            if (m_options.in_file_path != nullptr) {
                R_TRY(OpenFileStorage(std::addressof(input), m_local_fs, m_options.in_file_path));
            }

            /* Process for the specific file type. */
            switch (m_options.file_type) {
                case FileType::Nca:
                    R_TRY(this->ProcessAsNca(std::move(input)));
                    break;
                case FileType::Npdm:
                    R_TRY(this->ProcessAsNpdm(std::move(input)));
                    break;
                case FileType::Xci:
                    R_TRY(this->ProcessAsXci(std::move(input)));
                    break;
                case FileType::Pfs:
                    R_TRY(this->ProcessAsNsp(std::move(input)));
                    break;
                case FileType::Romfs:
                    R_TRY(this->ProcessAsRomfs(std::move(input)));
                    break;
                AMS_UNREACHABLE_DEFAULT_CASE();
            }
        }

        R_SUCCEED();
    }


}