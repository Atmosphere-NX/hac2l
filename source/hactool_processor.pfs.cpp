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

    Result Processor::ProcessAsPfs(std::shared_ptr<fs::IStorage> storage, ProcessAsPfsContext *ctx) {
        /* Ensure we have a context. */
        ProcessAsPfsContext local_ctx{};
        if (ctx == nullptr) {
            ctx = std::addressof(local_ctx);
        }

        /* Set the fs. */
        ctx->storage = std::move(storage);

        /* Read the magic. */
        R_TRY(ctx->storage->Read(0, std::addressof(ctx->magic), sizeof(ctx->magic)));

        /* Mount the partition filesystem. */
        {
            /* Allocate the fs. */
            auto fs = fssystem::AllocateShared<fssystem::PartitionFileSystem>();
            R_UNLESS(fs != nullptr, fs::ResultAllocationMemoryFailedInPartitionFileSystemCreatorA());

            /* Initialize the filesystem. */
            R_TRY(fs->Initialize(std::shared_ptr<fs::IStorage>(ctx->storage)));

            /* Set the context fs. */
            ctx->fs = std::move(fs);
        }

        /* Try to treat the context as an exefs. */
        std::shared_ptr<fs::IStorage> npdm_storage;
        {
            bool is_exefs = false;
            const auto check_npdm_res = fssystem::HasFile(std::addressof(is_exefs), ctx->fs.get(), fs::MakeConstantPath("/main.npdm"));
            if (R_SUCCEEDED(check_npdm_res)) {
                if (is_exefs) {
                    ctx->is_exefs = true;

                    if (const auto open_npdm_res = OpenFileStorage(std::addressof(npdm_storage), ctx->fs, "/main.npdm"); R_FAILED(open_npdm_res)) {
                        fprintf(stderr, "[Warning]: main.npdm exists in PartitionFileSystem but could not be opened: 2%03d-%04d\n", open_npdm_res.GetModule(), open_npdm_res.GetDescription());
                    }
                }
            } else {
                fprintf(stderr, "[Warning]: Failed to check if PartitionFileSystem is exefs: 2%03d-%04d\n", check_npdm_res.GetModule(), check_npdm_res.GetDescription());
            }
        }

        /* Parse as exefs or appfs. */
        if (ctx->is_exefs) {
            if (const auto process_npdm_res = this->ProcessAsNpdm(std::move(npdm_storage), std::addressof(ctx->npdm_ctx)); R_FAILED(process_npdm_res)) {
                fprintf(stderr, "[Warning]: Failed to process PartitionFileSystem main.npdm: 2%03d-%04d\n", process_npdm_res.GetModule(), process_npdm_res.GetDescription());
            }
        } else {
            if (const auto process_app_res = this->ProcessAsApplicationFileSystem(ctx->fs, std::addressof(ctx->app_ctx)); R_FAILED(process_app_res)) {
                fprintf(stderr, "[Warning]: Failed to process PartitionFileSystem applications: 2%03d-%04d\n", process_app_res.GetModule(), process_app_res.GetDescription());
            }
        }

        /* TODO: Recursive processing? */

        /* Print. */
        if (ctx == std::addressof(local_ctx)) {
            this->PrintAsPfs(*ctx);
        }

        /* Save. */
        if (ctx == std::addressof(local_ctx)) {
            this->SaveAsPfs(*ctx);
        }

        R_SUCCEED();
    }

    void Processor::PrintAsPfs(ProcessAsPfsContext &ctx) {
        {
            auto _ = this->PrintHeader("PartitionFileSystem");
            this->PrintMagic(ctx.magic);
            {
                auto _ = this->PrintHeader("Files");

                char print_prefix[1_KB + 5];
                std::memset(print_prefix, ' ', WidthToPrintFieldValue);
                util::TSNPrintf(print_prefix, sizeof(print_prefix), "%s%s", m_indent_buffer, "pfs:");

                PrintDirectory(ctx.fs, print_prefix, "/");
            }
        }

        if (ctx.is_exefs) {
            this->PrintAsNpdm(ctx.npdm_ctx);
        } else {
            this->PrintAsApplicationFileSystem(ctx.app_ctx);
        }
    }

    void Processor::SaveAsPfs(ProcessAsPfsContext &ctx) {
        /* Save pfs contents. */
        {
            /* Determine path to extract to. */
            const char *dir_path = nullptr;
            if (dir_path == nullptr && ctx.is_exefs && m_options.exefs_out_dir_path != nullptr) {
                dir_path = m_options.exefs_out_dir_path;
            }
            if (dir_path == nullptr && m_options.nsp_out_dir_path != nullptr) {
                dir_path = m_options.nsp_out_dir_path;
            }
            if (dir_path == nullptr && m_options.default_out_dir_path != nullptr) {
                dir_path = m_options.default_out_dir_path;
            }

            /* If we have a path, extract to it. */
            if (dir_path != nullptr) {
                ExtractDirectory(m_local_fs, ctx.fs, "pfs:", dir_path, "/");
            }
        }
        if (ctx.is_exefs) {
            this->SaveAsNpdm(ctx.npdm_ctx);
        } else {
            this->SaveAsApplicationFileSystem(ctx.app_ctx);
        }
    }

}