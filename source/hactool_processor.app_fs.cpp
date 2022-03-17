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

    namespace {

        constexpr const s32 MetaFileSystemPartitionIndex = 0;

        constexpr const char MetaNcaFileNameExtension[] = ".cnmt.nca";
        constexpr const char NcaFileNameExtension[] = ".nca";

        constexpr const char ContentMetaFileNameExtension[] = ".cnmt";

        Result ReadContentMetaFile(std::unique_ptr<u8[]> *out, size_t *out_size, std::shared_ptr<fs::fsa::IFileSystem> &fs) {
            bool found = false;
            R_RETURN(fssystem::IterateDirectoryRecursively(fs.get(),
                [&] (const fs::Path &, const fs::DirectoryEntry &) -> Result { R_SUCCEED(); },
                [&] (const fs::Path &, const fs::DirectoryEntry &) -> Result { R_SUCCEED(); },
                [&] (const fs::Path &path, const fs::DirectoryEntry &entry) -> Result {
                    /* If we already found the content meta, finish. */
                    R_SUCCEED_IF(found);

                    /* If the path isn't a meta nca, finish. */
                    R_SUCCEED_IF(!PathView(entry.name).HasSuffix(ContentMetaFileNameExtension));

                    /* Open the file storage. */
                    std::shared_ptr<fs::IStorage> storage;
                    R_TRY(OpenFileStorage(std::addressof(storage), fs, path.GetString()));

                    /* Get the meta file size. */
                    s64 size;
                    R_TRY(storage->GetSize(std::addressof(size)));

                    /* Allocate buffer. */
                    auto data = std::make_unique<u8[]>(static_cast<size_t>(size));
                    R_UNLESS(data != nullptr, fs::ResultAllocationMemoryFailedMakeUnique());

                    /* Read the meta into the buffer. */
                    R_TRY(storage->Read(0, data.get(), size));

                    /* Return the output buffer. */
                    *out      = std::move(data);
                    *out_size = static_cast<size_t>(size);
                    found = true;

                    R_SUCCEED();
                }
            ));

            R_THROW(ncm::ResultContentMetaNotFound());
        }

    }

    Result Processor::ProcessAsApplicationFileSystem(std::shared_ptr<fs::fsa::IFileSystem> fs, ProcessAsApplicationFileSystemCtx *ctx) {
        /* Ensure we have a context. */
        ProcessAsApplicationFileSystemCtx local_ctx{};
        if (ctx == nullptr) {
            ctx = std::addressof(local_ctx);
        }

        /* Set the fs. */
        ctx->fs = std::move(fs);

        /* Iterate all files in the filesystem. */
        {
            /* Iterate, printing the contents of the directory. */
            const auto iter_result = fssystem::IterateDirectoryRecursively(ctx->fs.get(),
                [&] (const fs::Path &, const fs::DirectoryEntry &) -> Result { R_SUCCEED(); },
                [&] (const fs::Path &, const fs::DirectoryEntry &) -> Result { R_SUCCEED(); },
                [&] (const fs::Path &path, const fs::DirectoryEntry &entry) -> Result {
                    /* If the path isn't a meta nca, finish. */
                    R_SUCCEED_IF(!PathView(entry.name).HasSuffix(MetaNcaFileNameExtension));

                    /* Try opening the meta. */
                    std::shared_ptr<fs::IStorage> meta_nca_storage;
                    if (const auto res = OpenFileStorage(std::addressof(meta_nca_storage), ctx->fs, path.GetString()); R_FAILED(res)) {
                        fprintf(stderr, "[Warning]: Failed to open meta nca (%s): 2%03d-%04d\n", path.GetString(), res.GetModule(), res.GetDescription());
                        R_SUCCEED();
                    }

                    ProcessAsNcaContext meta_nca_ctx = {};
                    if (const auto res = this->ProcessAsNca(std::move(meta_nca_storage), std::addressof(meta_nca_ctx)); R_FAILED(res)) {
                        fprintf(stderr, "[Warning]: Failed to process meta nca (%s): 2%03d-%04d\n", path.GetString(), res.GetModule(), res.GetDescription());
                        R_SUCCEED();
                    }

                    /* We only care about meta ncas. */
                    if (meta_nca_ctx.reader->GetContentType() != fssystem::NcaHeader::ContentType::Meta) {
                        fprintf(stderr, "[Warning]: Expected %s to be Meta, was %s\n", path.GetString(), fs::impl::IdString().ToString(meta_nca_ctx.reader->GetContentType()));
                        R_SUCCEED();
                    }

                    /* Clarification: we only care about meta ncas which are mountable. */
                    if (!meta_nca_ctx.is_mounted[MetaFileSystemPartitionIndex]) {
                        fprintf(stderr, "[Warning]: Expected to mount meta nca partition for %s, but didn't.\n", path.GetString());
                        R_SUCCEED();
                    }

                    /* Read the content meta file. */
                    std::unique_ptr<u8[]> meta_data;
                    size_t meta_size;
                    if (const auto res = ReadContentMetaFile(std::addressof(meta_data), std::addressof(meta_size), meta_nca_ctx.file_systems[MetaFileSystemPartitionIndex]); R_FAILED(res)) {
                        fprintf(stderr, "[Warning]: Failed to read cnmt from %s: 2%03d-%04d\n", path.GetString(), res.GetModule(), res.GetDescription());
                        R_SUCCEED();
                    }

                    /* Parse the cnmt. */
                    const auto meta_reader = ncm::PackagedContentMetaReader(meta_data.get(), meta_size);
                    const auto * const meta_header = meta_reader.GetHeader();

                    /* We only care about applications/patches. */
                    R_SUCCEED_IF(meta_header->type != ncm::ContentMetaType::Application && meta_header->type != ncm::ContentMetaType::Patch);

                    /* Get the key. */
                    const auto app_id = meta_reader.GetApplicationId();
                    AMS_ABORT_UNLESS(app_id.has_value());

                    /* Get the version. */
                    const auto version = meta_header->version;

                    /* Add all the content metas. */
                    for (size_t i = 0; i < meta_reader.GetContentCount(); ++i) {
                        const auto &info = *meta_reader.GetContentInfo(i);

                        /* Check that the type isn't a delta. */
                        if (info.GetType() == ncm::ContentType::DeltaFragment) {
                            continue;
                        }

                        /* Check that we don't already have an info for the content. */
                        if (auto existing = ctx->apps.Find(*app_id, version, info.GetIdOffset(), info.GetType()); existing != ctx->apps.end()) {
                            fprintf(stderr, "[Warning]: Ignoring duplicate entry { %016" PRIX64 ", %" PRIu32 ", %d, %d }\n", app_id->value, version, static_cast<int>(info.GetIdOffset()), static_cast<int>(info.GetType()));
                            continue;
                        }

                        /* Try to open the storage for the specified file. */
                        std::shared_ptr<fs::IStorage> storage;
                        {
                            const auto cid_str = ncm::GetContentIdString(info.GetId());
                            char file_name[ncm::ContentIdStringLength + 0x10];
                            util::TSNPrintf(file_name, sizeof(file_name), "%s%s", cid_str.data, NcaFileNameExtension);

                            const auto res = [&] () -> Result {
                                ams::fs::Path fs_path;
                                R_TRY(fs_path.Initialize(path));
                                R_TRY(fs_path.RemoveChild());
                                R_TRY(fs_path.AppendChild(file_name));

                                R_RETURN(OpenFileStorage(std::addressof(storage), ctx->fs, fs_path.GetString()));
                            }();
                            if (R_FAILED(res)) {
                                fprintf(stderr, "[Warning]: Failed to open NCA (type %d) specified by %s: 2%03d-%04d\n", static_cast<int>(info.GetType()), path.GetString(), res.GetModule(), res.GetDescription());
                                R_SUCCEED();
                            }
                        }

                        /* Add the new version for the content. */
                        auto *entry = ctx->apps.Insert(*app_id, version, info.GetIdOffset(), info.GetType());
                        entry->GetData().storage = std::move(storage);
                    }

                    R_SUCCEED();
                }
            );
            if (R_FAILED(iter_result)) {
                fprintf(stderr, "[Warning]: Failed to parse application filesystem: 2%03d-%04d\n", iter_result.GetModule(), iter_result.GetDescription());
            }
        }

        /* TODO: Recursive processing? */

        /* Print. */
        if (ctx == std::addressof(local_ctx)) {
            this->PrintAsApplicationFileSystem(*ctx);
        }

        /* Save. */
        if (ctx == std::addressof(local_ctx)) {
            this->SaveAsApplicationFileSystem(*ctx);
        }

        R_SUCCEED();
    }

    void Processor::PrintAsApplicationFileSystem(ProcessAsApplicationFileSystemCtx &ctx) {
        auto _ = this->PrintHeader("Application File System");

        {
            s32 app_idx = -1;
            ncm::ApplicationId cur_app_id{};
            const char *field_name = "Programs";
            for (const auto &entry : ctx.apps) {
                if (entry.GetType() != ncm::ContentType::Program) {
                    continue;
                }

                if (app_idx == -1 || cur_app_id != entry.GetId()) {
                    ++app_idx;
                    cur_app_id = entry.GetId();
                }

                this->PrintFormat(field_name, "{ Idx=%d, ProgramId=%016" PRIX64 ", Version=0x%08" PRIX32 ", IdOffset=%02" PRIX32 " }", app_idx, entry.GetId().value, entry.GetVersion(), entry.GetIdOffset());
                field_name = "";
            }
        }

        /* TODO */
        AMS_UNUSED(ctx);
    }

    void Processor::SaveAsApplicationFileSystem(ProcessAsApplicationFileSystemCtx &ctx) {
        /* TODO */
        AMS_UNUSED(ctx);
    }

}