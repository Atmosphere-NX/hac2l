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

        constexpr const char TicketFileNameExtension[] = ".tik";

        struct alignas(4) CommonTicketData {
            u32 signature_type;
            u8 signature_data[0x100];
            u8 padding0[0x3C];
            char issuer[0x40];
            u8 title_key_block[0x100];
            u8 format_version;
            u8 titlekey_type;
            u16 ticket_version;
            u8 license_type;
            u8 key_generation;
            u16 property_mask;
            u8 reserved[8];
            u8 ticket_id[8];
            u8 device_id[8];
            u8 rights_id[0x10];
            u8 account_id[0x4];
            u32 total_section_size;
            u32 section_header_offset;
            u16 section_header_count;
            u16 section_header_entry_size;
        };
        static_assert(util::is_pod<CommonTicketData>::value);
        static_assert(sizeof(CommonTicketData) == 0x2C0);

        bool IsValidCommonTicketFormat(const void *data, size_t size) {
            /* Check that the data is the right size for a ticket. */
            if (size != sizeof(CommonTicketData)) {
                return false;
            }

            /* Check the ticket. */
            const auto &ticket = *static_cast<const CommonTicketData *>(data);

            /* Check that the ticket is an aes key. */
            if (ticket.titlekey_type != 0) {
                return false;
            }

            /* Check that the ticket's rights id isn't all-zero. */
            size_t i;
            for (i = 0; i < util::size(ticket.rights_id); ++i) {
                if (ticket.rights_id[i] != 0) {
                    break;
                }
            }

            if (i == util::size(ticket.rights_id)) {
                return false;
            }

            /* Check that the ticket is a proper aes-key. */
            for (i = 0; i < sizeof(spl::AesKey); ++i) {
                if (ticket.title_key_block[i] != 0) {
                    break;
                }
            }
            if (i == sizeof(spl::AesKey)) {
                return false;
            }

            for (i = sizeof(spl::AesKey); i < util::size(ticket.title_key_block); ++i) {
                if (ticket.title_key_block[i] != 0) {
                    break;
                }
            }
            if (i != util::size(ticket.title_key_block)) {
                return false;
            }

            /* Check that the ticket's section header is proper. */
            if (ticket.section_header_offset != sizeof(CommonTicketData)) {
                return false;
            }

            /* Ticket is good enough. */
            return true;
        }

        bool TryLoadKeyFromCommonTicket(fssrv::impl::ExternalKeyManager &km, const void *data, size_t size) {
            if (IsValidCommonTicketFormat(data, size)) {
                /* Get the ticket. */
                const auto &ticket = *static_cast<const CommonTicketData *>(data);

                /* Decode the rights id. */
                fs::RightsId rights_id = {};
                std::memcpy(std::addressof(rights_id), ticket.rights_id, sizeof(rights_id));

                /* Decode the key. */
                spl::AccessKey access_key = {};
                std::memcpy(std::addressof(access_key), ticket.title_key_block, sizeof(access_key));

                /* Register with the key manager. */
                km.Register(rights_id, access_key);

                return true;
            } else {
                return false;
            }
        }

        Result ReadContentMetaFile(std::unique_ptr<u8[]> *out, size_t *out_size, std::shared_ptr<fs::fsa::IFileSystem> &fs) {
            bool found = false;
            R_RETURN(fssystem::IterateDirectoryRecursively(fs.get(),
                [&] (const fs::Path &, const fs::DirectoryEntry &) -> Result { R_SUCCEED(); },
                [&] (const fs::Path &, const fs::DirectoryEntry &) -> Result { R_SUCCEED(); },
                [&] (const fs::Path &path, const fs::DirectoryEntry &entry) -> Result {
                    /* If we already found the content meta, finish. */
                    R_SUCCEED_IF(found);

                    /* If the path isn't a meta nca, finish. */
                    R_SUCCEED_IF(!ncm::IsContentMetaFileName(entry.name));

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

    Result Processor::ProcessAsApplicationFileSystem(std::shared_ptr<fs::fsa::IFileSystem> fs, ProcessAsApplicationFileSystemContext *ctx) {
        /* Ensure we have a context. */
        ProcessAsApplicationFileSystemContext local_ctx{};
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
                    /* If the path is a ticket, try to load it. */
                    if (PathView(entry.name).HasSuffix(TicketFileNameExtension)) {
                        std::shared_ptr<fs::IStorage> tik_storage;
                        if (const auto res = OpenFileStorage(std::addressof(tik_storage), ctx->fs, path.GetString()); R_SUCCEEDED(res)) {
                            /* Get ticket size. */
                            s64 tik_size = -1;
                            if (const auto res = tik_storage->GetSize(std::addressof(tik_size)); R_SUCCEEDED(res)) {
                                if (tik_size >= static_cast<s64>(sizeof(CommonTicketData))) {
                                    CommonTicketData tik_data;
                                    if (const auto res = tik_storage->Read(0, std::addressof(tik_data), sizeof(tik_data)); R_SUCCEEDED(res)) {
                                        if (!TryLoadKeyFromCommonTicket(m_external_nca_key_manager, std::addressof(tik_data), sizeof(tik_data))) {
                                            fprintf(stderr, "[Warning]: Failed to load common title key from ticket file (%s). Is it not a common ticket?\n", path.GetString());
                                        }
                                    } else {
                                        fprintf(stderr, "[Warning]: Failed to read ticket file (%s): 2%03d-%04d\n", path.GetString(), res.GetModule(), res.GetDescription());
                                    }
                                } else {
                                    fprintf(stderr, "[Warning]: Ticket file (%s) has incorrect size: 2%03d-%04d\n", path.GetString(), res.GetModule(), res.GetDescription());
                                }
                            } else {
                                fprintf(stderr, "[Warning]: Failed to get size of ticket file (%s): 2%03d-%04d\n", path.GetString(), res.GetModule(), res.GetDescription());
                            }
                        } else {
                            fprintf(stderr, "[Warning]: Failed to open ticket file (%s): 2%03d-%04d\n", path.GetString(), res.GetModule(), res.GetDescription());
                        }
                    }

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

    void Processor::PrintAsApplicationFileSystem(ProcessAsApplicationFileSystemContext &ctx) {
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

    void Processor::SaveAsApplicationFileSystem(ProcessAsApplicationFileSystemContext &ctx) {
        /* TODO */
        AMS_UNUSED(ctx);
    }

}