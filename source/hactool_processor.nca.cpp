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
#include <exosphere/pkg1.hpp>
#include "hactool_processor.hpp"
#include "hactool_fs_utils.hpp"

namespace ams::hactool {

    namespace {

        constexpr size_t BufferPoolSize        = 1_MB;
        constexpr size_t BufferManagerHeapSize = 1_MB;

        constexpr size_t MaxCacheCount = 1024;
        constexpr size_t BlockSize     = 16_KB;

        alignas(os::MemoryPageSize) constinit u8 g_buffer_manager_heap[BufferManagerHeapSize] = {};
        alignas(os::MemoryPageSize) constinit u8 g_buffer_pool[BufferPoolSize] = {};

        constinit util::TypedStorage<fssystem::FileSystemBufferManager> g_buffer_manager = {};

        constinit util::TypedStorage<mem::StandardAllocator> g_buffer_allocator = {};
        constinit util::TypedStorage<fssrv::MemoryResourceFromStandardAllocator> g_allocator = {};

        constinit bool g_initialized = false;

        /* FileSystem creators. */
        constinit util::TypedStorage<fssrv::fscreator::RomFileSystemCreator>       g_rom_fs_creator = {};
        constinit util::TypedStorage<fssrv::fscreator::PartitionFileSystemCreator> g_partition_fs_creator = {};
        constinit util::TypedStorage<fssrv::fscreator::StorageOnNcaCreator>        g_storage_on_nca_creator = {};

        void InitializeFileSystemHelpers(const Options &options) {
            if (!g_initialized) {
                g_initialized = true;

                /* Decide if we're prod. */
                const bool is_prod = !options.dev;

                /* Setup our crypto configuration. */
                fssystem::SetUpKekAccessKeys(is_prod);

                /* Initialize buffer allocator. */
                util::ConstructAt(g_buffer_allocator, g_buffer_pool, BufferPoolSize);
                util::ConstructAt(g_allocator, GetPointer(g_buffer_allocator));

                /* Initialize the buffer manager. */
                util::ConstructAt(g_buffer_manager);
                GetReference(g_buffer_manager).Initialize(MaxCacheCount, reinterpret_cast<uintptr_t>(g_buffer_manager_heap), BufferManagerHeapSize, BlockSize);

                /* Initialize fs creators. */
                util::ConstructAt(g_rom_fs_creator, GetPointer(g_allocator));
                util::ConstructAt(g_partition_fs_creator);
                util::ConstructAt(g_storage_on_nca_creator, GetPointer(g_allocator), *fssystem::GetNcaCryptoConfiguration(is_prod), *fssystem::GetNcaCompressionConfiguration(), GetPointer(g_buffer_manager), fs::impl::GetNcaHashGeneratorFactorySelector());
            }
        }

        bool IsExternalKeyRequired(const std::shared_ptr<fssystem::NcaReader> &nca_reader) {
            constexpr fs::RightsId ZeroRightsId = {};
            fs::RightsId rights_id;
            nca_reader->GetRightsId(rights_id.data, sizeof(rights_id.data));

            return !crypto::IsSameBytes(std::addressof(rights_id), std::addressof(ZeroRightsId), sizeof(rights_id));
        }

        Result ParseNca(std::shared_ptr<fssystem::NcaReader> *out, std::shared_ptr<fs::IStorage> file_storage, fssrv::impl::ExternalKeyManager &external_key_manager) {
            /* Create the nca reader. */
            std::shared_ptr<fssystem::NcaReader> nca_reader;
            R_TRY(util::GetReference(g_storage_on_nca_creator).CreateNcaReader(std::addressof(nca_reader), std::move(file_storage)));

            /* If necessary, set the external key. */
            if (IsExternalKeyRequired(nca_reader)) {
                /* Get the rights id. */
                fs::RightsId rights_id;
                nca_reader->GetRightsId(rights_id.data, sizeof(rights_id.data));

                /* Get the encrypted titlekey. */
                spl::AccessKey encrypted_titlekey;
                if (R_SUCCEEDED(external_key_manager.Find(std::addressof(encrypted_titlekey), rights_id))) {
                    /* Decrypt the titlekey with the appropriate key generation. */
                    spl::AccessKey access_key = {};
                    R_ABORT_UNLESS(spl::PrepareCommonEsTitleKey(std::addressof(access_key), std::addressof(encrypted_titlekey), sizeof(encrypted_titlekey), nca_reader->GetKeyGeneration()));

                    nca_reader->SetExternalDecryptionKey(std::addressof(access_key), sizeof(access_key));
                } else {
                    fprintf(stderr, "[Warning]: Failed to find titlekey for rights id ");
                    for (size_t i = 0; i < sizeof(rights_id.data); ++i) {
                        fprintf(stderr, "%02X", rights_id.data[i]);
                    }
                    fprintf(stderr, "\n");
                }
            }

            /* Set output reader. */
            *out = std::move(nca_reader);
            R_SUCCEED();
        }

    }

    Result Processor::ProcessAsNca(std::shared_ptr<fs::IStorage> storage, ProcessAsNcaContext *ctx) {
        /* Ensure file system helpers are initialized. */
        InitializeFileSystemHelpers(m_options);

        /* Ensure we have a context. */
        ProcessAsNcaContext local_ctx{};
        if (ctx == nullptr) {
            ctx = std::addressof(local_ctx);
        }

        /* Set the storage. */
        ctx->storage = std::move(storage);

        /* Create an NCA reader for the input file. */
        R_TRY(ParseNca(std::addressof(ctx->reader), ctx->storage, m_external_nca_key_manager));

        /* Open storages for each section. */
        std::shared_ptr<fs::IStorage> npdm_storage;

        for (s32 i = 0; i < fssystem::NcaHeader::FsCountMax; ++i) {
            ctx->storage_contexts[i].open_raw_storage = true;

            const auto res = [&]() -> Result {
                if (ctx->base_reader != nullptr) {
                    R_RETURN(util::GetReference(g_storage_on_nca_creator).CreateWithPatchWithContext(std::addressof(ctx->raw_sections[i]), std::addressof(ctx->splitters[i]), std::addressof(ctx->header_readers[i]), std::addressof(ctx->storage_contexts[i]), ctx->base_reader, ctx->reader, i));
                } else {
                    R_RETURN(util::GetReference(g_storage_on_nca_creator).CreateWithContext(std::addressof(ctx->raw_sections[i]), std::addressof(ctx->splitters[i]), std::addressof(ctx->header_readers[i]), std::addressof(ctx->storage_contexts[i]), ctx->reader, i));
                }
            }();

            if (R_SUCCEEDED(res)) {
                ctx->has_sections[i] = true;

                if (ctx->header_readers[i].ExistsSparseLayer()) {
                    continue;
                }

                /* Try to open the non-raw section. */
                const auto real_res = util::GetReference(g_storage_on_nca_creator).CreateByRawStorage(std::addressof(ctx->sections[i]), std::addressof(ctx->splitters[i]), std::addressof(ctx->header_readers[i]), std::shared_ptr<fs::IStorage>(ctx->raw_sections[i]), std::addressof(ctx->storage_contexts[i]), ctx->reader);
                if (R_SUCCEEDED(real_res)) {
                    ctx->has_real_sections[i] = true;

                    /* Try to mount the section. */
                    const auto fs_type = ctx->header_readers[i].GetFsType();
                    switch (fs_type) {
                        case fssystem::NcaFsHeader::FsType::PartitionFs:
                            {
                                const auto mount_res = util::GetReference(g_partition_fs_creator).Create(std::addressof(ctx->file_systems[i]), ctx->sections[i]);
                                if (R_SUCCEEDED(mount_res)) {
                                    ctx->is_mounted[i] = true;

                                    /* Check if section is exefs. */
                                    if (ctx->exefs_index < 0 && ctx->reader->GetContentType() == fssystem::NcaHeader::ContentType::Program) {
                                        bool is_exefs = false;
                                        const auto check_npdm_res = fssystem::HasFile(std::addressof(is_exefs), ctx->file_systems[i].get(), fs::MakeConstantPath("/main.npdm"));
                                        if (R_SUCCEEDED(check_npdm_res)) {
                                            if (is_exefs) {
                                                ctx->exefs_index = i;

                                                if (const auto open_npdm_res = OpenFileStorage(std::addressof(npdm_storage), ctx->file_systems[i], "/main.npdm"); R_FAILED(open_npdm_res)) {
                                                    fprintf(stderr, "[Warning]: main.npdm exists in exefs section %d but could not be opened: 2%03d-%04d\n", i, open_npdm_res.GetModule(), open_npdm_res.GetDescription());
                                                }
                                            }
                                        } else {
                                            fprintf(stderr, "[Warning]: Failed to check if NCA section %d is exefs: 2%03d-%04d\n", i, check_npdm_res.GetModule(), check_npdm_res.GetDescription());
                                        }
                                    }
                                } else {
                                    fprintf(stderr, "[Warning]: Failed to mount NCA section %d as PartitionFileSystem: 2%03d-%04d\n", i, mount_res.GetModule(), mount_res.GetDescription());
                                }
                            }
                            break;
                        case fssystem::NcaFsHeader::FsType::RomFs:
                            {
                                const auto mount_res = util::GetReference(g_rom_fs_creator).Create(std::addressof(ctx->file_systems[i]), ctx->sections[i]);
                                if (R_SUCCEEDED(mount_res)) {
                                    ctx->is_mounted[i] = true;

                                    if (ctx->romfs_index < 0) {
                                        ctx->romfs_index = i;
                                    }

                                } else {
                                    fprintf(stderr, "[Warning]: Failed to mount NCA section %d as RomFsFileSystem: 2%03d-%04d\n", i, mount_res.GetModule(), mount_res.GetDescription());
                                }
                            }
                            break;
                        default:
                            fprintf(stderr, "[Warning]: NCA section %d has unknown section type %d\n", i, static_cast<int>(fs_type));
                            break;
                    }
                } else {
                    fprintf(stderr, "[Warning]: Failed to open NCA section %d: 2%03d-%04d, NCA may be corrupt.\n", i, real_res.GetModule(), real_res.GetDescription());
                }
            } else if (fs::ResultPartitionNotFound::Includes(res)) {
                ctx->has_sections[i] = false;
            } else {
                /* TODO: Should we stop here instead of pretending the NCA doesn't have this section? */
                fprintf(stderr, "[Warning]: Failed to open raw NCA section %d: 2%03d-%04d\n", i, res.GetModule(), res.GetDescription());
            }
        }

        /* If we have an npdm, process it. */
        if (npdm_storage != nullptr) {
            const auto process_npdm_res = this->ProcessAsNpdm(std::move(npdm_storage), std::addressof(ctx->npdm_ctx));
            if (R_FAILED(process_npdm_res)) {
                fprintf(stderr, "[Warning]: Failed to process main.npdm: 2%03d-%04d\n", process_npdm_res.GetModule(), process_npdm_res.GetDescription());
            }
        }

        /* Print. */
        if (ctx == std::addressof(local_ctx)) {
            this->PrintAsNca(*ctx);
        }

        /* Save. */
        if (ctx == std::addressof(local_ctx)) {
            this->SaveAsNca(*ctx);
        }

        R_SUCCEED();
    }

    void Processor::PrintAsNca(ProcessAsNcaContext &ctx) {
        auto _ = this->PrintHeader("NCA");

        /* Get raw data. */
        fssystem::NcaHeader raw_header;
        ctx.reader->GetRawData(std::addressof(raw_header), sizeof(raw_header));

        this->PrintMagic(ctx.reader->GetMagic());
        this->PrintHex("HeaderSign1 Key Generation", ctx.reader->GetHeaderSign1KeyGeneration());
        if (!m_options.verify) {
            this->PrintBytes("HeaderSign1", raw_header.header_sign_1, sizeof(raw_header.header_sign_1));
            this->PrintBytes("HeaderSign2", raw_header.header_sign_2, sizeof(raw_header.header_sign_2));
        } else {
            this->PrintBytesWithVerify("HeaderSign1", ctx.reader->GetHeaderSign1Valid(), raw_header.header_sign_1, sizeof(raw_header.header_sign_1));

            if (ctx.reader->GetContentType() == fssystem::NcaHeader::ContentType::Program) {
                bool is_header_sign2_valid = false;
                if (ctx.npdm_ctx.modulus != nullptr) {
                    const u8 *sig         = raw_header.header_sign_2;
                    const size_t sig_size = sizeof(raw_header.header_sign_2);
                    const u8 *mod         = static_cast<const u8 *>(ctx.npdm_ctx.modulus);
                    const size_t mod_size = crypto::Rsa2048PssSha256Verifier::ModulusSize;
                    const u8 *exp         = fssystem::GetAcidSignatureKeyPublicExponent();
                    const size_t exp_size = fssystem::AcidSignatureKeyPublicExponentSize;

                    u8 hsh[fssystem::IHash256Generator::HashSize];
                    ctx.reader->GetHeaderSign2TargetHash(hsh, sizeof(hsh));

                    is_header_sign2_valid = crypto::VerifyRsa2048PssSha256WithHash(sig, sig_size, mod, mod_size, exp, exp_size, hsh, sizeof(hsh));
                }

                this->PrintBytesWithVerify("HeaderSign2", is_header_sign2_valid, raw_header.header_sign_2, sizeof(raw_header.header_sign_2));
            } else {
                this->PrintBytes("HeaderSign2", raw_header.header_sign_2, sizeof(raw_header.header_sign_2));
            }
        }
        this->PrintHex12("Content Size", ctx.reader->GetContentSize());

        union {
            u32 v32;
            u8 v8[sizeof(u32)];
        } addon;
        addon.v32 = util::ConvertToBigEndian<u32>(ctx.reader->GetSdkAddonVersion());
        this->PrintFormat("SDK Version", "%" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8, addon.v8[0], addon.v8[1], addon.v8[2], addon.v8[3]);

        this->PrintString("Distribution Type", fs::impl::IdString().ToString(ctx.reader->GetDistributionType()));
        this->PrintString("Content Type", fs::impl::IdString().ToString(ctx.reader->GetContentType()));

        const auto key_generation = static_cast<pkg1::KeyGeneration>(std::max<s32>(ctx.reader->GetKeyGeneration() - 1, 0));
        this->PrintFormat("Master Key Generation", "%02" PRIX8 " (%s)", static_cast<u8>(key_generation), fs::impl::IdString().ToString(key_generation));

        const bool external = IsExternalKeyRequired(ctx.reader);
        this->PrintString("Encryption Type", external ? "External" : "Internal");
        if (external) {
            u8 rights_id[fssystem::NcaHeader::RightsIdSize];
            ctx.reader->GetRightsId(rights_id, sizeof(rights_id));

            this->PrintBytes("Rights Id", rights_id, sizeof(rights_id));

            /* TODO: External key print support. */
        } else {
            this->PrintFormat("Key Index", "%" PRIX8, ctx.reader->GetKeyIndex());

            /* Print the encrypted key area. */
            {
                auto _ = this->PrintHeader("Key Area (Encrypted)");

                for (int i = 0; i < fssystem::NcaHeader::DecryptionKey_Count; ++i) {
                    char key_name[0x40];
                    util::TSNPrintf(key_name, sizeof(key_name), "Key %d (%s)", i, fs::impl::IdString().ToString(static_cast<fssystem::NcaHeader::DecryptionKey>(i)));

                    this->PrintBytes(key_name, raw_header.encrypted_key_area + crypto::AesDecryptor128::KeySize * i, crypto::AesDecryptor128::KeySize);
                }
            }

            /* Print the decrypted key area. */
            {
                auto _ = this->PrintHeader("Key Area (Decrypted)");

                for (int i = 0; i < fssystem::NcaHeader::DecryptionKey_Count; ++i) {
                    char key_name[0x40];
                    util::TSNPrintf(key_name, sizeof(key_name), "Key %d (%s)", i, fs::impl::IdString().ToString(static_cast<fssystem::NcaHeader::DecryptionKey>(i)));

                    this->PrintBytes(key_name, ctx.reader->GetDecryptionKey(i), crypto::AesDecryptor128::KeySize);
                }
            }
        }

        /* Print any special sections in the order that they appear. */
        for (s32 i = 0; i < fssystem::NcaHeader::FsCountMax; ++i) {
            if (i == ctx.exefs_index) {
                this->PrintAsNpdm(ctx.npdm_ctx);
            }
        }

        /* Print all sections. */
        {
            auto _ = this->PrintHeader("Sections");

            for (s32 i = 0; i < fssystem::NcaHeader::FsCountMax; ++i) {
                if (!ctx.has_sections[i]) {
                    continue;
                }

                this->PrintLineImpl("Section %d:\n", i);
                auto _ = this->IncreaseIndentation();

                this->PrintHex12("Offset", ctx.reader->GetFsOffset(i));
                this->PrintHex12("Size", ctx.reader->GetFsSize(i));
                this->PrintInteger("Version", ctx.header_readers[i].GetVersion());
                this->PrintString("Fs Type", fs::impl::IdString().ToString(ctx.header_readers[i].GetFsType()));
                this->PrintString("Hash Type", fs::impl::IdString().ToString(ctx.header_readers[i].GetHashType()));
                this->PrintString("Encryption Type", fs::impl::IdString().ToString(ctx.header_readers[i].GetEncryptionType()));

                /* Note: Iv format is same for all encryption types. */
                {
                    u8 iv[0x10];
                    fssystem::AesCtrStorageBySharedPointer::MakeIv(iv, sizeof(iv), ctx.header_readers[i].GetAesCtrUpperIv().value, ctx.reader->GetFsOffset(i));
                    this->PrintBytes("Encryption Iv", iv, sizeof(iv));
                }

                this->PrintBool("Has Sparse Layer", ctx.header_readers[i].ExistsSparseLayer());

                const auto &patch_info = ctx.header_readers[i].GetPatchInfo();
                this->PrintBool("Has AesCtrEx Table", patch_info.HasAesCtrExTable());
                this->PrintBool("Has Indirect Table", patch_info.HasIndirectTable());

                this->PrintBool("Has Compression Layer", ctx.header_readers[i].ExistsCompressionLayer());

                /* TODO: Print specific information about the integrity layers. */
            }
        }
    }

    void Processor::SaveAsNca(ProcessAsNcaContext &ctx) {
        /* If we should, save the header. */
        if (m_options.header_out_path != nullptr) {
            /* Get the header. */
            u8 raw_header[sizeof(fssystem::NcaHeader) + fssystem::NcaHeader::FsCountMax * sizeof(fssystem::NcaFsHeader)];
            std::memset(raw_header, 0xCC, sizeof(raw_header));

            ctx.reader->GetRawData(raw_header, sizeof(fssystem::NcaHeader));
            for (s32 i = 0; i < fssystem::NcaHeader::FsCountMax; ++i) {
                R_ABORT_UNLESS(ctx.reader->ReadHeader(reinterpret_cast<fssystem::NcaFsHeader *>(raw_header + sizeof(fssystem::NcaHeader) + sizeof(fssystem::NcaHeader) * i), i));
            }

            /* Save to disk. */
            printf("Saving header to %s...\n", m_options.header_out_path);
            SaveToFile(m_local_fs, m_options.header_out_path, raw_header, sizeof(raw_header));
        }

        /* TODO: plaintext */

        /* Process sections. */
        for (s32 i = 0; i < fssystem::NcaHeader::FsCountMax; ++i) {
            /* TODO: Save section as file, including raw. */
            {
                /* Determine path to save to. */
                const char *path = nullptr;
                if (path == nullptr && ctx.exefs_index == i && m_options.exefs_out_file_path != nullptr) {
                    path = m_options.exefs_out_file_path;
                }
                if (path == nullptr && ctx.romfs_index == i && m_options.romfs_out_file_path != nullptr) {
                    path = m_options.romfs_out_file_path;
                }
                if (path == nullptr && m_options.section_out_file_paths[i] != nullptr) {
                    path = m_options.section_out_file_paths[i];
                }

                /* If we have a path, save to it. */
                if (path != nullptr) {
                    if (m_options.raw && ctx.has_sections[i]) {
                        SaveToFile(m_local_fs, path, ctx.raw_sections[i].get());
                    } else if (ctx.has_real_sections[i]) {
                        SaveToFile(m_local_fs, path, ctx.sections[i].get());
                    }
                }
            }

            /* Extract section to directory. */
            if (ctx.is_mounted[i]) {
                /* Determine path to extract to. */
                const char *dir_path = nullptr;
                char prefix[0x20] = {};
                if (dir_path == nullptr && ctx.exefs_index == i && m_options.exefs_out_dir_path != nullptr) {
                    dir_path = m_options.exefs_out_dir_path;
                    util::TSNPrintf(prefix, sizeof(prefix), "exe:");
                }
                if (dir_path == nullptr && ctx.romfs_index == i && m_options.romfs_out_dir_path != nullptr) {
                    dir_path = m_options.romfs_out_dir_path;
                    util::TSNPrintf(prefix, sizeof(prefix), "rom:");
                }
                if (dir_path == nullptr && m_options.section_out_dir_paths[i] != nullptr) {
                    dir_path = m_options.section_out_dir_paths[i];
                    util::TSNPrintf(prefix, sizeof(prefix), "section%d:", i);
                }

                /* If we have a path, extract to it. */
                if (dir_path != nullptr) {
                    if (ctx.romfs_index == i && m_options.only_updated && !ctx.header_readers[i].ExistsCompressionLayer() && ctx.storage_contexts[i].aes_ctr_ex_storage != nullptr && ctx.storage_contexts[i].indirect_storage != nullptr) {
                        if (!m_options.list_romfs) {
                            ExtractUpdatedRomFsDirectory(m_local_fs, static_cast<fssystem::RomFsFileSystem *>(ctx.file_systems[i].get()), ctx.storage_contexts[i].indirect_storage, ctx.storage_contexts[i].aes_ctr_ex_storage, m_options.updated_generation, prefix, dir_path, "/");
                        }
                    } else {
                        ExtractDirectory(m_local_fs, ctx.file_systems[i], prefix, dir_path, "/");
                    }
                }
            }

            if (ctx.romfs_index == i && ctx.is_mounted[i] && m_options.list_romfs) {
                if (m_options.only_updated && !ctx.header_readers[i].ExistsCompressionLayer() && ctx.storage_contexts[i].aes_ctr_ex_storage != nullptr && ctx.storage_contexts[i].indirect_storage != nullptr) {
                    PrintUpdatedRomFsDirectory(static_cast<fssystem::RomFsFileSystem *>(ctx.file_systems[i].get()), ctx.storage_contexts[i].indirect_storage, ctx.storage_contexts[i].aes_ctr_ex_storage, m_options.updated_generation, "rom:", "/");
                } else {
                    PrintDirectory(ctx.file_systems[i], "rom:", "/");
                }
            }
        }

        /* TODO: what else? */
        AMS_UNUSED(ctx);
    }

}