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

        constexpr size_t CardInitialDataRegionSize = 0x1000;

        constexpr size_t CardPageSize = 0x200;

        struct XciBodyHeader {
            gc::impl::CardHeaderWithSignature card_header;
            gc::impl::CardHeaderWithSignature card_header_for_sign2;
            gc::impl::Ca10Certificate ca10_cert;
        };

        Result DetermineXciSubStorages(std::shared_ptr<fs::IStorage> *out_key_area, std::shared_ptr<fs::IStorage> *out_body, std::shared_ptr<fs::IStorage> &storage) {
            /* Get the storage size. */
            s64 storage_size;
            R_TRY(storage->GetSize(std::addressof(storage_size)));

            /* Try to read the header from after the initial data region. */
            if (storage_size >= static_cast<s64>(CardInitialDataRegionSize)) {
                gc::impl::CardHeaderWithSignature card_header;
                R_TRY(storage->Read(CardInitialDataRegionSize, std::addressof(card_header), sizeof(card_header)));

                if (card_header.data.magic == gc::impl::CardHeader::Magic) {
                    *out_key_area = std::make_shared<fs::SubStorage>(std::shared_ptr<fs::IStorage>(storage), 0, CardInitialDataRegionSize);
                    *out_body     = std::make_shared<fs::SubStorage>(std::shared_ptr<fs::IStorage>(storage), CardInitialDataRegionSize, storage_size - CardInitialDataRegionSize);
                    R_SUCCEED();
                }
            }

            /* Default to treating the xci as though it has no key area. */
            fprintf(stderr, "[Warning]: Game card is missing key area/initial data header. Re-dump?\n");
            *out_key_area = nullptr;
            *out_body     = std::make_shared<fs::SubStorage>(storage, 0, storage_size);
            R_SUCCEED();
        }

        Result CreateRootPartitionFileSystem(std::shared_ptr<fs::fsa::IFileSystem> *out, std::shared_ptr<fs::IStorage> &storage, const gc::impl::CardHeaderWithSignature &header) {
            /* Create meta data. */
            auto meta = std::make_unique<fssystem::Sha256PartitionFileSystemMeta>();
            AMS_ABORT_UNLESS(meta != nullptr);

            /* Initialize meta data. */
            {
                util::optional<u8> salt = util::nullopt;
                if (static_cast<fs::GameCardCompatibilityType>(header.data.encrypted_data.compatibility_type) != fs::GameCardCompatibilityType::Normal) {
                    salt.emplace(header.data.encrypted_data.compatibility_type);
                }
                R_TRY(meta->Initialize(storage.get(), sf::GetNewDeleteMemoryResource(), header.data.partition_fs_header_hash, sizeof(header.data.partition_fs_header_hash), salt));
            }

            /* Create fs. */
            auto fs = std::make_shared<fssystem::Sha256PartitionFileSystem>();
            R_TRY(fs->Initialize(std::move(meta), storage));

            /* Set output. */
            *out = std::move(fs);
            R_SUCCEED();
        }

        Result CreatePartitionFileSystem(std::shared_ptr<fs::fsa::IFileSystem> *out, std::shared_ptr<fs::IStorage> &storage) {
            /* Create meta data. */
            auto meta = std::make_unique<fssystem::Sha256PartitionFileSystemMeta>();
            AMS_ABORT_UNLESS(meta != nullptr);

            s64 size;
            R_ABORT_UNLESS(storage->GetSize(std::addressof(size)));

            /* Initialize meta data. */
            R_TRY(meta->Initialize(storage.get(), sf::GetNewDeleteMemoryResource()));

            /* Create fs. */
            auto fs = std::make_shared<fssystem::Sha256PartitionFileSystem>();
            R_TRY(fs->Initialize(std::move(meta), storage));

            /* Set output. */
            *out = std::move(fs);
            R_SUCCEED();
        }

    }

    Result Processor::ProcessAsXci(std::shared_ptr<fs::IStorage> storage, ProcessAsXciContext *ctx) {
        /* Ensure we have a context. */
        ProcessAsXciContext local_ctx{};
        if (ctx == nullptr) {
            ctx = std::addressof(local_ctx);
        }

        /* Set the storage. */
        ctx->storage = std::move(storage);

        /* Decide on storages. */
        R_TRY(DetermineXciSubStorages(std::addressof(ctx->key_area_storage), std::addressof(ctx->body_storage), ctx->storage));

        /* If we have a key area, read the initial data. */
        if (ctx->key_area_storage != nullptr) {
            R_ABORT_UNLESS(ctx->key_area_storage->Read(0, std::addressof(ctx->card_data.initial_data), sizeof(ctx->card_data.initial_data)));
        }

        /* Read the header. */
        XciBodyHeader body_header;
        R_ABORT_UNLESS(ctx->body_storage->Read(0, std::addressof(body_header), sizeof(body_header)));

        /* Make the card header. */
        ctx->card_data.header = body_header.card_header;

        /* Decrypt the card header. */
        ctx->card_data.decrypted_header = ctx->card_data.header;
        R_ABORT_UNLESS(gc::impl::GcCrypto::DecryptCardHeader(std::addressof(ctx->card_data.decrypted_header.data), sizeof(ctx->card_data.decrypted_header.data)));

        /* Set up the headers for ca10 sign2. */
        if (ctx->card_data.header.data.flags & fs::GameCardAttribute_HasCa10CertificateFlag) {
            ctx->card_data.ca10_certificate          = body_header.ca10_cert;
            ctx->card_data.header_for_hash           = body_header.card_header_for_sign2;
            ctx->card_data.decrypted_header_for_hash = ctx->card_data.header_for_hash;
            R_ABORT_UNLESS(gc::impl::GcCrypto::DecryptCardHeader(std::addressof(ctx->card_data.decrypted_header_for_hash.data), sizeof(ctx->card_data.decrypted_header_for_hash.data)));
        } else {
            ctx->card_data.ca10_certificate          = {};
            ctx->card_data.header_for_hash           = ctx->card_data.header;
            ctx->card_data.decrypted_header_for_hash = ctx->card_data.decrypted_header;
        }

        /* Read the T1 cert. */
        R_ABORT_UNLESS(ctx->body_storage->Read(CardPageSize * 0x38, std::addressof(ctx->card_data.t1_certificate), sizeof(ctx->card_data.t1_certificate)));

        /* Parse the root partition. */
        {
            /* Create the root partition storage. */
            using AlignmentMatchingStorageForGameCard = fssystem::AlignmentMatchingStorageInBulkRead<1>;
            auto aligned_storage = std::make_shared<AlignmentMatchingStorageForGameCard>(ctx->body_storage, CardPageSize);

            /* Get the size of the body. */
            s64 body_size;
            R_ABORT_UNLESS(aligned_storage->GetSize(std::addressof(body_size)));

            /* Create sub storage for the root partition. */
            ctx->root_partition.storage = std::make_shared<fs::SubStorage>(std::move(aligned_storage), ctx->card_data.header.data.partition_fs_header_address, body_size - ctx->card_data.header.data.partition_fs_header_address);

            /* Create filesystem for the root partition. */
            if (const auto res = CreateRootPartitionFileSystem(std::addressof(ctx->root_partition.fs), ctx->root_partition.storage, ctx->card_data.decrypted_header); R_FAILED(res)) {
                fprintf(stderr, "[Warning]: Failed to mount the game card root partition: 2%03d-%04d\n", res.GetModule(), res.GetDescription());
            }
        }

        /* Parse all other partitions. */
        if (ctx->root_partition.fs != nullptr) {
            const auto iter_result = fssystem::IterateDirectoryRecursively(ctx->root_partition.fs.get(),
                fs::MakeConstantPath("/"),
                [&] (const fs::Path &, const fs::DirectoryEntry &) -> Result {
                    R_SUCCEED();
                },
                [&] (const fs::Path &, const fs::DirectoryEntry &) -> Result {
                    R_SUCCEED();
                },
                [&] (const fs::Path &path, const fs::DirectoryEntry &) -> Result {
                    ProcessAsXciContext::PartitionData *target_partition = nullptr;

                    if (std::strcmp(path.GetString(), "/update") == 0) {
                        target_partition = std::addressof(ctx->update_partition);
                    } else if (std::strcmp(path.GetString(), "/logo") == 0) {
                        target_partition = std::addressof(ctx->logo_partition);
                    } else if (std::strcmp(path.GetString(), "/normal") == 0) {
                        target_partition = std::addressof(ctx->normal_partition);
                    } else if (std::strcmp(path.GetString(), "/secure") == 0) {
                        target_partition = std::addressof(ctx->secure_partition);
                    } else {
                        fprintf(stderr, "[Warning]: Found unrecognized game card partition (%s)\n", path.GetString());
                    }

                    if (target_partition != nullptr) {
                        if (const auto res = OpenFileStorage(std::addressof(target_partition->storage), ctx->root_partition.fs, path.GetString()); R_SUCCEEDED(res)) {
                            if (const auto res = CreatePartitionFileSystem(std::addressof(target_partition->fs), target_partition->storage); R_FAILED(res)) {
                                fprintf(stderr, "[Warning]: Failed to mount game card partition (%s): 2%03d-%04d\n", path.GetString(), res.GetModule(), res.GetDescription());
                            }
                        } else {
                            fprintf(stderr, "[Warning]: Failed to open game card partition (%s): 2%03d-%04d\n", path.GetString(), res.GetModule(), res.GetDescription());
                        }
                    }

                    R_SUCCEED();
                }
            );
            if (R_FAILED(iter_result)) {
                fprintf(stderr, "[Warning]: Iterating the root partition failed: 2%03d-%04d\n", iter_result.GetModule(), iter_result.GetDescription());
            }
        }

        /* TODO: Recursive processing? */

        /* Print. */
        if (ctx == std::addressof(local_ctx)) {
            this->PrintAsXci(*ctx);
        }

        /* Save. */
        if (ctx == std::addressof(local_ctx)) {
            this->SaveAsXci(*ctx);
        }

        R_SUCCEED();
    }

    void Processor::PrintAsXci(ProcessAsXciContext &ctx) {
        auto _ = this->PrintHeader("XCI");

        /* Print the initial data. */
        if (ctx.key_area_storage != nullptr) {
            auto _ = this->PrintHeader("Initial Data");

            if (m_options.verify) {
                this->PrintBytesWithVerify("Package Id", std::memcmp(ctx.card_data.initial_data.payload.package_id, ctx.card_data.decrypted_header.data.package_id, sizeof(ctx.card_data.initial_data.payload.package_id)) == 0, ctx.card_data.initial_data.payload.package_id, sizeof(ctx.card_data.initial_data.payload.package_id));
            } else {
                this->PrintBytes("Package Id", ctx.card_data.initial_data.payload.package_id, sizeof(ctx.card_data.initial_data.payload.package_id));
            }

            this->PrintBytes("Encrypted Title Key", ctx.card_data.initial_data.payload.auth_data, sizeof(ctx.card_data.initial_data.payload.auth_data));

            const auto kek_idx = ctx.card_data.decrypted_header.data.key_index.Get<gc::impl::CardHeaderKeyIndex::TitleKeyDecIndex>();
            u8 key[sizeof(ctx.card_data.initial_data.payload.auth_data)];
            if (R_SUCCEEDED(gc::impl::GcCrypto::DecryptCardInitialData(key, sizeof(key), std::addressof(ctx.card_data.initial_data), sizeof(ctx.card_data.initial_data), kek_idx))) {
                this->PrintBytes("Decrypted Title Key", key, sizeof(key));
            } else {
                printf("%08x\n", gc::impl::GcCrypto::DecryptCardInitialData(key, sizeof(key), std::addressof(ctx.card_data.initial_data), sizeof(ctx.card_data.initial_data), kek_idx).GetValue());
            }
        } else {
            this->PrintString("Initial Data", "Missing/Not Dumped");
        }

        /* Declare helper for printing a card header. */
        auto PrintCardHeader = [&](const char *header_name, const gc::impl::CardHeaderWithSignature &header, const gc::impl::CardHeaderWithSignature &enc_header, const void *modulus) {
            auto _ = this->PrintHeader(header_name);

            /* Print the magic. */
            this->PrintMagic(header.data.magic);

            /* Print the signature. */
            if (m_options.verify) {
                const bool signature_valid = R_SUCCEEDED(gc::impl::GcCrypto::VerifyCardHeader(std::addressof(enc_header), sizeof(enc_header), modulus, crypto::Rsa2048Pkcs1Sha256Verifier::ModulusSize));
                this->PrintBytesWithVerify("Signature", signature_valid, header.signature, sizeof(header.signature));
            } else {
                this->PrintBytes("Signature", header.signature, sizeof(header.signature));
            }

            this->PrintBytes("Package Id", header.data.package_id, sizeof(header.data.package_id));

            this->PrintString("Memory Capacity", fs::impl::IdString().ToString(static_cast<gc::impl::MemoryCapacity>(header.data.rom_size)));
            this->PrintHex12("Rom Area Start", static_cast<u64>(header.data.rom_area_start_page) * CardPageSize);
            this->PrintHex12("Backup Area Start", static_cast<u64>(header.data.backup_area_start_page) * CardPageSize);
            this->PrintHex12("Valid Data End", static_cast<u64>(header.data.valid_data_end_page) * CardPageSize);
            this->PrintHex12("Limit Area", static_cast<u64>(header.data.lim_area_page) * CardPageSize);
            this->PrintString("Kek Index", fs::impl::IdString().ToString(header.data.key_index.Get<gc::impl::CardHeaderKeyIndex::KekIndex>()));
            this->PrintInteger("Title Key Dec Index", header.data.key_index.Get<gc::impl::CardHeaderKeyIndex::TitleKeyDecIndex>());
            {
                auto _ = this->PrintHeader("Flags");
                this->PrintBool("Auto Boot", header.data.flags & fs::GameCardAttribute_AutoBootFlag);
                this->PrintBool("History Erase", header.data.flags & fs::GameCardAttribute_HistoryEraseFlag);
                this->PrintBool("Repair Tool", header.data.flags & fs::GameCardAttribute_RepairToolFlag);
                this->PrintBool("Different Region Cup to Terra Device", header.data.flags & fs::GameCardAttribute_DifferentRegionCupToTerraDeviceFlag);
                this->PrintBool("Different Region Cup to Global Device", header.data.flags & fs::GameCardAttribute_DifferentRegionCupToGlobalDeviceFlag);
                this->PrintBool("Has Ca10 Certificate", header.data.flags & fs::GameCardAttribute_HasCa10CertificateFlag);
            }
            this->PrintString("Sel Sec", fs::impl::IdString().ToString(static_cast<gc::impl::SelSec>(header.data.sel_sec)));
            this->PrintInteger("Sel T1 Key", header.data.sel_t1_key);
            this->PrintInteger("Sel Key", header.data.sel_key);
            if (m_options.verify) {
                u8 hash[crypto::Sha256Generator::HashSize];

                crypto::GenerateSha256(hash, sizeof(hash), std::addressof(ctx.card_data.initial_data), sizeof(ctx.card_data.initial_data));
                const bool initial_data_hash_good = ctx.key_area_storage != nullptr && crypto::IsSameBytes(hash, header.data.initial_data_hash, sizeof(hash));
                this->PrintBytesWithVerify("Initial Data Hash", initial_data_hash_good, header.data.initial_data_hash, sizeof(header.data.initial_data_hash));

                {
                    void *tmp = std::malloc(header.data.partition_fs_header_size + 1);
                    AMS_ABORT_UNLESS(tmp != nullptr);
                    ON_SCOPE_EXIT { std::free(tmp); };

                    R_ABORT_UNLESS(ctx.body_storage->Read(header.data.partition_fs_header_address, tmp, header.data.partition_fs_header_size));
                    if (static_cast<fs::GameCardCompatibilityType>(header.data.encrypted_data.compatibility_type) != fs::GameCardCompatibilityType::Normal) {
                        static_cast<u8 *>(tmp)[header.data.partition_fs_header_size] = header.data.encrypted_data.compatibility_type;
                        crypto::GenerateSha256(hash, sizeof(hash), tmp, header.data.partition_fs_header_size + 1);
                    } else {
                        crypto::GenerateSha256(hash, sizeof(hash), tmp, header.data.partition_fs_header_size);
                    }
                }

                const bool partition_header_hash_good = crypto::IsSameBytes(hash, header.data.partition_fs_header_hash, sizeof(hash));
                this->PrintBytesWithVerify("Partition Header Hash", partition_header_hash_good, header.data.partition_fs_header_hash, sizeof(header.data.partition_fs_header_hash));
            } else {
                this->PrintBytes("Initial Data Hash", header.data.initial_data_hash, sizeof(header.data.initial_data_hash));
                this->PrintBytes("Partition Header Hash", header.data.partition_fs_header_hash, sizeof(header.data.partition_fs_header_hash));
            }
            this->PrintBytes("Encrypted Data Iv", header.data.iv, sizeof(header.data.iv));
            {
                auto _ = this->PrintHeader("Card Info");

                auto &enc_data = header.data.encrypted_data;

                this->PrintString("Card Fw Version", fs::impl::IdString().ToString(static_cast<gc::impl::FwVersion>(enc_data.fw_version[0])));
                this->PrintString("Clock Rate", fs::impl::IdString().ToString(static_cast<gc::impl::AccessControl1ClockRate>(enc_data.acc_ctrl_1)));
                this->PrintInteger("Wait1 Time Read", enc_data.wait_1_time_read);
                this->PrintInteger("Wait2 Time Read", enc_data.wait_2_time_read);
                this->PrintInteger("Wait1 Time Write", enc_data.wait_1_time_write);
                this->PrintInteger("Wait2 Time Write", enc_data.wait_2_time_write);
                this->PrintHex8("Fw Mode", enc_data.fw_mode);
                this->PrintString("Compatibility Type", fs::impl::IdString().ToString(static_cast<fs::GameCardCompatibilityType>(enc_data.compatibility_type)));
                this->PrintFormat("Cup Version", "%" PRIu32 ".%" PRIu32 ".%" PRIu32 ".%" PRIu32 " (%" PRIu32")", (enc_data.cup_version >> 26) & 0x3F, (enc_data.cup_version >> 20) & 0x3F, (enc_data.cup_version >> 16) & 0xF, (enc_data.cup_version >> 0) & 0xFFFF, enc_data.cup_version);
                this->PrintId64("Cup Id", enc_data.cup_id);
                this->PrintBytes("Upp Hash", enc_data.upp_hash, sizeof(enc_data.upp_hash));
            }
        };

        /* Print the main card header. */
        PrintCardHeader("Main Header", ctx.card_data.decrypted_header, ctx.card_data.header, nullptr);

        auto PrintGamecardPartition = [&](const char *header, const char *prefix, ProcessAsXciContext::PartitionData &part) {
            if (part.fs != nullptr) {
                auto _ = this->PrintHeader(header);

                char print_prefix[0x100];
                std::memset(print_prefix, ' ', WidthToPrintFieldValue);
                util::TSNPrintf(print_prefix + WidthToPrintFieldValue, sizeof(print_prefix) - WidthToPrintFieldValue, "%s", prefix);
                PrintDirectory(part.fs, print_prefix, "/");
            }
        };

        PrintGamecardPartition("Root Partition", "root:", ctx.root_partition);
        PrintGamecardPartition("Logo Partition", "logo:", ctx.logo_partition);
        PrintGamecardPartition("Normal Partition", "normal:", ctx.normal_partition);
        PrintGamecardPartition("Secure Partition", "secure:", ctx.secure_partition);
        if (m_options.list_update) {
            PrintGamecardPartition("Update Partition", "update:", ctx.update_partition);
        }

        AMS_UNUSED(ctx);
    }

    void Processor::SaveAsXci(ProcessAsXciContext &ctx) {
        /* Extract partitions. */
        if (m_options.root_partition_out_dir != nullptr) { ExtractDirectoryWithProgress(m_local_fs, ctx.root_partition.fs, "root:", m_options.root_partition_out_dir, "/"); }
        if (m_options.logo_partition_out_dir != nullptr) { ExtractDirectoryWithProgress(m_local_fs, ctx.logo_partition.fs, "logo:", m_options.logo_partition_out_dir, "/"); }
        if (m_options.normal_partition_out_dir != nullptr) { ExtractDirectoryWithProgress(m_local_fs, ctx.normal_partition.fs, "normal:", m_options.normal_partition_out_dir, "/"); }
        if (m_options.secure_partition_out_dir != nullptr) { ExtractDirectoryWithProgress(m_local_fs, ctx.secure_partition.fs, "secure:", m_options.secure_partition_out_dir, "/"); }
        if (m_options.update_partition_out_dir != nullptr) { ExtractDirectoryWithProgress(m_local_fs, ctx.update_partition.fs, "update:", m_options.update_partition_out_dir, "/"); }

        /* TODO: Recurse, dump NCAs? */
    }

}