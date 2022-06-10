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
#include "hactool_options.hpp"
#include "hactool_application_list.hpp"

namespace ams::hactool {

    class Processor {
        NON_COPYABLE(Processor);
        NON_MOVEABLE(Processor);
        private:
            static constexpr size_t WidthToPrintFieldValue = 52;
            static constexpr size_t BytesPerLine           = 32;
        private:
            class ScopedIndentHolder {
                NON_COPYABLE(ScopedIndentHolder);
                NON_MOVEABLE(ScopedIndentHolder);
                private:
                    char *m_p;
                public:
                    ScopedIndentHolder(char *p) : m_p(p) { /* ... */ }
                    ~ScopedIndentHolder() { *m_p = 0; }
            };

            struct ProcessAsNpdmContext {
                std::shared_ptr<fs::IStorage> storage;

                std::unique_ptr<u8[]> raw_data;

                const ldr::Npdm *npdm = nullptr;
                const ldr::Acid *acid = nullptr;
                const ldr::Aci *aci = nullptr;

                const void *acid_fac = nullptr;
                const void *acid_sac = nullptr;
                const void *acid_kac = nullptr;

                const void *aci_fah = nullptr;
                const void *aci_sac = nullptr;
                const void *aci_kac = nullptr;

                const void *modulus = nullptr;
            };

            struct ProcessAsNcaContext {
                std::shared_ptr<fs::IStorage> storage;
                std::shared_ptr<fssystem::NcaReader> reader;
                s32 exefs_index = -1;
                s32 romfs_index = -1;
                std::array<bool, fssystem::NcaHeader::FsCountMax> has_sections{};
                std::array<bool, fssystem::NcaHeader::FsCountMax> has_real_sections{};
                std::array<bool, fssystem::NcaHeader::FsCountMax> is_mounted{};
                std::array<std::shared_ptr<fs::IStorage>, fssystem::NcaHeader::FsCountMax> raw_sections{};
                std::array<std::shared_ptr<fs::IStorage>, fssystem::NcaHeader::FsCountMax> sections{};
                std::array<std::shared_ptr<fssystem::IAsynchronousAccessSplitter>, fssystem::NcaHeader::FsCountMax> splitters{};
                std::array<fssystem::NcaFsHeaderReader, fssystem::NcaHeader::FsCountMax> header_readers{};
                std::array<fssystem::NcaFileSystemDriver::StorageContext, fssystem::NcaHeader::FsCountMax> storage_contexts{};
                std::array<std::shared_ptr<fs::fsa::IFileSystem>, fssystem::NcaHeader::FsCountMax> file_systems{};

                ProcessAsNpdmContext npdm_ctx;
            };

            struct ProcessAsApplicationFileSystemContext {
                std::shared_ptr<fs::fsa::IFileSystem> fs;

                struct ApplicationEntryData {
                    std::shared_ptr<fs::IStorage> storage;
                };

                ApplicationContentsHolder<ApplicationEntryData> apps;

                bool has_target;
                ncm::ApplicationId target_app_id;
                u32 target_version;
                u8 target_index;
            };

            struct ProcessAsXciContext {
                std::shared_ptr<fs::IStorage> storage;

                std::shared_ptr<fs::IStorage> key_area_storage;
                std::shared_ptr<fs::IStorage> body_storage;

                struct CardData {
                    gc::impl::CardInitialData initial_data;
                    gc::impl::CardHeaderWithSignature header;
                    gc::impl::CardHeaderWithSignature decrypted_header;
                    gc::impl::CardHeaderWithSignature header_for_hash;
                    gc::impl::CardHeaderWithSignature decrypted_header_for_hash;
                    gc::impl::T1CardCertificate t1_certificate;
                    gc::impl::Ca10Certificate ca10_certificate;
                };

                CardData card_data;

                struct PartitionData {
                    std::shared_ptr<fs::IStorage> storage;
                    std::shared_ptr<fs::fsa::IFileSystem> fs;
                };

                PartitionData root_partition;
                PartitionData update_partition;
                PartitionData logo_partition;
                PartitionData normal_partition;
                PartitionData secure_partition;

                ProcessAsApplicationFileSystemContext app_ctx;
            };

            struct ProcessAsPfsContext {
                std::shared_ptr<fs::IStorage> storage;
                std::shared_ptr<fs::fsa::IFileSystem> fs;

                bool is_exefs;

                ProcessAsNpdmContext npdm_ctx;
                ProcessAsApplicationFileSystemContext app_ctx;
            };
        private:
            Options m_options;
            fssrv::impl::ExternalKeyManager m_external_nca_key_manager;
            std::shared_ptr<fs::fsa::IFileSystem> m_local_fs;

            os::SdkMutex m_print_lock;
            char m_indent_buffer[1_KB];
        public:
            Processor(const Options &options);

            Result Process();
        private:
            /* Printing. */
            [[nodiscard]] ScopedIndentHolder IncreaseIndentation() {
                static constexpr const char Indentation[] = "    ";
                const auto len = std::strlen(m_indent_buffer);
                AMS_ABORT_UNLESS(len + sizeof(Indentation) < sizeof(m_indent_buffer));

                std::memcpy(m_indent_buffer + len, Indentation, sizeof(Indentation));

                return ScopedIndentHolder(m_indent_buffer + len);
            }

            void PrintLineImpl(const char *fmt, ...) const __attribute__((format(printf, 2, 3)));

            void PrintFormat(const char *field_name, const char *fmt, ...) const __attribute__((format(printf, 3, 4)));

            [[nodiscard]] ScopedIndentHolder PrintHeader(const char *field_name) { this->PrintFormat(field_name, ""); return this->IncreaseIndentation(); }

            void PrintString(const char *field_name, const char *str) const { this->PrintFormat(field_name, "%s", str); }

            void PrintInteger(const char *field_name, s64 v) const { return this->PrintFormat(field_name, "%" PRId64, v); }

            void PrintMagic(u32 magic) {
                char magic_str[5];
                *reinterpret_cast<u32 *>(magic_str) = magic;
                magic_str[4] = 0;
                this->PrintString("Magic", magic_str);
            }

            static void MakeVerifyFieldName(char *dst, size_t dst_size, const char *name, bool verified) {
                util::TSNPrintf(dst, dst_size, "%s %s", name, verified ? "(GOOD)" : "(FAIL)");
            }

            void PrintHex(const char *field_name, u64 v) const { this->PrintFormat(field_name, "0x%" PRIX64, v); }
            void PrintHex2(const char *field_name, u64 v) const { this->PrintFormat(field_name, "0x%02" PRIX64, v); }
            void PrintHex4(const char *field_name, u64 v) const { this->PrintFormat(field_name, "0x%04" PRIX64, v); }
            void PrintHex8(const char *field_name, u64 v) const { this->PrintFormat(field_name, "0x%08" PRIX64, v); }
            void PrintHex12(const char *field_name, u64 v) const { this->PrintFormat(field_name, "0x%012" PRIX64, v); }
            void PrintHex16(const char *field_name, u64 v) const { this->PrintFormat(field_name, "0x%016" PRIX64, v); }

            void PrintId64(const char *field_name, u64 v) const { this->PrintFormat(field_name, "%016" PRIX64, v); }

            void PrintBool(const char *field_name, bool v) const { this->PrintFormat(field_name, "%d", v); }

            void PrintBytes(const char *field_name, const void *src, size_t src_size) {
                char byte_str[2 * BytesPerLine + 1] = {};
                size_t byte_str_len = 0;

                const u8 *src8 = static_cast<const u8 *>(src);
                for (size_t i = 0; i < src_size; ++i) {
                    util::TSNPrintf(byte_str + byte_str_len, 3, "%02" PRIX8, src8[i]);
                    byte_str_len += 2;

                    if (byte_str_len == sizeof(byte_str) - 1) {
                        this->PrintFormat(field_name, "%s", byte_str);
                        field_name   = "";
                        byte_str_len = 0;
                    }
                }

                if (byte_str_len > 0) {
                    this->PrintFormat(field_name, "%s", byte_str);
                }
            }

            void PrintBytesWithVerify(const char *field_name, bool verified, const void *src, size_t src_size) {
                char verif_field_name[0x40];
                MakeVerifyFieldName(verif_field_name, sizeof(verif_field_name), field_name, verified);

                return this->PrintBytes(verif_field_name, src, src_size);
            }

            /* Utility/management. */
            void PresetInternalKeys();

            /* Procesing. */
            Result ProcessAsNca(std::shared_ptr<fs::IStorage> storage, ProcessAsNcaContext *ctx = nullptr);
            Result ProcessAsNpdm(std::shared_ptr<fs::IStorage> storage, ProcessAsNpdmContext *ctx = nullptr);
            Result ProcessAsXci(std::shared_ptr<fs::IStorage> storage, ProcessAsXciContext *ctx = nullptr);
            Result ProcessAsPfs(std::shared_ptr<fs::IStorage> storage, ProcessAsPfsContext *ctx = nullptr);
            Result ProcessAsApplicationFileSystem(std::shared_ptr<fs::fsa::IFileSystem> fs, ProcessAsApplicationFileSystemContext *ctx = nullptr);

            /* Printing. */
            void PrintAsNca(ProcessAsNcaContext &ctx);
            void PrintAsNpdm(ProcessAsNpdmContext &ctx);
            void PrintAsXci(ProcessAsXciContext &ctx);
            void PrintAsPfs(ProcessAsPfsContext &ctx);
            void PrintAsApplicationFileSystem(ProcessAsApplicationFileSystemContext &ctx);

            /* Saving. */
            void SaveAsNca(ProcessAsNcaContext &ctx);
            void SaveAsNpdm(ProcessAsNpdmContext &ctx);
            void SaveAsXci(ProcessAsXciContext &ctx);
            void SaveAsPfs(ProcessAsPfsContext &ctx);
            void SaveAsApplicationFileSystem(ProcessAsApplicationFileSystemContext &ctx);
    };

    inline void Processor::PrintLineImpl(const char *fmt, ...) const {
        char print_buf[4_KB];
        {
            std::memcpy(print_buf, m_indent_buffer, sizeof(m_indent_buffer));
            const auto l = std::strlen(print_buf);

            std::va_list vl;
            va_start(vl, fmt);
            util::VSNPrintf(print_buf + l, sizeof(print_buf) - l, fmt, vl);
            va_end(vl);
        }

        const auto l = std::strlen(print_buf);
        if (print_buf[l - 1] != '\n') {
            AMS_ABORT_UNLESS(l < sizeof(print_buf) - 1);
            print_buf[l] = '\n';
            print_buf[l + 1] = 0;
        }

        std::printf("%s", print_buf);
    }

    inline void Processor::PrintFormat(const char *field_name, const char *fmt, ...) const {
        const auto l = std::strlen(m_indent_buffer);
        AMS_ABORT_UNLESS(l < WidthToPrintFieldValue);

        char line_fmt[0x40];
        util::TSNPrintf(line_fmt, sizeof(line_fmt), "%%-%ds" "%%s", static_cast<int>(WidthToPrintFieldValue - l));

        char field_colon[0x40];
        if (field_name[0] == 0 || field_name[std::strlen(field_name) - 1] == ':') {
            util::TSNPrintf(field_colon, sizeof(field_colon), "%s", field_name);
        } else {
            util::TSNPrintf(field_colon, sizeof(field_colon), "%s:", field_name);
        }

        char value_str[4_KB];
        {
            std::va_list vl;
            va_start(vl, fmt);
            util::VSNPrintf(value_str, sizeof(value_str), fmt, vl);
            va_end(vl);
        }

        this->PrintLineImpl(line_fmt, field_colon, value_str);
    }

}