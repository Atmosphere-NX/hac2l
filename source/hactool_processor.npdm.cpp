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
#include <vapours/svc/svc_definition_macro.hpp>
#include <stratosphere/rapidjson/document.h>
#include <stratosphere/rapidjson/prettywriter.h>
#include "hactool_processor.hpp"
#include "hactool_fs_utils.hpp"

namespace ams::hactool {

    namespace {

        Result ValidateSubregion(size_t allowed_start, size_t allowed_end, size_t start, size_t size, size_t min_size = 0) {
            R_UNLESS(size >= min_size,            ldr::ResultInvalidMeta());
            R_UNLESS(allowed_start <= start,      ldr::ResultInvalidMeta());
            R_UNLESS(start <= allowed_end,        ldr::ResultInvalidMeta());
            R_UNLESS(start + size <= allowed_end, ldr::ResultInvalidMeta());
            R_SUCCEED();
        }

        Result ValidateNpdm(const ldr::Npdm *npdm, size_t size) {
            /* Validate magic. */
            R_UNLESS(npdm->magic == ldr::Npdm::Magic, ldr::ResultInvalidMeta());

            /* Validate Acid extents. */
            R_TRY(ValidateSubregion(sizeof(ldr::Npdm), size, npdm->acid_offset, npdm->acid_size, sizeof(ldr::Acid)));

            /* Validate Aci extends. */
            R_TRY(ValidateSubregion(sizeof(ldr::Npdm), size, npdm->aci_offset, npdm->aci_size, sizeof(ldr::Aci)));

            R_SUCCEED();
        }

        Result ValidateAcid(const ldr::Acid *acid, size_t size) {
            /* Validate magic. */
            R_UNLESS(acid->magic == ldr::Acid::Magic, ldr::ResultInvalidMeta());

            /* Validate Fac, Sac, Kac. */
            R_TRY(ValidateSubregion(sizeof(ldr::Acid), size, acid->fac_offset, acid->fac_size));
            R_TRY(ValidateSubregion(sizeof(ldr::Acid), size, acid->sac_offset, acid->sac_size));
            R_TRY(ValidateSubregion(sizeof(ldr::Acid), size, acid->kac_offset, acid->kac_size));

            R_SUCCEED();
        }

        Result ValidateAci(const ldr::Aci *aci, size_t size) {
            /* Validate magic. */
            R_UNLESS(aci->magic == ldr::Aci::Magic, ldr::ResultInvalidMeta());

            /* Validate Fah, Sac, Kac. */
            R_TRY(ValidateSubregion(sizeof(ldr::Aci), size, aci->fah_offset, aci->fah_size));
            R_TRY(ValidateSubregion(sizeof(ldr::Aci), size, aci->sac_offset, aci->sac_size));
            R_TRY(ValidateSubregion(sizeof(ldr::Aci), size, aci->kac_offset, aci->kac_size));

            R_SUCCEED();
        }


        /* See kern::KCapabilities, from which this is sourced. */
        constexpr size_t InterruptIdCount = 0x400;
        constexpr size_t SystemCallCount  = 0xC0;

        enum class CapabilityType : u32 {
            CorePriority  = (1u <<  3) - 1,
            SyscallMask   = (1u <<  4) - 1,
            MapRange      = (1u <<  6) - 1,
            MapIoPage     = (1u <<  7) - 1,
            MapRegion     = (1u << 10) - 1,
            InterruptPair = (1u << 11) - 1,
            ProgramType   = (1u << 13) - 1,
            KernelVersion = (1u << 14) - 1,
            HandleTable   = (1u << 15) - 1,
            DebugFlags    = (1u << 16) - 1,

            Invalid       = 0u,
            Padding       = ~0u,
        };

        using RawCapabilityValue = util::BitPack32::Field<0, BITSIZEOF(util::BitPack32), u32>;

        static constexpr CapabilityType GetCapabilityType(const util::BitPack32 cap) {
            const u32 value = cap.Get<RawCapabilityValue>();
            return static_cast<CapabilityType>((~value & (value + 1)) - 1);
        }

        template<size_t Index, size_t Count, typename T = u32>
        using Field = util::BitPack32::Field<Index, Count, T>;

        #define DEFINE_FIELD(name, prev, ...) using name = Field<prev::Next, __VA_ARGS__>

        template<CapabilityType Type>
        static constexpr inline u32 CapabilityFlag = static_cast<u32>(Type) + 1;

        template<CapabilityType Type>
        static constexpr inline u32 CapabilityId = util::CountTrailingZeros<u32>(CapabilityFlag<Type>);

        struct CorePriority {
            using IdBits = Field<0, CapabilityId<CapabilityType::CorePriority> + 1>;

            DEFINE_FIELD(LowestThreadPriority,  IdBits,                6);
            DEFINE_FIELD(HighestThreadPriority, LowestThreadPriority,  6);
            DEFINE_FIELD(MinimumCoreId,         HighestThreadPriority, 8);
            DEFINE_FIELD(MaximumCoreId,         MinimumCoreId,         8);
        };

        struct SyscallMask {
            using IdBits = Field<0, CapabilityId<CapabilityType::SyscallMask> + 1>;

            DEFINE_FIELD(Mask,  IdBits, 24);
            DEFINE_FIELD(Index, Mask,    3);
        };

        /* NOTE: This always parses as though a mesosphere extension is true to use 40 pa bits instead of 36. */
        struct MapRange {
            using IdBits = Field<0, CapabilityId<CapabilityType::MapRange> + 1>;

            DEFINE_FIELD(Address,  IdBits,  24);
            DEFINE_FIELD(ReadOnly, Address,  1, bool);
        };

        struct MapRangeSize {
            using IdBits = Field<0, CapabilityId<CapabilityType::MapRange> + 1>;

            DEFINE_FIELD(Pages, IdBits, 20);

            DEFINE_FIELD(AddressHigh, Pages,        4);
            DEFINE_FIELD(Normal,      AddressHigh,  1, bool);
        };

        struct MapIoPage {
            using IdBits = Field<0, CapabilityId<CapabilityType::MapIoPage> + 1>;

            DEFINE_FIELD(Address, IdBits, 24);
        };

        enum class RegionType : u32 {
            None              = 0,
            KernelTraceBuffer = 1,
            OnMemoryBootImage = 2,
            DTB               = 3,
        };

        struct MapRegion {
            using IdBits = Field<0, CapabilityId<CapabilityType::MapRegion> + 1>;

            DEFINE_FIELD(Region0,   IdBits,      6, RegionType);
            DEFINE_FIELD(ReadOnly0, Region0,     1, bool);
            DEFINE_FIELD(Region1,   ReadOnly0,   6, RegionType);
            DEFINE_FIELD(ReadOnly1, Region1,     1, bool);
            DEFINE_FIELD(Region2,   ReadOnly1,   6, RegionType);
            DEFINE_FIELD(ReadOnly2, Region2,     1, bool);
        };

        static const u32 PaddingInterruptId = 0x3FF;
        static_assert(PaddingInterruptId < InterruptIdCount);

        struct InterruptPair {
            using IdBits = Field<0, CapabilityId<CapabilityType::InterruptPair> + 1>;

            DEFINE_FIELD(InterruptId0, IdBits,       10);
            DEFINE_FIELD(InterruptId1, InterruptId0, 10);
        };


        struct ProgramType {
            using IdBits = Field<0, CapabilityId<CapabilityType::ProgramType> + 1>;

            DEFINE_FIELD(Type,     IdBits,  3);
            DEFINE_FIELD(Reserved, Type,   15);
        };

        struct KernelVersion {
            using IdBits = Field<0, CapabilityId<CapabilityType::KernelVersion> + 1>;

            DEFINE_FIELD(MinorVersion, IdBits,        4);
            DEFINE_FIELD(MajorVersion, MinorVersion, 13);
        };

        struct HandleTable {
            using IdBits = Field<0, CapabilityId<CapabilityType::HandleTable> + 1>;

            DEFINE_FIELD(Size,     IdBits, 10);
            DEFINE_FIELD(Reserved, Size,    6);
        };

        struct DebugFlags {
            using IdBits = Field<0, CapabilityId<CapabilityType::DebugFlags> + 1>;

            DEFINE_FIELD(AllowDebug, IdBits,      1, bool);
            DEFINE_FIELD(ForceDebug, AllowDebug,  1, bool);
            DEFINE_FIELD(Reserved,   ForceDebug, 13);
        };

        #undef DEFINE_FIELD

        struct InterruptFlagSetTag{};
        using InterruptFlagSet = util::BitFlagSet<InterruptIdCount, InterruptFlagSetTag>;

        struct SystemCallFlagSetTag{};
        using SystemCallFlagSet = util::BitFlagSet<SystemCallCount, SystemCallFlagSetTag>;

        class MappedRange : public util::IntrusiveRedBlackTreeBaseNode<MappedRange> {
            private:
                u64 m_address;
                size_t m_size;
                bool m_read_only;
            public:
                MappedRange(u64 a, size_t s, bool ro) : m_address(a), m_size(s), m_read_only(ro) { /* ... */ }

                constexpr u64 GetAddress()  const { return m_address; }
                constexpr size_t GetSize()  const { return m_size; }
                constexpr bool IsReadOnly() const { return m_read_only; }
        };

        struct MappedRangeCompare {
            using RedBlackKeyType = uintptr_t;

            static constexpr ALWAYS_INLINE int Compare(const RedBlackKeyType a, const RedBlackKeyType &b) {
                if (a < b) {
                    return -1;
                } else if (a > b) {
                    return 1;
                } else {
                    return 0;
                }
            }

            static constexpr ALWAYS_INLINE int Compare(const RedBlackKeyType &a, const MappedRange &b) {
                return Compare(a, b.GetAddress());
            }

            static constexpr ALWAYS_INLINE int Compare(const MappedRange &a, const MappedRange &b) {
                return Compare(a.GetAddress(), b.GetAddress());
            }
        };

        using MappedRangeTree = util::IntrusiveRedBlackTreeBaseTraits<MappedRange>::TreeType<MappedRangeCompare>;

        struct MappedRangeHolder {
            private:
                MappedRangeTree m_tree;
            public:
                MappedRangeHolder() : m_tree() { /* ... */ }

                ~MappedRangeHolder() {
                    while (!m_tree.empty()) {
                        auto it = m_tree.begin();
                        while (it != m_tree.end()) {
                            auto *region = std::addressof(*it);
                            it = m_tree.erase(it);
                            delete region;
                        }
                    }
                }

                void Insert(u64 a, size_t s, bool ro) {
                    m_tree.insert(*(new MappedRange(a, s, ro)));
                }

                auto begin() const { return m_tree.begin(); }
                auto end() const { return m_tree.end(); }
        };

        const char *GetSystemCallName(size_t i) {
            #define EMPTY_HANDLER(TYPE, NAME)
            #define RETURN_NAME_HANDLER(ID, _, NAME, ...) if (i == ID) { return #NAME ; }
            AMS_SVC_FOREACH_DEFINITION_IMPL(RETURN_NAME_HANDLER, _, EMPTY_HANDLER, EMPTY_HANDLER, EMPTY_HANDLER, EMPTY_HANDLER)
            #undef EMPTY_HANDLER
            #undef RETURN_NAME_HANDLER

            return "Unknown";
        }

        class AccessControlEntry {
            private:
                const u8 *m_entry;
                size_t m_capacity;
            public:
                AccessControlEntry(const void *e, size_t c) : m_entry(static_cast<const u8 *>(e)), m_capacity(c) {
                    /* ... */
                }

                AccessControlEntry GetNextEntry() const {
                    return AccessControlEntry(m_entry + this->GetSize(), m_capacity - this->GetSize());
                }

                size_t GetSize() const {
                    return this->GetServiceNameSize() + 1;
                }

                size_t GetServiceNameSize() const {
                    return (m_entry[0] & 7) + 1;
                }

                sm::ServiceName GetServiceName() const {
                    return sm::ServiceName::Encode(reinterpret_cast<const char *>(m_entry + 1), this->GetServiceNameSize());
                }

                bool IsHost() const {
                    return (m_entry[0] & 0x80) != 0;
                }

                bool IsWildcard() const {
                    return m_entry[this->GetServiceNameSize()] == '*';
                }

                bool IsValid() const {
                    /* Validate that we can access data. */
                    if (m_entry == nullptr || m_capacity == 0) {
                        return false;
                    }

                    /* Validate that the size is correct. */
                    return this->GetSize() <= m_capacity;
                }

                void GetName(char *dst) {
                    std::memcpy(dst, m_entry + 1, this->GetServiceNameSize());
                    dst[this->GetServiceNameSize()] = 0;
                }
        };

        bool IsAllowedAccessControl(AccessControlEntry access_control, sm::ServiceName service, bool is_host, bool is_wildcard) {
            /* Iterate over all entries in the access control, checking to see if we have a match. */
            while (access_control.IsValid()) {
                if (access_control.IsHost() == is_host) {
                    bool is_valid = true;

                    if (access_control.IsWildcard() == is_wildcard) {
                        /* Check for exact match. */
                        is_valid &= access_control.GetServiceName() == service;
                    } else if (access_control.IsWildcard()) {
                        /* Also allow fuzzy match for wildcard. */
                        sm::ServiceName ac_service = access_control.GetServiceName();
                        is_valid &= std::memcmp(std::addressof(ac_service), std::addressof(service), access_control.GetServiceNameSize() - 1) == 0;
                    }

                    if (is_valid) {
                        return true;
                    }
                }
                access_control = access_control.GetNextEntry();
            }

            return false;
        }

        struct ParsedKernelCapabilities {
            util::optional<util::BitPack32> core_prio = util::nullopt;
            SystemCallFlagSet system_calls{};
            InterruptFlagSet interrupts{};
            util::optional<util::BitPack32> program_type   = util::nullopt;
            util::optional<util::BitPack32> kernel_version = util::nullopt;
            util::optional<util::BitPack32> handle_table   = util::nullopt;
            util::optional<util::BitPack32> debug_flags    = util::nullopt;
            util::optional<util::BitPack32> mapped_regions = util::nullopt;

            MappedRangeHolder mapped_static_ranges{};
            MappedRangeHolder mapped_io_ranges{};
            util::optional<util::BitPack32> unknown_caps[0x40]{};
            size_t num_unknown_caps = 0;
        };

        void ParseKernelCapabilities(ParsedKernelCapabilities *out, const util::BitPack32 *caps, size_t num_caps) {
            /* Walk all caps. */
            for (size_t i = 0; i < num_caps; ++i) {
                switch (GetCapabilityType(caps[i])) {
                    using enum CapabilityType;
                    case CorePriority:
                        if (out->core_prio.has_value()) {
                            fprintf(stderr, "[Warning]: KernelAccessControl contains multiple CorePriority capabilities\n");
                        }
                        out->core_prio = caps[i];
                        break;
                    case SyscallMask:
                        {
                            const auto mask  = caps[i].Get<SyscallMask::Mask>();
                            const auto index = caps[i].Get<SyscallMask::Index>();

                            for (size_t n = 0; n < SyscallMask::Mask::Count; ++n) {
                                const u32 svc_id = SyscallMask::Mask::Count * index + n;
                                if (mask & (1u << n)) {
                                    out->system_calls[svc_id] = true;
                                }
                            }
                        }
                        break;
                    case MapRange:
                        {
                            if (i + 1 < num_caps) {
                                const auto cap      = caps[i++];
                                const auto size_cap = caps[i];
                                if (GetCapabilityType(size_cap) == MapRange) {
                                    const u64 phys_addr = static_cast<u64>(cap.Get<MapRange::Address>() | (size_cap.Get<MapRangeSize::AddressHigh>() << MapRange::Address::Count)) * os::MemoryPageSize;

                                    const size_t num_pages = size_cap.Get<MapRangeSize::Pages>();
                                    const size_t size      = num_pages * os::MemoryPageSize;

                                    const bool is_ro = cap.Get<MapRange::ReadOnly>();
                                    if (size_cap.Get<MapRangeSize::Normal>()) {
                                        out->mapped_static_ranges.Insert(phys_addr, size, is_ro);
                                    } else {
                                        out->mapped_io_ranges.Insert(phys_addr, size, is_ro);
                                    }
                                } else {
                                    fprintf(stderr, "[Warning]: KernelAccessControl contains invalid MapRange pair\n");
                                }
                            } else {
                                fprintf(stderr, "[Warning]: KernelAccessControl truncates during MapRange pair\n");
                            }
                        }
                        break;
                    case MapIoPage:
                        {
                            const u64 phys_addr = caps[i].Get<MapIoPage::Address>() * os::MemoryPageSize;
                            out->mapped_io_ranges.Insert(phys_addr, os::MemoryPageSize, false);
                        }
                        break;
                    case MapRegion:
                        if (out->mapped_regions.has_value()) {
                            fprintf(stderr, "[Warning]: KernelAccessControl contains multiple MapRegion capabilities\n");
                        }
                        out->mapped_regions = caps[i];
                        break;
                    case InterruptPair:
                        {
                            const u32 ids[2] = { caps[i].Get<InterruptPair::InterruptId0>(), caps[i].Get<InterruptPair::InterruptId1>(), };
                            for (size_t i = 0; i < util::size(ids); ++i) {
                                if (ids[i] != PaddingInterruptId) {
                                    out->interrupts[ids[i]] = true;
                                }
                            }
                        }
                        break;
                    case ProgramType:
                        if (out->program_type.has_value()) {
                            fprintf(stderr, "[Warning]: KernelAccessControl contains multiple ProgramType capabilities\n");
                        }
                        out->program_type = caps[i];
                        break;
                    case KernelVersion:
                        if (out->kernel_version.has_value()) {
                            fprintf(stderr, "[Warning]: KernelAccessControl contains multiple KernelVersion capabilities\n");
                        }
                        out->kernel_version = caps[i];
                        break;
                    case HandleTable:
                        if (out->handle_table.has_value()) {
                            fprintf(stderr, "[Warning]: KernelAccessControl contains multiple HandleTable capabilities\n");
                        }
                        out->handle_table = caps[i];
                        break;
                    case DebugFlags:
                        if (out->debug_flags.has_value()) {
                            fprintf(stderr, "[Warning]: KernelAccessControl contains multiple DebugFlags capabilities\n");
                        }
                        out->debug_flags = caps[i];
                        break;
                    case Invalid:
                        fprintf(stderr, "[Warning]: KernelAccessControl contains invalid capability\n");
                        break;
                    case Padding:
                        break;
                    default:
                        AMS_ABORT_UNLESS(out->num_unknown_caps < util::size(out->unknown_caps));
                        out->unknown_caps[out->num_unknown_caps++] = caps[i];
                        break;
                }
            }
        }

    }

    /* Procesing. */
    Result Processor::ProcessAsNpdm(std::shared_ptr<fs::IStorage> storage, ProcessAsNpdmContext *ctx) {
        /* Ensure we have a context. */
        ProcessAsNpdmContext local_ctx{};
        if (ctx == nullptr) {
            ctx = std::addressof(local_ctx);
        }

        /* Set the storage. */
        ctx->storage = std::move(storage);

        /* Get the npdm's size. */
        s64 total_size;
        R_TRY(ctx->storage->GetSize(std::addressof(total_size)));

        /* Basic sanity checks. */
        if (total_size > static_cast<s64>(32_KB)) {
            fprintf(stderr, "[Warning]: Npdm is much larger than expected. Is file type correct?\n");
            R_THROW(ldr::ResultMetaOverflow());
        }
        if (total_size < static_cast<s64>(sizeof(ldr::Npdm))) {
            fprintf(stderr, "[Warning]: Npdm is too small. Is file type correct?\n");
            R_THROW(ldr::ResultInvalidMeta());
        }

        /* Ensure size is small enough. */

        /* Allocate space to hold the npdm. */
        ctx->raw_data = std::make_unique<u8[]>(static_cast<size_t>(total_size));
        R_UNLESS(ctx->raw_data != nullptr, fs::ResultAllocationMemoryFailedMakeUnique());

        /* Read the npdm. */
        R_TRY(ctx->storage->Read(0, ctx->raw_data.get(), total_size));

        /* Begin processing. */
        const u8 *file_data = static_cast<const u8 *>(ctx->raw_data.get());

        /* Set npdm. */
        const auto *npdm = reinterpret_cast<const ldr::Npdm *>(file_data);
        R_TRY(ValidateNpdm(npdm, total_size));
        ctx->npdm = npdm;

        /* Npdm is valid, so try ACI. */
        const auto *acid = reinterpret_cast<const ldr::Acid *>(file_data + ctx->npdm->acid_offset);
        R_TRY(ValidateAcid(acid, ctx->npdm->acid_size));
        ctx->acid = acid;

        const auto *aci  = reinterpret_cast<const ldr::Aci *>(file_data + ctx->npdm->aci_offset);
        R_TRY(ValidateAci(aci, ctx->npdm->aci_size));
        ctx->aci = aci;

        /* Set remaining members. */
        ctx->acid_fac = file_data + ctx->npdm->acid_offset + acid->fac_offset;
        ctx->acid_sac = file_data + ctx->npdm->acid_offset + acid->sac_offset;
        ctx->acid_kac = file_data + ctx->npdm->acid_offset + acid->kac_offset;

        ctx->aci_fah = file_data + ctx->npdm->aci_offset + aci->fah_offset;
        ctx->aci_sac = file_data + ctx->npdm->aci_offset + aci->sac_offset;
        ctx->aci_kac = file_data + ctx->npdm->aci_offset + aci->kac_offset;

        ctx->modulus = acid->modulus;

        /* Print. */
        if (ctx == std::addressof(local_ctx)) {
            this->PrintAsNpdm(*ctx);
        }

        /* Save. */
        if (ctx == std::addressof(local_ctx)) {
            this->SaveAsNpdm(*ctx);
        }

        R_SUCCEED();
    }

    /* Printing. */
    void Processor::PrintAsNpdm(ProcessAsNpdmContext &ctx) {
        if (ctx.npdm == nullptr) {
            return;
        }

        auto _ = this->PrintHeader("NPDM");

        this->PrintMagic(ctx.npdm->magic);

        this->PrintHex2("Flags", ctx.npdm->flags);
        {
            auto _ = this->IncreaseIndentation();

            using enum ldr::Npdm::MetaFlag;
            using enum ldr::Npdm::AddressSpaceType;

            this->PrintBool("Is64Bit", ctx.npdm->flags & MetaFlag_Is64Bit);

            switch (static_cast<ldr::Npdm::AddressSpaceType>((ctx.npdm->flags & MetaFlag_AddressSpaceTypeMask) >> MetaFlag_AddressSpaceTypeShift)) {
                case AddressSpaceType_32Bit:             this->PrintString("Address Space Type", "32Bit");             break;
                case AddressSpaceType_64BitDeprecated:   this->PrintString("Address Space Type", "64BitDeprecated");   break;
                case AddressSpaceType_32BitWithoutAlias: this->PrintString("Address Space Type", "32BitWithoutAlias"); break;
                case AddressSpaceType_64Bit:             this->PrintString("Address Space Type", "64Bit");             break;
            }

            this->PrintBool("Optimize Memory Allocation", ctx.npdm->flags & MetaFlag_OptimizeMemoryAllocation);
            this->PrintBool("Disable Device Address Space Merge", ctx.npdm->flags & MetaFlag_DisableDeviceAddressSpaceMerge);
        }
        this->PrintInteger("Main Thread Priority", ctx.npdm->main_thread_priority);
        this->PrintInteger("Default Cpu Id", ctx.npdm->default_cpu_id);
        this->PrintFormat("Version", "%" PRIu32 ".%" PRIu32 ".%" PRIu32 ".%" PRIu32 " (%" PRIu32")", (ctx.npdm->version >> 26) & 0x3F, (ctx.npdm->version >> 20) & 0x3F, (ctx.npdm->version >> 16) & 0x3F, (ctx.npdm->version >> 0) & 0xFFFF, ctx.npdm->version);
        this->PrintHex("Main Thread Stack Size", ctx.npdm->main_thread_stack_size);
        this->PrintHex("System Resource Size", ctx.npdm->system_resource_size);
        this->PrintString("Program Name", ctx.npdm->program_name);

        /* Print acid, if present. */
        if (ctx.acid != nullptr) {
            auto _ = this->PrintHeader("ACID");

            this->PrintMagic(ctx.acid->magic);

            this->PrintHex("Version", ctx.acid->version);

            this->PrintHex("Sign Key Generation", ctx.npdm->signature_key_generation);

            this->PrintBytes("Signature", ctx.acid->signature, sizeof(ctx.acid->signature));
            this->PrintBytes("HeaderSign2 Modulus", ctx.acid->modulus, sizeof(ctx.acid->modulus));

            this->PrintHex2("Flags", ctx.acid->flags);
            {
                auto _ = this->IncreaseIndentation();

                using enum ldr::Acid::AcidFlag;
                using enum ldr::Acid::PoolPartition;

                this->PrintBool("Production", ctx.acid->flags & AcidFlag_Production);
                this->PrintBool("Unqualified Approval", ctx.acid->flags & AcidFlag_UnqualifiedApproval);

                switch (static_cast<ldr::Acid::PoolPartition>((ctx.acid->flags & AcidFlag_PoolPartitionMask) >> AcidFlag_PoolPartitionShift)) {
                    case PoolPartition_Application:     this->PrintString("Pool Partition", "Application");     break;
                    case PoolPartition_Applet:          this->PrintString("Pool Partition", "Applet");          break;
                    case PoolPartition_System:          this->PrintString("Pool Partition", "System");          break;
                    case PoolPartition_SystemNonSecure: this->PrintString("Pool Partition", "SystemNonSecure"); break;
                }

                this->PrintFormat("Program Id Range", "%016" PRIX64 "-%016" PRIX64, ctx.acid->program_id_min.value, ctx.acid->program_id_max.value);
            }
        }

        /* Print aci, if present. */
        if (ctx.aci != nullptr) {
            auto _ = this->PrintHeader("ACI");

            this->PrintMagic(ctx.aci->magic);

            this->PrintId64("Program Id", ctx.aci->program_id.value);
        }

        /* Print kernel access control. */
        {
            auto PrintKernelAccessControl = [&] (const char *name, const util::BitPack32 *caps, size_t num_caps) {
                auto _ = this->PrintHeader(name);

                ParsedKernelCapabilities parsed;
                ParseKernelCapabilities(std::addressof(parsed), caps, num_caps);

                /* Print parsed caps. */
                if (parsed.core_prio.has_value()) {
                    const auto cap = parsed.core_prio.value();
                    this->PrintInteger("Lowest Thread Priority", cap.Get<CorePriority::LowestThreadPriority>());
                    this->PrintInteger("Highest Thread Priority", cap.Get<CorePriority::HighestThreadPriority>());
                    this->PrintInteger("Minimum Core Id", cap.Get<CorePriority::MinimumCoreId>());
                    this->PrintInteger("Maximum Core Id", cap.Get<CorePriority::MaximumCoreId>());
                }

                /* Print system calls. */
                {
                    const char *field_name = "Allowed System Calls";
                    for (size_t i = 0; i < SystemCallCount; ++i) {
                        if (!parsed.system_calls[i]) {
                            continue;
                        }

                        this->PrintFormat(field_name, "%-35s (0x%02" PRIX32 ")", GetSystemCallName(i), static_cast<u32>(i));
                        field_name = "";
                    }
                }

                /* Print mapped io ranges. */
                {
                    const char *field_name = "Mapped Io Ranges";
                    for (const auto &range : parsed.mapped_io_ranges) {
                        this->PrintFormat(field_name, "(%010" PRIX64 "-%010" PRIX64 ", %s", range.GetAddress(), range.GetAddress() + range.GetSize(), range.IsReadOnly() ? "R--" : "RW-");
                        field_name = "";
                    }
                }

                /* Print mapped normal ranges. */
                {
                    const char *field_name = "Mapped Normal Ranges";
                    for (const auto &range : parsed.mapped_static_ranges) {
                        this->PrintFormat(field_name, "(%010" PRIX64 "-%010" PRIX64 ", %s", range.GetAddress(), range.GetAddress() + range.GetSize(), range.IsReadOnly() ? "R--" : "RW-");
                        field_name = "";
                    }
                }

                /* Print mapped regions. */
                if (parsed.mapped_regions.has_value()) {
                    /* Extract regions/read only. */
                    const auto cap = parsed.mapped_regions.value();

                    const RegionType types[3] = { cap.Get<MapRegion::Region0>(),   cap.Get<MapRegion::Region1>(),   cap.Get<MapRegion::Region2>(), };
                    const bool          ro[3] = { cap.Get<MapRegion::ReadOnly0>(), cap.Get<MapRegion::ReadOnly1>(), cap.Get<MapRegion::ReadOnly2>(), };

                    const char *field_name = "Mapped Regions";
                    for (size_t i = 0; i < util::size(types); ++i) {
                        switch (types[i]) {
                            using enum RegionType;
                            case None:
                                break;
                            case KernelTraceBuffer:
                                this->PrintFormat(field_name, "KernelTraceBuffer (%s)", ro[i] ? "R--" : "RW-");
                                field_name = "";
                                break;
                            case OnMemoryBootImage:
                                this->PrintFormat(field_name, "OnMemoryBootImage (%s)", ro[i] ? "R--" : "RW-");
                                field_name = "";
                                break;
                            case DTB:
                                this->PrintFormat(field_name, "DeviceTreeBlob (%s)", ro[i] ? "R--" : "RW-");
                                field_name = "";
                                break;
                            default:
                                this->PrintFormat(field_name, "Unknown (%d) (%s)", static_cast<int>(types[i]), ro[i] ? "R--" : "RW-");
                                field_name = "";
                                break;
                        }
                    }
                }

                /* Print interrupts. */
                {
                    const char *field_name = "Mapped Interrupts";
                    for (size_t i = 0; i < InterruptIdCount; ++i) {
                        if (!parsed.interrupts[i]) {
                            continue;
                        }

                        this->PrintFormat(field_name, "0x%03" PRIX32, static_cast<u32>(i));
                        field_name = "";
                    }
                }

                /* Program Type. */
                if (parsed.program_type.has_value()) {
                    const auto type = parsed.program_type.value().Get<ProgramType::Type>();
                    switch (type) {
                        case 0: this->PrintString("Program Type", "System Program"); break;
                        case 1: this->PrintString("Program Type", "Application");    break;
                        case 2: this->PrintString("Program Type", "Applet");         break;
                        default:
                            this->PrintFormat("Program Type", "Unknown (%d)", static_cast<int>(type));
                            break;
                    }
                }

                /* Kernel Version. */
                if (parsed.kernel_version.has_value()) {
                    const u32 major = parsed.kernel_version.value().Get<KernelVersion::MajorVersion>();
                    const u32 minor = parsed.kernel_version.value().Get<KernelVersion::MinorVersion>();

                    this->PrintFormat("Minimum Kernel Version", "%" PRIu32 ".%" PRIu32, major, minor);
                }

                /* Handle Table. */
                if (parsed.handle_table.has_value()) {
                    this->PrintInteger("Handle Table Size", static_cast<int>(parsed.handle_table.value().Get<HandleTable::Size>()));
                }

                /* Debug flags. */
                if (parsed.debug_flags.has_value()) {
                    this->PrintBool("Allow Debug", parsed.debug_flags.value().Get<DebugFlags::AllowDebug>());
                    this->PrintBool("Force Debug", parsed.debug_flags.value().Get<DebugFlags::ForceDebug>());
                }

                /* Unknown capabilities. */
                {
                    const char *field_name = "Unknown Capabilities";
                    for (size_t i = 0; i < parsed.num_unknown_caps; ++i) {
                        const auto type = GetCapabilityType(parsed.unknown_caps[i].value());
                        this->PrintFormat(field_name, "(Type %d, Value 0x%08" PRIX32 ")", static_cast<int>(type), parsed.unknown_caps[i].value().value);
                    }
                }
            };

            if (ctx.acid_kac != nullptr && ctx.aci_kac != nullptr && ctx.acid->kac_size == ctx.aci->kac_size && std::memcmp(ctx.acid_kac, ctx.aci_kac, ctx.acid->kac_size) == 0) {
                PrintKernelAccessControl("Kernel Access Control", static_cast<const util::BitPack32 *>(ctx.acid_kac), ctx.acid->kac_size / sizeof(util::BitPack32));
            } else {
                if (ctx.acid_kac != nullptr) {
                    PrintKernelAccessControl("Acid Kernel Access Control", static_cast<const util::BitPack32 *>(ctx.acid_kac), ctx.acid->kac_size / sizeof(util::BitPack32));
                }

                if (ctx.aci_kac != nullptr) {
                    PrintKernelAccessControl("Aci Kernel Access Control", static_cast<const util::BitPack32 *>(ctx.aci_kac), ctx.aci->kac_size / sizeof(util::BitPack32));
                }
            }
        }

        /* Print Service Access Control. */
        if (ctx.acid_sac != nullptr && ctx.aci_sac != nullptr) {
            auto PrintServiceAccessControl = [&] (const char *name, AccessControlEntry access_control, auto get_allowed_summary) {
                auto _ = this->PrintHeader(name);

                const char *field_name = "Hosts";
                for (auto cur = access_control; cur.IsValid(); cur = cur.GetNextEntry()) {
                    if (cur.IsHost()) {
                        char name[sizeof(sm::ServiceName) + 1];
                        cur.GetName(name);

                        this->PrintFormat(field_name, "%-16s%s", name, get_allowed_summary(cur));
                        field_name = "";
                    }
                }

                field_name = "Accesses";
                for (auto cur = access_control; cur.IsValid(); cur = cur.GetNextEntry()) {
                    if (!cur.IsHost()) {
                        char name[sizeof(sm::ServiceName) + 1];
                        cur.GetName(name);

                        this->PrintFormat(field_name, "%-16s%s", name, get_allowed_summary(cur));
                        field_name = "";
                    }
                }
            };

            AccessControlEntry restriction(ctx.acid_sac, ctx.acid->sac_size);
            AccessControlEntry access_control(ctx.aci_sac, ctx.aci->sac_size);

            PrintServiceAccessControl("Service Access Control", access_control, [&] (AccessControlEntry entry) -> const char * {
                if (IsAllowedAccessControl(restriction, entry.GetServiceName(), entry.IsHost(), entry.IsWildcard())) {
                    return "";
                } else {
                    return "(Invalid)";
                }
            });

            if (ctx.acid->sac_size != ctx.aci->sac_size || std::memcmp(ctx.acid_sac, ctx.aci_sac, ctx.acid->sac_size) != 0) {
                PrintServiceAccessControl("Service Access Control Restrictiction", restriction, [&] (AccessControlEntry) -> const char * {
                    return "";
                });
            }
        }

        /* Print FileSystem Access Control. */
        if (ctx.acid_fac != nullptr && ctx.aci_fah != nullptr){
            auto _ = this->PrintHeader("FileSystem Access Control");

            /* Get the old debug flag. */
            const bool is_fssrv_debug = fssrv::IsDebugFlagEnabled();
            ON_SCOPE_EXIT { fssrv::SetDebugFlagEnabled(is_fssrv_debug); };

            /* Create access controls. */
            fssrv::SetDebugFlagEnabled(true);
            fssrv::impl::AccessControl access_control(ctx.aci_fah, ctx.aci->fah_size, ctx.acid_fac, ctx.acid->fac_size);

            fssrv::SetDebugFlagEnabled(false);
            fssrv::impl::AccessControl access_control_no_debug(ctx.aci_fah, ctx.aci->fah_size, ctx.acid_fac, ctx.acid->fac_size);

            /* Print raw permissions. */
            this->PrintHex16("Raw AccessControlBits", access_control.GetRawFlagBits());

            const char *field_name = "AccessControlBits";
            for (size_t i = 0; i < BITSIZEOF(u64); ++i) {
                const u64 mask = UINT64_C(1) << i;
                if (access_control.GetRawFlagBits() & mask) {
                    this->PrintString(field_name, fs::impl::IdString().ToString(static_cast<fssrv::impl::AccessControlBits::Bits>(mask)));
                    field_name = "";
                }
            }

            /* Print accessibilities. */
            field_name = "Accessibilities";
            for (s32 i = 0; i < static_cast<s32>(fssrv::impl::AccessControl::AccessibilityType::Count); ++i) {
                /* Convert to type. */
                const auto type = static_cast<fssrv::impl::AccessControl::AccessibilityType>(i);

                /* Get the accessibilities. */
                fssrv::SetDebugFlagEnabled(false);
                const auto accessibility_no_debug = access_control_no_debug.GetAccessibilityFor(type);

                if (accessibility_no_debug.CanRead() || accessibility_no_debug.CanWrite()) {
                    this->PrintFormat(field_name, "%-44s (%c%c)", fs::impl::IdString().ToString(type), accessibility_no_debug.CanRead() ? 'R' : '-', accessibility_no_debug.CanWrite() ? 'W' : '-');
                    field_name = "";
                }
            }

            /* Print debug accessibilities. */
            field_name = "Debug-Only Accessibilities";
            for (s32 i = 0; i < static_cast<s32>(fssrv::impl::AccessControl::AccessibilityType::Count); ++i) {
                /* Convert to type. */
                const auto type = static_cast<fssrv::impl::AccessControl::AccessibilityType>(i);

                /* Get the accessibilities. */
                fssrv::SetDebugFlagEnabled(true);
                const auto accessibility = access_control.GetAccessibilityFor(type);
                fssrv::SetDebugFlagEnabled(false);
                const auto accessibility_no_debug = access_control_no_debug.GetAccessibilityFor(type);

                /* Ensure that the debug is a superset of the non-debug. */
                AMS_ABORT_UNLESS(!accessibility_no_debug.CanRead() || accessibility.CanRead());
                AMS_ABORT_UNLESS(!accessibility_no_debug.CanWrite() || accessibility.CanWrite());

                if ((accessibility.CanRead() && !accessibility_no_debug.CanRead()) || (accessibility.CanWrite() && !accessibility_no_debug.CanWrite())) {
                    this->PrintFormat(field_name, "%-44s (%c%c)", fs::impl::IdString().ToString(type), accessibility.CanRead() ? 'R' : '-', accessibility.CanWrite() ? 'W' : '-');
                    field_name = "";
                }
            }

            /* Print operations. */
            field_name = "Operations";
            for (s32 i = 0; i < static_cast<s32>(fssrv::impl::AccessControl::OperationType::Count); ++i) {
                /* Convert to type. */
                const auto type = static_cast<fssrv::impl::AccessControl::OperationType>(i);
                if (type == fssrv::impl::AccessControl::OperationType::Debug) {
                    continue;
                }

                /* Get the callabilities. */
                fssrv::SetDebugFlagEnabled(false);
                const auto can_call_no_debug = access_control_no_debug.CanCall(type);

                if (can_call_no_debug) {
                    this->PrintString(field_name, fs::impl::IdString().ToString(type));
                    field_name = "";
                }
            }

            /* Print debug operations. */
            field_name = "Debug-Only Operations";
            for (s32 i = 0; i < static_cast<s32>(fssrv::impl::AccessControl::OperationType::Count); ++i) {
                /* Convert to type. */
                const auto type = static_cast<fssrv::impl::AccessControl::OperationType>(i);
                if (type == fssrv::impl::AccessControl::OperationType::Debug) {
                    continue;
                }

                /* Get the callabilities. */
                fssrv::SetDebugFlagEnabled(true);
                const auto can_call = access_control.CanCall(type);
                fssrv::SetDebugFlagEnabled(false);
                const auto can_call_no_debug = access_control_no_debug.CanCall(type);

                /* Ensure that the debug is a superset of the non-debug. */
                AMS_ABORT_UNLESS(!can_call_no_debug || can_call);

                if (can_call && !can_call_no_debug) {
                    this->PrintString(field_name, fs::impl::IdString().ToString(type));
                    field_name = "";
                }
            }

            /* Print Content Owner Ids. */
            field_name = "Content Owner Ids";
            s32 count;
            access_control.ListContentOwnerId(std::addressof(count), nullptr, 0, 0);
            {
                u64 content_owner_ids[16];
                s32 ofs = 0;
                while (ofs < count) {
                    s32 cur_read = 0;
                    access_control.ListContentOwnerId(std::addressof(cur_read), content_owner_ids, ofs, static_cast<int>(util::size(content_owner_ids)));

                    for (s32 i = 0; i < cur_read; ++i) {
                        this->PrintId64(field_name, content_owner_ids[i]);
                        field_name = "";
                    }

                    ofs += cur_read;
                }
            }

            /* Print SaveDataOwnerIds. */
            field_name = "SaveData Owned Ids";
            access_control.ListSaveDataOwnedId(std::addressof(count), nullptr, 0, 0);
            {
                ncm::ApplicationId save_data_owned_id[16];
                s32 ofs = 0;
                while (ofs < count) {
                    s32 cur_read = 0;
                    access_control.ListSaveDataOwnedId(std::addressof(cur_read), save_data_owned_id, ofs, static_cast<int>(util::size(save_data_owned_id)));

                    for (s32 i = 0; i < cur_read; ++i) {
                        const u64 id = save_data_owned_id[i].value;
                        const auto accessibility = access_control.GetAccessibilitySaveDataOwnedBy(id);

                        this->PrintFormat(field_name, "%016" PRIX64 " (%c%c)", id, accessibility.CanRead() ? 'R' : '-', accessibility.CanWrite() ? 'W' : '-');
                        field_name = "";
                    }

                    ofs += cur_read;
                }
            }
        }
    }

    /* Saving. */
    void Processor::SaveAsNpdm(ProcessAsNpdmContext &ctx) {
        /* If we should, save the npdm as json. */
        if (m_options.json_out_file_path != nullptr) {
            if (ctx.npdm == nullptr || ctx.acid == nullptr || ctx.aci == nullptr) {
                fprintf(stderr, "[Warning]: Could not save invalid npdm to %s\n", m_options.json_out_file_path);
                return;
            }

            /* Create the json document. */
            rapidjson::Document d;
            d.SetObject();
            {
                /* Helper for adding strings to json. */
                auto AddFormatString = [&d] (auto &target, const char *name, const char *fmt, ...) __attribute__((format(printf, 4, 5))) {
                    char tmp[1_KB];

                    std::va_list vl;
                    va_start(vl, fmt);
                    const auto len = util::TVSNPrintf(tmp, sizeof(tmp), fmt, vl);
                    va_end(vl);

                    target.AddMember(rapidjson::StringRef(name), rapidjson::Value().SetString(tmp, len, d.GetAllocator()), d.GetAllocator());
                };
                auto AddString = [&] (auto &target, const char *name, const char *v) { AddFormatString(target, name, "%s", v);    };
                auto AddU64    = [&] (auto &target, const char *name, u64 v) { AddFormatString(target, name, "0x%016" PRIX64, v); };
                auto AddU32    = [&] (auto &target, const char *name, u32 v) { AddFormatString(target, name, "0x%08" PRIX32, v);  };
                auto AddInt    = [&] (auto &target, const char *name, int v) { target.AddMember(rapidjson::StringRef(name), rapidjson::Value().SetInt(v), d.GetAllocator()); };
                auto AddBool   = [&] (auto &target, const char *name, bool v) { target.AddMember(rapidjson::StringRef(name), rapidjson::Value().SetBool(v), d.GetAllocator()); };

                /* Add the npdm's meta information. */
                AddString(d, "name", ctx.npdm->program_name);
                AddInt(d, "signature_key_generation", ctx.npdm->signature_key_generation);
                AddU64(d, "program_id", ctx.aci->program_id.value);
                AddU64(d, "program_id_range_min", ctx.acid->program_id_min.value);
                AddU64(d, "program_id_range_max", ctx.acid->program_id_max.value);
                AddU32(d, "main_thread_stack_size", ctx.npdm->main_thread_stack_size);
                AddInt(d, "main_thread_priority", ctx.npdm->main_thread_priority);
                AddInt(d, "default_cpu_id", ctx.npdm->default_cpu_id);
                AddU32(d, "version", ctx.npdm->version);
                AddBool(d, "is_retail", ctx.acid->flags & ldr::Acid::AcidFlag_Production);
                AddBool(d, "unqualified_approval", ctx.acid->flags & ldr::Acid::AcidFlag_UnqualifiedApproval);
                AddInt(d, "pool_partition", (ctx.acid->flags & ldr::Acid::AcidFlag_PoolPartitionMask) >> ldr::Acid::AcidFlag_PoolPartitionShift);
                AddBool(d, "is_64_bit", ctx.npdm->flags & ldr::Npdm::MetaFlag_Is64Bit);
                AddInt(d, "address_space_type", ctx.npdm->flags & (ctx.npdm->flags & ldr::Npdm::MetaFlag_AddressSpaceTypeMask) >> ldr::Npdm::MetaFlag_AddressSpaceTypeShift);
                AddBool(d, "optimize_memory_allocation", ctx.npdm->flags & ldr::Npdm::MetaFlag_OptimizeMemoryAllocation);
                AddBool(d, "disable_device_address_space_merge", ctx.npdm->flags & ldr::Npdm::MetaFlag_DisableDeviceAddressSpaceMerge);
                AddU32(d, "system_resource_size", ctx.npdm->system_resource_size);

                /* Add filesystem access control. */
                {
                    rapidjson::Value filesystem_access(rapidjson::kObjectType);
                    {
                        /* Get the old debug flag. */
                        const bool is_fssrv_debug = fssrv::IsDebugFlagEnabled();
                        ON_SCOPE_EXIT { fssrv::SetDebugFlagEnabled(is_fssrv_debug); };

                        /* Create access controls. */
                        fssrv::SetDebugFlagEnabled(true);
                        fssrv::impl::AccessControl access_control(ctx.aci_fah, ctx.aci->fah_size, ctx.acid_fac, ctx.acid->fac_size);

                        /* Add permissions. */
                        AddU64(filesystem_access, "permissions", access_control.GetRawFlagBits());

                        /* Add content owner ids. */
                        {
                            rapidjson::Value content_owner_ids(rapidjson::kArrayType);
                            {
                                s32 count;
                                access_control.ListContentOwnerId(std::addressof(count), nullptr, 0, 0);
                                u64 id_values[16];
                                s32 ofs = 0;
                                while (ofs < count) {
                                    s32 cur_read = 0;
                                    access_control.ListContentOwnerId(std::addressof(cur_read), id_values, ofs, static_cast<int>(util::size(id_values)));

                                    for (s32 i = 0; i < cur_read; ++i) {
                                        char tmp[0x20];
                                        const auto len = util::TSNPrintf(tmp, sizeof(tmp), "0x%016" PRIX64, id_values[i]);
                                        content_owner_ids.PushBack(rapidjson::Value().SetString(tmp, len, d.GetAllocator()), d.GetAllocator());
                                    }

                                    ofs += cur_read;
                                }
                            }
                            filesystem_access.AddMember(rapidjson::StringRef("content_owner_ids"), content_owner_ids, d.GetAllocator());
                        }

                        /* Print save data owned ids. */
                        {
                            rapidjson::Value save_data_owned_ids(rapidjson::kArrayType);
                            {
                                s32 count;
                                access_control.ListSaveDataOwnedId(std::addressof(count), nullptr, 0, 0);

                                ncm::ApplicationId id_values[16];
                                s32 ofs = 0;
                                while (ofs < count) {
                                    s32 cur_read = 0;
                                    access_control.ListSaveDataOwnedId(std::addressof(cur_read), id_values, ofs, static_cast<int>(util::size(id_values)));

                                    for (s32 i = 0; i < cur_read; ++i) {
                                        rapidjson::Value save_data_owned(rapidjson::kObjectType);
                                        AddInt(save_data_owned, "accessibility", access_control.GetAccessibilitySaveDataOwnedBy(id_values[i].value).value);
                                        AddU64(save_data_owned, "id", id_values[i].value);

                                        save_data_owned_ids.PushBack(save_data_owned, d.GetAllocator());
                                    }

                                    ofs += cur_read;
                                }
                            }
                            filesystem_access.AddMember(rapidjson::StringRef("save_data_owner_ids"), save_data_owned_ids, d.GetAllocator());
                        }
                    }
                    d.AddMember(rapidjson::StringRef("filesystem_access"), filesystem_access, d.GetAllocator());
                }

                /* Add service access control. */
                {
                    rapidjson::Value service_access(rapidjson::kArrayType);
                    rapidjson::Value service_host(rapidjson::kArrayType);

                    AccessControlEntry restriction(ctx.acid_sac, ctx.acid->sac_size);
                    AccessControlEntry access_control(ctx.aci_sac, ctx.aci->sac_size);

                    for (auto cur = access_control; cur.IsValid(); cur = cur.GetNextEntry()) {
                        if (!IsAllowedAccessControl(restriction, cur.GetServiceName(), cur.IsHost(), cur.IsWildcard())) {
                            continue;
                        }

                        char name[sizeof(sm::ServiceName) + 1] = {};
                        cur.GetName(name);

                        if (cur.IsHost()) {
                            service_host.PushBack(rapidjson::Value().SetString(name, d.GetAllocator()), d.GetAllocator());
                        } else {
                            service_access.PushBack(rapidjson::Value().SetString(name, d.GetAllocator()), d.GetAllocator());
                        }
                    }

                    d.AddMember(rapidjson::StringRef("service_access"), service_access, d.GetAllocator());
                    d.AddMember(rapidjson::StringRef("service_host"), service_host, d.GetAllocator());
                }

                /* Add kernel capabilities. */
                {
                    rapidjson::Value kernel_capabilities(rapidjson::kArrayType);
                    {
                        /* Parse kernel capabilities. */
                        ParsedKernelCapabilities parsed;
                        ParseKernelCapabilities(std::addressof(parsed), static_cast<const util::BitPack32 *>(ctx.aci_kac), ctx.aci->kac_size / sizeof(util::BitPack32));

                        /* Core/Priority. */
                        if (parsed.core_prio.has_value()) {
                            const auto cap = parsed.core_prio.value();

                            rapidjson::Value k(rapidjson::kObjectType);
                            AddString(k, "type", "kernel_flags");
                            {
                                rapidjson::Value v(rapidjson::kObjectType);
                                AddInt(v, "lowest_thread_priority", cap.Get<CorePriority::LowestThreadPriority>());
                                AddInt(v, "highest_thread_priority", cap.Get<CorePriority::HighestThreadPriority>());
                                AddInt(v, "lowest_cpu_id", cap.Get<CorePriority::MinimumCoreId>());
                                AddInt(v, "highest_cpu_id", cap.Get<CorePriority::MaximumCoreId>());
                                k.AddMember(rapidjson::StringRef("value"), v, d.GetAllocator());
                            }

                            kernel_capabilities.PushBack(k, d.GetAllocator());
                        }

                        /* System calls. */
                        {
                            rapidjson::Value k(rapidjson::kObjectType);
                            AddString(k, "type", "syscalls");

                            {
                                rapidjson::Value v(rapidjson::kObjectType);
                                for (size_t i = 0; i < SystemCallCount; ++i) {
                                    if (parsed.system_calls[i]) {
                                        const char *name = GetSystemCallName(i);
                                        if (std::strcmp(name, "Unknown") != 0) {
                                            AddFormatString(v, name, "0x%02" PRIXZ, i);
                                        } else {
                                            char key_str[0x20];
                                            char val_str[0x20];
                                            util::TSNPrintf(key_str, sizeof(key_str), "Unknown%02" PRIXZ, i);
                                            util::TSNPrintf(val_str, sizeof(val_str), "0x%02" PRIXZ, i);

                                            v.AddMember(rapidjson::Value().SetString(key_str, d.GetAllocator()), rapidjson::Value().SetString(val_str, d.GetAllocator()), d.GetAllocator());
                                        }
                                    }
                                }
                                k.AddMember(rapidjson::StringRef("value"), v, d.GetAllocator());
                            }

                            kernel_capabilities.PushBack(k, d.GetAllocator());
                        }

                        /* Mappings. */
                        {
                            for (const auto &range : parsed.mapped_io_ranges) {
                                rapidjson::Value k(rapidjson::kObjectType);
                                if (range.GetSize() == os::MemoryPageSize && !range.IsReadOnly()) {
                                    AddString(k, "type", "map_page");

                                    AddU64(k, "value", range.GetAddress());
                                } else {
                                    AddString(k, "type", "map");

                                    rapidjson::Value v(rapidjson::kObjectType);
                                    AddU64(v, "address", range.GetAddress());
                                    AddU64(v, "size", range.GetSize());
                                    AddBool(v, "is_ro", range.IsReadOnly());
                                    AddBool(v, "is_io", true);
                                    k.AddMember(rapidjson::StringRef("value"), v, d.GetAllocator());
                                }

                                kernel_capabilities.PushBack(k, d.GetAllocator());
                            }
                            for (const auto &range : parsed.mapped_static_ranges) {
                                rapidjson::Value k(rapidjson::kObjectType);
                                AddString(k, "type", "map");
                                {
                                    rapidjson::Value v(rapidjson::kObjectType);
                                    AddU64(v, "address", range.GetAddress());
                                    AddU64(v, "size", range.GetSize());
                                    AddBool(v, "is_ro", range.IsReadOnly());
                                    AddBool(v, "is_io", false);
                                    k.AddMember(rapidjson::StringRef("value"), v, d.GetAllocator());
                                }

                                kernel_capabilities.PushBack(k, d.GetAllocator());
                            }
                        }

                        /* Mapped regions. */
                        if (parsed.mapped_regions.has_value()) {
                            rapidjson::Value k(rapidjson::kObjectType);
                            AddString(k, "type", "map_region");
                            {
                                rapidjson::Value v(rapidjson::kArrayType);

                                const auto cap = parsed.mapped_regions.value();
                                const RegionType types[3] = { cap.Get<MapRegion::Region0>(),   cap.Get<MapRegion::Region1>(),   cap.Get<MapRegion::Region2>(), };
                                const bool          ro[3] = { cap.Get<MapRegion::ReadOnly0>(), cap.Get<MapRegion::ReadOnly1>(), cap.Get<MapRegion::ReadOnly2>(), };

                                for (size_t i = 0; i < util::size(types); ++i) {
                                    rapidjson::Value r(rapidjson::kObjectType);
                                    AddInt(r, "region_type", static_cast<int>(types[i]));
                                    AddBool(r, "is_ro", ro[i]);
                                    v.PushBack(r, d.GetAllocator());
                                }

                                k.AddMember(rapidjson::StringRef("value"), v, d.GetAllocator());
                            }

                            kernel_capabilities.PushBack(k, d.GetAllocator());
                        }

                        /* Interrupts. */
                        {
                            u32 irq_ids[2] = { PaddingInterruptId, PaddingInterruptId };

                            auto FlushInterruptIds = [&]() {
                                rapidjson::Value k(rapidjson::kObjectType);
                                AddString(k, "type", "irq_pair");
                                {
                                    rapidjson::Value v(rapidjson::kArrayType);
                                    for (size_t i = 0; i < util::size(irq_ids); ++i) {
                                        if (irq_ids[i] != PaddingInterruptId) {
                                            v.PushBack(rapidjson::Value().SetInt(irq_ids[i]), d.GetAllocator());
                                        } else {
                                            v.PushBack(rapidjson::Value().SetNull(), d.GetAllocator());
                                        }

                                        irq_ids[i] = PaddingInterruptId;
                                    }

                                    k.AddMember(rapidjson::StringRef("value"), v, d.GetAllocator());
                                }

                                kernel_capabilities.PushBack(k, d.GetAllocator());
                            };

                            for (size_t i = 0; i < InterruptIdCount; ++i) {
                                if (!parsed.interrupts[i]) {
                                    continue;
                                }

                                if (irq_ids[0] == PaddingInterruptId) {
                                    irq_ids[0] = i;
                                } else {
                                    irq_ids[1] = i;
                                    FlushInterruptIds();
                                }
                            }

                            if (irq_ids[0] != PaddingInterruptId) {
                                FlushInterruptIds();
                            }
                        }


                        /* Program Type. */
                        if (parsed.program_type.has_value()) {
                            const auto cap = parsed.program_type.value();

                            rapidjson::Value k(rapidjson::kObjectType);
                            AddString(k, "type", "application_type");
                            AddInt(k, "value", cap.Get<ProgramType::Type>());

                            kernel_capabilities.PushBack(k, d.GetAllocator());
                        }

                        /* Kernel Version. */
                        if (parsed.kernel_version.has_value()) {
                            const auto cap = parsed.kernel_version.value();

                            rapidjson::Value k(rapidjson::kObjectType);
                            AddString(k, "type", "min_kernel_version");
                            {
                                const u32 major = cap.Get<KernelVersion::MajorVersion>();
                                const u32 minor = cap.Get<KernelVersion::MinorVersion>();
                                AddFormatString(k, "value", "0x%04" PRIX32, static_cast<u32>((major << 4) | minor));
                            }

                            kernel_capabilities.PushBack(k, d.GetAllocator());
                        }

                        /* Handle Table. */
                        if (parsed.handle_table.has_value()) {
                            const auto cap = parsed.handle_table.value();

                            rapidjson::Value k(rapidjson::kObjectType);
                            AddString(k, "type", "handle_table_size");
                            AddInt(k, "value", cap.Get<HandleTable::Size>());

                            kernel_capabilities.PushBack(k, d.GetAllocator());
                        }

                        /* Debug flags. */
                        if (parsed.debug_flags.has_value()) {
                            const auto cap = parsed.debug_flags.value();

                            rapidjson::Value k(rapidjson::kObjectType);
                            AddString(k, "type", "debug_flags");
                            {
                                rapidjson::Value v(rapidjson::kObjectType);
                                AddBool(v, "allow_debug", cap.Get<DebugFlags::AllowDebug>());
                                AddBool(v, "force_debug", cap.Get<DebugFlags::ForceDebug>());
                                k.AddMember(rapidjson::StringRef("value"), v, d.GetAllocator());
                            }

                            kernel_capabilities.PushBack(k, d.GetAllocator());
                        }

                        /* Unknown capabilities. */
                        if (parsed.num_unknown_caps > 0) {
                            fprintf(stderr, "[Warning]: Was unable to convert %" PRIuZ " unknown capabilities to JSON\n", parsed.num_unknown_caps);
                        }
                    }
                    d.AddMember(rapidjson::StringRef("kernel_capabilities"), kernel_capabilities, d.GetAllocator());
                }
            }

            /* Convert json to string. */
            rapidjson::StringBuffer str_buf;
            rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(str_buf);
            d.Accept(writer);

            /* Write the json. */
            printf("Saving Npdm JSON to %s...\n", m_options.json_out_file_path);
            SaveToFile(m_local_fs, m_options.json_out_file_path, str_buf.GetString(), str_buf.GetLength());
        }
    }

}