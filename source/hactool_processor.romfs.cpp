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

        /* Taken from fssrv::RomFileSystemCreator. */
        class RomFileSystemWithBuffer : public ::ams::fssystem::RomFsFileSystem {
            private:
                void *m_meta_cache_buffer;
                size_t m_meta_cache_buffer_size;
                MemoryResource *m_allocator;
            public:
                explicit RomFileSystemWithBuffer(MemoryResource *mr) : m_meta_cache_buffer(nullptr), m_allocator(mr) { /* ... */ }

                ~RomFileSystemWithBuffer() {
                    if (m_meta_cache_buffer != nullptr) {
                        m_allocator->Deallocate(m_meta_cache_buffer, m_meta_cache_buffer_size);
                    }
                }

                Result Initialize(std::shared_ptr<fs::IStorage> storage) {
                    /* Check if the buffer is eligible for cache. */
                    size_t buffer_size = 0;
                    if (R_FAILED(RomFsFileSystem::GetRequiredWorkingMemorySize(std::addressof(buffer_size), storage.get())) || buffer_size == 0 || buffer_size >= 128_KB) {
                        R_RETURN(RomFsFileSystem::Initialize(std::move(storage), nullptr, 0, false));
                    }

                    /* Allocate a buffer. */
                    m_meta_cache_buffer = m_allocator->Allocate(buffer_size);
                    if (m_meta_cache_buffer == nullptr) {
                        R_RETURN(RomFsFileSystem::Initialize(std::move(storage), nullptr, 0, false));
                    }

                    /* Initialize with cache buffer. */
                    m_meta_cache_buffer_size = buffer_size;
                    R_RETURN(RomFsFileSystem::Initialize(std::move(storage), m_meta_cache_buffer, m_meta_cache_buffer_size, true));
                }
        };

    }

    Result Processor::ProcessAsRomfs(std::shared_ptr<fs::IStorage> storage, ProcessAsRomfsContext *ctx) {
        /* Ensure we have a context. */
        ProcessAsRomfsContext local_ctx{};
        if (ctx == nullptr) {
            ctx = std::addressof(local_ctx);
        }

        /* Set the fs. */
        ctx->storage = std::move(storage);

        /* Mount the rom filesystem. */
        {
            /* Allocate the fs. */
            auto fs = fssystem::AllocateShared<RomFileSystemWithBuffer>(sf::GetNewDeleteMemoryResource());
            R_UNLESS(fs != nullptr, fs::ResultAllocationMemoryFailedInRomFileSystemCreatorA());

            /* Initialize the filesystem. */
            R_TRY(fs->Initialize(std::shared_ptr<fs::IStorage>(ctx->storage)));

            /* Set the context fs. */
            ctx->fs = std::move(fs);
        }

        /* Print. */
        if (ctx == std::addressof(local_ctx)) {
            this->PrintAsRomfs(*ctx);
        }

        /* Save. */
        if (ctx == std::addressof(local_ctx)) {
            this->SaveAsRomfs(*ctx);
        }

        R_SUCCEED();
    }

    void Processor::PrintAsRomfs(ProcessAsRomfsContext &ctx) {
        /* There's nothing meaningful to print about romfs. */
        AMS_UNUSED(ctx);
    }

    void Processor::SaveAsRomfs(ProcessAsRomfsContext &ctx) {
        if (m_options.list_romfs) {
            PrintDirectory(ctx.fs, "rom:", "/");
        } else {
            /* Determine path to extract to. */
            const char *dir_path = nullptr;
            if (dir_path == nullptr && m_options.romfs_out_dir_path != nullptr) {
                dir_path = m_options.romfs_out_dir_path;
            }
            if (dir_path == nullptr && m_options.default_out_dir_path != nullptr) {
                dir_path = m_options.default_out_dir_path;
            }

            /* If we have a path, extract to it. */
            if (dir_path != nullptr) {
                ExtractDirectory(m_local_fs, ctx.fs, "rom:", dir_path, "/");
            }
        }
    }

}