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
#include "hactool_fs_utils.hpp"

namespace ams::hactool {

    namespace {

        constexpr size_t WorkBufferSize = 4_MB;

        template<size_t Count, char Full = '=', char Empty = ' '>
        class ProgressPrinter {
            NON_COPYABLE(ProgressPrinter);
            NON_MOVEABLE(ProgressPrinter);
            private:
                const char *m_prefix;
                size_t m_segs;
                size_t m_current;
                size_t m_total;
            public:
                ProgressPrinter(const char *p, size_t total) : m_prefix(p), m_segs(0), m_current(0), m_total(total) {
                    this->Render();
                }

                ~ProgressPrinter() {
                    printf(" Done!\n");
                }

                void Update(size_t new_current) {
                    m_current = new_current;

                    const size_t unit = m_total / Count;
                    if (const size_t segs = std::min<size_t>(m_current / unit, Count); segs != m_segs) {
                        m_segs = segs;
                        this->Render();
                    }
                }

                void Render() {
                    char prog[Count + 1];
                    std::memset(prog, Full, m_segs);
                    std::memset(prog + m_segs, Empty, Count - m_segs);
                    prog[Count] = 0;

                    printf("\r%s [%s]", m_prefix, prog);
                    fflush(stdout);
                }
        };

    }

    bool PathView::HasPrefix(util::string_view prefix) const {
        return m_path.compare(0, prefix.length(), prefix) == 0;
    }

    bool PathView::HasSuffix(util::string_view suffix) const {
        return m_path.compare(m_path.length() - suffix.length(), suffix.length(), suffix) == 0;
    }

    Result OpenFileStorage(std::shared_ptr<fs::IStorage> *out, std::shared_ptr<fs::fsa::IFileSystem> &fs, const char *path) {
        /* Open the file storage. */
        std::shared_ptr<ams::fs::FileStorageBasedFileSystem> file_storage = fssystem::AllocateShared<ams::fs::FileStorageBasedFileSystem>();
        R_UNLESS(file_storage != nullptr, fs::ResultAllocationMemoryFailedInNcaFileSystemServiceImplB());

        /* Get the fs path. */
        ams::fs::Path fs_path;
        R_UNLESS(path != nullptr, fs::ResultNullptrArgument());
        R_TRY(fs_path.SetShallowBuffer(path));

        /* Initialize the file storage. */
        R_TRY(file_storage->Initialize(std::shared_ptr<fs::fsa::IFileSystem>(fs), fs_path, ams::fs::OpenMode_Read));

        /* Set the output. */
        *out = std::move(file_storage);
        R_SUCCEED();
    }

    Result OpenSubDirectoryFileSystem(std::shared_ptr<fs::fsa::IFileSystem> *out, std::shared_ptr<fs::fsa::IFileSystem> &fs, const char *path) {
        /* Get the fs path. */
        ams::fs::Path fs_path;
        R_UNLESS(path != nullptr, fs::ResultNullptrArgument());
        R_TRY(fs_path.SetShallowBuffer(path));

        /* Verify that we can open the directory on the base filesystem. */
        {
            std::unique_ptr<fs::fsa::IDirectory> sub_dir;
            R_TRY(fs->OpenDirectory(std::addressof(sub_dir), fs_path, fs::OpenDirectoryMode_Directory));
        }

        /* Allocate the subdirectory filesystem. */
        auto subdir_fs = fssystem::AllocateShared<fssystem::SubDirectoryFileSystem>(fs);
        R_UNLESS(subdir_fs != nullptr, fs::ResultAllocationMemoryFailedAllocateShared());

        /* Initialize the subdirectory filesystem. */
        R_TRY(subdir_fs->Initialize(fs_path));

        /* Set the output. */
        *out = std::move(subdir_fs);
        R_SUCCEED();
    }

    Result PrintDirectory(std::shared_ptr<fs::fsa::IFileSystem> &fs, const char *prefix, const char *path) {
        /* Get the fs path. */
        ams::fs::Path fs_path;
        R_UNLESS(path != nullptr, fs::ResultNullptrArgument());
        R_TRY(fs_path.SetShallowBuffer(path));

        /* Iterate, printing the contents of the directory. */
        const auto iter_result = fssystem::IterateDirectoryRecursively(fs.get(),
            fs_path,
            [&] (const fs::Path &, const fs::DirectoryEntry &) -> Result {
                R_SUCCEED();
            },
            [&] (const fs::Path &, const fs::DirectoryEntry &) -> Result {
                R_SUCCEED();
            },
            [&] (const fs::Path &path, const fs::DirectoryEntry &) -> Result {
                printf("%s%s\n", prefix, path.GetString());
                R_SUCCEED();
            }
        );
        if (R_FAILED(iter_result)) {
            fprintf(stderr, "[Warning]: Failed to print directory (%s): 2%03d-%04d\n", path, iter_result.GetModule(), iter_result.GetDescription());
        }

        R_RETURN(iter_result);
    }

    Result PrintUpdatedRomFsDirectory(fssystem::RomFsFileSystem *fs, std::shared_ptr<fssystem::IndirectStorage> &indirect, std::shared_ptr<fssystem::AesCtrCounterExtendedStorage> &aes_ctr_ex, s32 min_gen, const char *prefix, const char *path) {
        /* Get the fs path. */
        ams::fs::Path fs_path;
        R_UNLESS(path != nullptr, fs::ResultNullptrArgument());
        R_TRY(fs_path.SetShallowBuffer(path));

        /* Allocate a work buffer. */
        constexpr size_t EntryBufferSize = 2_MB;
        void *buffer = std::malloc(EntryBufferSize);
        if (buffer == nullptr) {
            fprintf(stderr, "[Warning]: Failed to allocate work buffer to print updated romfs directory (%s%s)!\n", prefix, path);
            R_SUCCEED();
        }
        ON_SCOPE_EXIT { std::free(buffer); };

        /* Set up entry buffers. */
        auto *indirect_entries = reinterpret_cast<fssystem::IndirectStorage::Entry *>(reinterpret_cast<uintptr_t>(buffer) + 0);
        const auto max_indirect_entries = (EntryBufferSize / 2) / sizeof(*indirect_entries);

        auto *aes_ctr_ex_entries = reinterpret_cast<fssystem::AesCtrCounterExtendedStorage::Entry *>(reinterpret_cast<uintptr_t>(buffer) + (EntryBufferSize / 2));
        const auto max_aes_ctr_ex_entries = (EntryBufferSize / 2) / sizeof(*aes_ctr_ex_entries);

        /* Iterate, printing the contents of the directory. */
        const auto iter_result = fssystem::IterateDirectoryRecursively(fs,
            fs_path,
            [&] (const fs::Path &, const fs::DirectoryEntry &) -> Result {
                R_SUCCEED();
            },
            [&] (const fs::Path &, const fs::DirectoryEntry &) -> Result {
                R_SUCCEED();
            },
            [&] (const fs::Path &path, const fs::DirectoryEntry &ent) -> Result {
                /* Get the file base offset. */
                s64 file_offset = 0;
                R_TRY(fs->GetFileBaseOffset(std::addressof(file_offset), path));

                /* We'll want to get the maximum generation that the file was updated in. */
                s32 max_gen = 0;
                bool was_updated = false;

                /* Get the indirect entries. */
                s32 indirect_count = 0;
                R_TRY(indirect->GetEntryList(indirect_entries, std::addressof(indirect_count), max_indirect_entries, file_offset, ent.file_size));

                /* Check all indirect entries. */
                s64 offset_in_file = 0;
                for (auto i = 0; i < indirect_count; ++i) {
                    /* Get the current entry. */
                    const auto &indirect_entry = indirect_entries[i];

                    /* Determine the current entry size, which we'll advance by after this iteration. */
                    size_t cur_size = ent.file_size - offset_in_file;
                    if (i + 1 < indirect_count) {
                        cur_size = std::min<size_t>(indirect_entries[i + 1].GetVirtualOffset() - std::max<s64>(file_offset, indirect_entry.GetVirtualOffset()), cur_size);
                    }
                    ON_SCOPE_EXIT { offset_in_file += cur_size; };

                    /* We should have non-zero in this entry. */
                    AMS_ABORT_UNLESS(cur_size > 0);

                    /* If the entry is from the base storage, skip it. */
                    if (indirect_entry.storage_index == 0) {
                        continue;
                    }

                    /* The file has been updated at least once. */
                    was_updated = true;

                    /* Now, let's find the generation it was updated in. */
                    {
                        /* Get the aes ctr ex entries. */
                        s32 aes_ctr_ex_count = 0;
                        R_TRY(aes_ctr_ex->GetEntryList(aes_ctr_ex_entries, std::addressof(aes_ctr_ex_count), max_aes_ctr_ex_entries, indirect_entry.GetPhysicalOffset(), cur_size));

                        /* Check all aes ctr ex entries. */
                        for (auto j = 0; j < aes_ctr_ex_count; ++j) {
                            /* Get the current entry. */
                            const auto &aes_ctr_ex_entry = aes_ctr_ex_entries[j];

                            /* Check the entry's generation. */
                            max_gen = std::max(max_gen, aes_ctr_ex_entry.generation);
                        }
                    }
                }

                /* If we should, print. */
                if (was_updated && max_gen >= min_gen) {
                    printf("[%02d] %s%s\n", max_gen, prefix, path.GetString());
                }

                R_SUCCEED();
            }
        );
        if (R_FAILED(iter_result)) {
            fprintf(stderr, "[Warning]: Failed to print updated romfs directory (%s): 2%03d-%04d\n", path, iter_result.GetModule(), iter_result.GetDescription());
        }

        R_RETURN(iter_result);
    }

    Result ExtractDirectory(std::shared_ptr<fs::fsa::IFileSystem> &dst_fs, std::shared_ptr<fs::fsa::IFileSystem> &src_fs, const char *prefix, const char *dst_path, const char *src_path) {
        /* Allocate a work buffer. */
        void *buffer = std::malloc(WorkBufferSize);
        if (buffer == nullptr) {
            fprintf(stderr, "[Warning]: Failed to allocate work buffer to extract %s%s to %s!\n", prefix, src_path, dst_path);
            R_SUCCEED();
        }
        ON_SCOPE_EXIT { std::free(buffer); };

        auto extract_impl = [&] () -> Result {
            /* Set up the destination work path to point at the target directory. */
            fs::Path dst_fs_path;
            R_TRY(dst_fs_path.SetShallowBuffer(dst_path));

            /* Try to create the destination directory. */
            dst_fs->CreateDirectory(dst_fs_path);

            /* Verify that we can open the directory on the base filesystem. */
            {
                std::unique_ptr<fs::fsa::IDirectory> sub_dir;
                R_TRY(dst_fs->OpenDirectory(std::addressof(sub_dir), dst_fs_path, fs::OpenDirectoryMode_Directory));
            }

            /* Create/Initialize subdirectory filesystem. */
            fssystem::SubDirectoryFileSystem subdir_fs{dst_fs};
            R_TRY(subdir_fs.Initialize(dst_fs_path));

            /* Set up the source path to point at the target directory. */
            fs::Path src_fs_path;
            R_TRY(src_fs_path.SetShallowBuffer(src_path));

            /* Iterate, copying files. */
            R_RETURN(fssystem::IterateDirectoryRecursively(src_fs.get(), src_fs_path,
                [&](const fs::Path &path, const fs::DirectoryEntry &) -> Result { /* On Enter Directory */
                    /* Create the directory. */
                    R_TRY_CATCH(subdir_fs.CreateDirectory(path)) {
                        R_CATCH(fs::ResultPathAlreadyExists) { /* ... */ }
                    } R_END_TRY_CATCH;

                    R_SUCCEED();
                },
                [&](const fs::Path &, const fs::DirectoryEntry &) -> Result { /* On Exit Directory */
                    R_SUCCEED();
                },
                [&](const fs::Path &path, const fs::DirectoryEntry &) -> Result { /* On File */
                    /* Delete a file, if one already exists. */
                    subdir_fs.DeleteFile(path);

                    /* Copy the file. */
                    printf("Saving %s%s...\n", prefix, path.GetString());
                    R_TRY(fssystem::CopyFile(std::addressof(subdir_fs), src_fs.get(), path, path, buffer, WorkBufferSize));

                    R_SUCCEED();
                }
            ));
        };

        const auto res = extract_impl();
        if (R_FAILED(res)) {
            fprintf(stderr, "[Warning]: Failed to extract %s%s to %s: 2%03d-%04d\n", prefix, src_path, dst_path, res.GetModule(), res.GetDescription());
        }
        R_RETURN(res);
    }

    Result ExtractDirectoryWithProgress(std::shared_ptr<fs::fsa::IFileSystem> &dst_fs, std::shared_ptr<fs::fsa::IFileSystem> &src_fs, const char *prefix, const char *dst_path, const char *src_path) {
        /* Allocate a work buffer. */
        void *buffer = std::malloc(WorkBufferSize);
        if (buffer == nullptr) {
            fprintf(stderr, "[Warning]: Failed to allocate work buffer to extract %s%s to %s!\n", prefix, src_path, dst_path);
            R_SUCCEED();
        }
        ON_SCOPE_EXIT { std::free(buffer); };

        auto extract_impl = [&] () -> Result {
            /* Set up the destination work path to point at the target directory. */
            fs::Path dst_fs_path;
            R_TRY(dst_fs_path.SetShallowBuffer(dst_path));

            /* Try to create the destination directory. */
            dst_fs->CreateDirectory(dst_fs_path);

            /* Verify that we can open the directory on the base filesystem. */
            {
                std::unique_ptr<fs::fsa::IDirectory> sub_dir;
                R_TRY(dst_fs->OpenDirectory(std::addressof(sub_dir), dst_fs_path, fs::OpenDirectoryMode_Directory));
            }

            /* Create/Initialize subdirectory filesystem. */
            fssystem::SubDirectoryFileSystem subdir_fs{dst_fs};
            R_TRY(subdir_fs.Initialize(dst_fs_path));

            /* Set up the source path to point at the target directory. */
            fs::Path src_fs_path;
            R_TRY(src_fs_path.SetShallowBuffer(src_path));

            /* Iterate, copying files. */
            R_RETURN(fssystem::IterateDirectoryRecursively(src_fs.get(), src_fs_path,
                [&](const fs::Path &path, const fs::DirectoryEntry &) -> Result { /* On Enter Directory */
                    /* Create the directory. */
                    R_TRY_CATCH(subdir_fs.CreateDirectory(path)) {
                        R_CATCH(fs::ResultPathAlreadyExists) { /* ... */ }
                    } R_END_TRY_CATCH;

                    R_SUCCEED();
                },
                [&](const fs::Path &, const fs::DirectoryEntry &) -> Result { /* On Exit Directory */
                    R_SUCCEED();
                },
                [&](const fs::Path &path, const fs::DirectoryEntry &) -> Result { /* On File */
                    /* Delete a file, if one already exists. */
                    subdir_fs.DeleteFile(path);

                    /* Open the existing file. */
                    std::shared_ptr<fs::IStorage> storage;
                    R_TRY(OpenFileStorage(std::addressof(storage), src_fs, path.GetString()));

                    /* Get the file size. */
                    s64 size;
                    R_TRY(storage->GetSize(std::addressof(size)));

                    /* Create the file. */
                    R_TRY(subdir_fs.CreateFile(path, size));

                    /* Open the file. */
                    std::unique_ptr<fs::fsa::IFile> base_file;
                    R_TRY(subdir_fs.OpenFile(std::addressof(base_file), path, fs::OpenMode_ReadWrite));

                    /* Set the file size. */
                    R_TRY(base_file->SetSize(size));

                    /* Create a progress printer. */
                    char prog_prefix[1_KB];
                    util::TSNPrintf(prog_prefix, sizeof(prog_prefix), "Saving %s%s... ", prefix, path.GetString());
                    ProgressPrinter<40> printer{prog_prefix, static_cast<size_t>(size)};

                    /* Write. */
                    s64 offset = 0;
                    const s64 end_offset = static_cast<s64>(offset + size);
                    while (offset < end_offset) {
                        const s64 cur_write_size = std::min<s64>(WorkBufferSize, end_offset - offset);

                        R_TRY(storage->Read(offset, buffer, cur_write_size));
                        R_TRY(base_file->Write(offset, buffer, cur_write_size, fs::WriteOption::None));

                        offset += cur_write_size;
                        printer.Update(static_cast<size_t>(offset));
                    }

                    R_SUCCEED();
                }
            ));
        };

        const auto res = extract_impl();
        if (R_FAILED(res)) {
            fprintf(stderr, "[Warning]: Failed to extract %s%s to %s: 2%03d-%04d\n", prefix, src_path, dst_path, res.GetModule(), res.GetDescription());
        }
        R_RETURN(res);
    }

    Result ExtractUpdatedRomFsDirectory(std::shared_ptr<fs::fsa::IFileSystem> &dst_fs, fssystem::RomFsFileSystem *src_fs, std::shared_ptr<fssystem::IndirectStorage> &indirect, std::shared_ptr<fssystem::AesCtrCounterExtendedStorage> &aes_ctr_ex, s32 min_gen, const char *prefix, const char *dst_path, const char *src_path) {
        /* Allocate a work buffer. */
        void *buffer = std::malloc(WorkBufferSize);
        if (buffer == nullptr) {
            fprintf(stderr, "[Warning]: Failed to allocate work buffer to extract %s%s to %s!\n", prefix, src_path, dst_path);
            R_SUCCEED();
        }
        ON_SCOPE_EXIT { std::free(buffer); };

        /* Allocate a work buffer. */
        constexpr size_t EntryBufferSize = 2_MB;
        void *entry_buffer = std::malloc(EntryBufferSize);
        if (entry_buffer == nullptr) {
            fprintf(stderr, "[Warning]: Failed to allocate work buffer to extract updated romfs directory %s%s to %s!\n", prefix, src_path, dst_path);
            R_SUCCEED();
        }
        ON_SCOPE_EXIT { std::free(entry_buffer); };

        /* Set up entry buffers. */
        auto *indirect_entries = reinterpret_cast<fssystem::IndirectStorage::Entry *>(reinterpret_cast<uintptr_t>(entry_buffer) + 0);
        const auto max_indirect_entries = (EntryBufferSize / 2) / sizeof(*indirect_entries);

        auto *aes_ctr_ex_entries = reinterpret_cast<fssystem::AesCtrCounterExtendedStorage::Entry *>(reinterpret_cast<uintptr_t>(entry_buffer) + (EntryBufferSize / 2));
        const auto max_aes_ctr_ex_entries = (EntryBufferSize / 2) / sizeof(*aes_ctr_ex_entries);

        auto extract_impl = [&] () -> Result {
            /* Set up the destination work path to point at the target directory. */
            fs::Path dst_fs_path;
            R_TRY(dst_fs_path.SetShallowBuffer(dst_path));

            /* Try to create the destination directory. */
            dst_fs->CreateDirectory(dst_fs_path);

            /* Verify that we can open the directory on the base filesystem. */
            {
                std::unique_ptr<fs::fsa::IDirectory> sub_dir;
                R_TRY(dst_fs->OpenDirectory(std::addressof(sub_dir), dst_fs_path, fs::OpenDirectoryMode_Directory));
            }

            /* Create/Initialize subdirectory filesystem. */
            fssystem::SubDirectoryFileSystem subdir_fs{dst_fs};
            R_TRY(subdir_fs.Initialize(dst_fs_path));

            /* Set up the source path to point at the target directory. */
            fs::Path src_fs_path;
            R_TRY(src_fs_path.SetShallowBuffer(src_path));

            /* Iterate, copying files. */
            R_RETURN(fssystem::IterateDirectoryRecursively(src_fs, src_fs_path,
                [&](const fs::Path &path, const fs::DirectoryEntry &) -> Result { /* On Enter Directory */
                    /* Create the directory. */
                    R_TRY_CATCH(subdir_fs.CreateDirectory(path)) {
                        R_CATCH(fs::ResultPathAlreadyExists) { /* ... */ }
                    } R_END_TRY_CATCH;

                    R_SUCCEED();
                },
                [&](const fs::Path &path, const fs::DirectoryEntry &) -> Result { /* On Exit Directory */
                    /* If the directory has no files, we need to delete it. */
                    R_TRY_CATCH(subdir_fs.DeleteDirectory(path)) {
                        R_CATCH(fs::ResultDirectoryNotEmpty) { /* ... */ }
                    } R_END_TRY_CATCH;

                    R_SUCCEED();
                },
                [&](const fs::Path &path, const fs::DirectoryEntry &ent) -> Result { /* On File */
                    /* Delete a file, if one already exists. */
                    subdir_fs.DeleteFile(path);

                    /* We'll want to get the maximum generation that the file was updated in. */
                    s32 max_gen = 0;
                    bool was_updated = false;
                    {
                        /* Get the file base offset. */
                        s64 file_offset = 0;
                        R_TRY(src_fs->GetFileBaseOffset(std::addressof(file_offset), path));

                        /* Get the indirect entries. */
                        s32 indirect_count = 0;
                        R_TRY(indirect->GetEntryList(indirect_entries, std::addressof(indirect_count), max_indirect_entries, file_offset, ent.file_size));

                        /* Check all indirect entries. */
                        s64 offset_in_file = 0;
                        for (auto i = 0; i < indirect_count; ++i) {
                            /* Get the current entry. */
                            const auto &indirect_entry = indirect_entries[i];

                            /* Determine the current entry size, which we'll advance by after this iteration. */
                            size_t cur_size = ent.file_size - offset_in_file;
                            if (i + 1 < indirect_count) {
                                cur_size = std::min<size_t>(indirect_entries[i + 1].GetVirtualOffset() - std::max<s64>(file_offset, indirect_entry.GetVirtualOffset()), cur_size);
                            }
                            ON_SCOPE_EXIT { offset_in_file += cur_size; };

                            /* We should have non-zero in this entry. */
                            AMS_ABORT_UNLESS(cur_size > 0);

                            /* If the entry is from the base storage, skip it. */
                            if (indirect_entry.storage_index == 0) {
                                continue;
                            }

                            /* The file has been updated at least once. */
                            was_updated = true;

                            /* Now, let's find the generation it was updated in. */
                            {
                                /* Get the aes ctr ex entries. */
                                s32 aes_ctr_ex_count = 0;
                                R_TRY(aes_ctr_ex->GetEntryList(aes_ctr_ex_entries, std::addressof(aes_ctr_ex_count), max_aes_ctr_ex_entries, indirect_entry.GetPhysicalOffset(), cur_size));

                                /* Check all aes ctr ex entries. */
                                for (auto j = 0; j < aes_ctr_ex_count; ++j) {
                                    /* Get the current entry. */
                                    const auto &aes_ctr_ex_entry = aes_ctr_ex_entries[j];

                                    /* Check the entry's generation. */
                                    max_gen = std::max(max_gen, aes_ctr_ex_entry.generation);
                                }
                            }
                        }
                    }

                    /* If we should, copy the file. */
                    if (was_updated && max_gen >= min_gen) {
                        printf("Saving [%02d] %s%s...\n", max_gen, prefix, path.GetString());
                        R_TRY(fssystem::CopyFile(std::addressof(subdir_fs), src_fs, path, path, buffer, WorkBufferSize));
                    }

                    R_SUCCEED();
                }
            ));
        };

        const auto res = extract_impl();
        if (R_FAILED(res)) {
            fprintf(stderr, "[Warning]: Failed to extract %s%s to %s: 2%03d-%04d\n", prefix, src_path, dst_path, res.GetModule(), res.GetDescription());
        }
        R_RETURN(res);
    }

    Result SaveToFile(std::shared_ptr<fs::fsa::IFileSystem> &fs, const char *path, fs::IStorage *storage, s64 offset, size_t size) {
        /* Allocate a work buffer. */
        void *buffer = std::malloc(WorkBufferSize);
        if (buffer == nullptr) {
            fprintf(stderr, "[Warning]: Failed to allocate work buffer to save storage to %s!\n", path);
            R_SUCCEED();
        }
        ON_SCOPE_EXIT { std::free(buffer); };

        auto save_impl = [&] () -> Result {
            /* Get the fs path. */
            ams::fs::Path fs_path;
            R_UNLESS(path != nullptr, fs::ResultNullptrArgument());
            R_TRY(fs_path.SetShallowBuffer(path));

            /* Delete an existing file, this is allowed to fail. */
            fs->DeleteFile(fs_path);

            /* Create the file. */
            R_TRY(fs->CreateFile(fs_path, size));

            /* Open the file. */
            std::unique_ptr<fs::fsa::IFile> base_file;
            R_TRY(fs->OpenFile(std::addressof(base_file), fs_path, fs::OpenMode_ReadWrite));

            /* Set the file size. */
            R_TRY(base_file->SetSize(size));

            /* Create a progress printer. */
            char prog_prefix[1_KB];
            util::TSNPrintf(prog_prefix, sizeof(prog_prefix), "Saving storage to %s... ", path);
            ProgressPrinter<40> printer{prog_prefix, static_cast<size_t>(size)};

            /* Write. */
            const s64 start_offset = offset;
            const s64 end_offset   = static_cast<s64>(offset + size);
            while (offset < end_offset) {
                const s64 cur_write_size = std::min<s64>(WorkBufferSize, end_offset - offset);

                R_TRY(storage->Read(offset, buffer, cur_write_size));
                R_TRY(base_file->Write(offset, buffer, cur_write_size, fs::WriteOption::None));

                offset += cur_write_size;
                printer.Update(static_cast<size_t>(offset - start_offset));
            }

            R_SUCCEED();
        };

        const auto res = save_impl();
        if (R_FAILED(res)) {
            fprintf(stderr, "[Warning]: Failed to save storage to %s: 2%03d-%04d\n", path, res.GetModule(), res.GetDescription());
        }
        R_RETURN(res);
    }

    Result SaveToFile(std::shared_ptr<fs::fsa::IFileSystem> &fs, const char *path, fs::IStorage *storage) {
        s64 size;
        R_TRY(storage->GetSize(std::addressof(size)));

        R_RETURN(SaveToFile(fs, path, storage, 0, size));
    }

    Result SaveToFile(std::shared_ptr<fs::fsa::IFileSystem> &fs, const char *path, const void *data, size_t size) {
        auto save_impl = [&] () -> Result {
            /* Get the fs path. */
            ams::fs::Path fs_path;
            R_UNLESS(path != nullptr, fs::ResultNullptrArgument());
            R_TRY(fs_path.SetShallowBuffer(path));

            /* Delete an existing file, this is allowed to fail. */
            fs->DeleteFile(fs_path);

            /* Create the file. */
            R_TRY(fs->CreateFile(fs_path, size));

            /* Open the file. */
            std::unique_ptr<fs::fsa::IFile> base_file;
            R_TRY(fs->OpenFile(std::addressof(base_file), fs_path, fs::OpenMode_ReadWrite));

            /* Set the file size. */
            R_TRY(base_file->SetSize(size));

            /* Write the file data. */
            R_TRY(base_file->Write(0, data, size, fs::WriteOption::Flush));

            R_SUCCEED();
        };

        const auto res = save_impl();
        if (R_FAILED(res)) {
            fprintf(stderr, "[Warning]: Failed to save file from memory (%s): 2%03d-%04d\n", path, res.GetModule(), res.GetDescription());
        }
        R_RETURN(res);
    }

}