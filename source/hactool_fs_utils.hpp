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

namespace ams::hactool {

   class PathView {
        private:
            util::string_view m_path;
        public:
            PathView(util::string_view p) : m_path(p) { /* ...*/ }
            bool HasPrefix(util::string_view prefix) const;
            bool HasSuffix(util::string_view suffix) const;
    };

    Result OpenFileStorage(std::shared_ptr<fs::IStorage> *out, std::shared_ptr<fs::fsa::IFileSystem> &fs, const char *path);

    Result OpenSubDirectoryFileSystem(std::shared_ptr<fs::fsa::IFileSystem> *out, std::shared_ptr<fs::fsa::IFileSystem> &fs, const char *path);

    Result PrintDirectory(std::shared_ptr<fs::fsa::IFileSystem> &fs, const char *prefix, const char *path);

    Result PrintUpdatedRomFsDirectory(fssystem::RomFsFileSystem *fs, std::shared_ptr<fssystem::IndirectStorage> &indirect, std::shared_ptr<fssystem::AesCtrCounterExtendedStorage> &aes_ctr_ex, s32 min_gen, const char *prefix, const char *path);

    Result ExtractDirectory(std::shared_ptr<fs::fsa::IFileSystem> &dst_fs, std::shared_ptr<fs::fsa::IFileSystem> &src_fs, const char *prefix, const char *dst_path, const char *src_path);
    Result ExtractDirectoryWithProgress(std::shared_ptr<fs::fsa::IFileSystem> &dst_fs, std::shared_ptr<fs::fsa::IFileSystem> &src_fs, const char *prefix, const char *dst_path, const char *src_path);

    Result ExtractUpdatedRomFsDirectory(std::shared_ptr<fs::fsa::IFileSystem> &dst_fs, fssystem::RomFsFileSystem *src_fs, std::shared_ptr<fssystem::IndirectStorage> &indirect, std::shared_ptr<fssystem::AesCtrCounterExtendedStorage> &aes_ctr_ex, s32 min_gen, const char *prefix, const char *dst_path, const char *src_path);

    Result SaveToFile(std::shared_ptr<fs::fsa::IFileSystem> &fs, const char *path, fs::IStorage *storage, s64 offset, size_t size);
    Result SaveToFile(std::shared_ptr<fs::fsa::IFileSystem> &fs, const char *path, fs::IStorage *storage);

    Result SaveToFile(std::shared_ptr<fs::fsa::IFileSystem> &fs, const char *path, const void *data, size_t size);


}