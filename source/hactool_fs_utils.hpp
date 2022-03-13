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

    Result OpenFileStorage(std::shared_ptr<fs::IStorage> *out, std::shared_ptr<fs::fsa::IFileSystem> &fs, const char *path);

    Result PrintDirectory(std::shared_ptr<fs::fsa::IFileSystem> &fs, const char *prefix, const char *path);

    Result ExtractDirectory(std::shared_ptr<fs::fsa::IFileSystem> &dst_fs, std::shared_ptr<fs::fsa::IFileSystem> &src_fs, const char *prefix, const char *dst_path, const char *src_path);

    Result SaveToFile(std::shared_ptr<fs::fsa::IFileSystem> &fs, const char *path, fs::IStorage *storage, s64 offset, size_t size);
    Result SaveToFile(std::shared_ptr<fs::fsa::IFileSystem> &fs, const char *path, fs::IStorage *storage);

    Result SaveToFile(std::shared_ptr<fs::fsa::IFileSystem> &fs, const char *path, const void *data, size_t size);


}