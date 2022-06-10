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

    template<typename UserData>
    class ApplicationContentTreeEntry : public util::IntrusiveRedBlackTreeBaseNode<ApplicationContentTreeEntry<UserData>> {
        private:
            ncm::ApplicationId m_id;
            u32 m_version;
            u8 m_id_offset;
            ncm::ContentType m_type;
            ncm::ContentMetaType m_meta_type;
            UserData m_data;
        public:
            ApplicationContentTreeEntry(ncm::ApplicationId id, u32 v, u8 o, ncm::ContentType t, ncm::ContentMetaType m) : m_id(id), m_version(v), m_id_offset(o), m_type(t), m_meta_type(m), m_data() {
                /* ... */
            }

            ncm::ApplicationId GetId() const {
                return m_id;
            }

            u32 GetVersion() const {
                return m_version;
            }

            u8 GetIdOffset() const {
                return m_id_offset;
            }

            ncm::ContentType GetType() const {
                return m_type;
            }

            ncm::ContentMetaType GetMetaType() const {
                return m_meta_type;
            }

            const UserData &GetData() const { return m_data; }

            UserData &GetData() { return m_data; }
    };

    template<typename T>
    struct ApplicationContentTreeEntryCompare {
        static ALWAYS_INLINE int Compare(const ApplicationContentTreeEntry<T> &a, const ApplicationContentTreeEntry<T> &b) {
            const auto a_i = a.GetId();
            const auto a_v = a.GetVersion();
            const auto a_o = a.GetIdOffset();
            const auto a_t = a.GetType();
            const auto a_m = a.GetMetaType();
            const auto b_i = b.GetId();
            const auto b_v = b.GetVersion();
            const auto b_o = b.GetIdOffset();
            const auto b_t = b.GetType();
            const auto b_m = b.GetMetaType();
            if (std::tie(a_i, a_v, a_o, a_t, a_m) < std::tie(b_i, b_v, b_o, b_t, b_m)) {
                return -1;
            } else if (std::tie(a_i, a_v, a_o, a_t, a_m) > std::tie(b_i, b_v, b_o, b_t, b_m)) {
                return 1;
            } else {
                return 0;
            }
        }
    };

    template<typename T>
    using ApplicationContentTree = typename util::IntrusiveRedBlackTreeBaseTraits<ApplicationContentTreeEntry<T>>::TreeType<ApplicationContentTreeEntryCompare<T>>;

    template<typename T>
    struct ApplicationContentsHolder {
        NON_COPYABLE(ApplicationContentsHolder);
        NON_MOVEABLE(ApplicationContentsHolder);
        private:
            ApplicationContentTree<T> m_tree;
        public:
            ApplicationContentsHolder() : m_tree() { /* ... */ }

            ~ApplicationContentsHolder() {
                while (!m_tree.empty()) {
                    auto it = m_tree.begin();
                    while (it != m_tree.end()) {
                        auto *entry = std::addressof(*it);
                        it = m_tree.erase(it);
                        delete entry;
                    }
                }
            }

            ApplicationContentTreeEntry<T> *Insert(ncm::ApplicationId id, u32 v, u8 o, ncm::ContentType t, ncm::ContentMetaType m) {
                auto *entry = new ApplicationContentTreeEntry<T>(id, v, o, t, m);
                m_tree.insert(*entry);
                return entry;
            }

            auto begin() const { return m_tree.begin(); }
            auto end() const { return m_tree.end(); }

            auto Find(ncm::ApplicationId id, u32 v, u8 o, ncm::ContentType t, ncm::ContentMetaType m) {
                ApplicationContentTreeEntry<T> dummy(id, v, o, t, m);
                return m_tree.find(dummy);
            }
    };

}