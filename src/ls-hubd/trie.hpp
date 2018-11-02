// Copyright (c) 2016-2019 LG Electronics, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <vector>
#include <memory>

// A naive implementation of prefix tree proved to be not only simple,
// but also efficient. The idea is to branch on every character,
// to use linear search on every node for data locality.

template <typename T>
struct Trie : T
{
    using PtrT = std::unique_ptr<Trie<T>>;
    std::vector<std::pair<char, PtrT>> children;

    Trie() = default;
    Trie(const Trie<T> &) = delete;
    Trie& operator=(const Trie<T> &) = delete;
    Trie(Trie<T> &&other) = default;
    Trie& operator=(Trie<T> &&other) = default;

    // Ensure the key can be stored in the trie, and return the leaf node for
    // the key.
    Trie<T>* Add(const char *key)
    {
        auto node = this;

        while (true)
        {
            char ch = *key;

            if (_IsCharTerminal(ch))
                return node;

            auto next = node->Child(ch);
            if (!next)
            {
                next = new Trie<T>;
                node->children.emplace_back(ch, PtrT(next));
            }

            node = next;
            ++key;
        }
    }

    // Find the leaf node for the key or nullptr.
    const Trie<T>* Find(const char *key) const
    {
        auto node = this;

        while (true)
        {
            char ch = *key;

            if (_IsCharTerminal(ch))
                return node;

            node = node->Child(ch);
            if (!node)
                return nullptr;

            ++key;
        }
    }

    // Find the leaf node for the key or nullptr.
    Trie<T>* Get(const char *key)
    {
        auto node = this;

        while (true)
        {
            char ch = *key;

            if (_IsCharTerminal(ch))
                return node;

            node = node->Child(ch);
            if (!node)
                return nullptr;

            ++key;
        }
    }

    // Search for the given key, executing func along the descent.
    template <typename Func>
    const Trie<T>* Search(const char *key, Func func) const
    {
        auto node = this;

        while (true)
        {
            func(*node);

            char ch = key[0];
            if (_IsCharTerminal(ch))
                return node;

            node = node->Child(ch);
            if (!node)
                return nullptr;

            ++key;
        }
    }

    // Execute func on the given leaf node. Remove empty nodes on the way back
    // to the root.
    template <typename Func>
    void Remove(const char *key, const Func &func)
    {
        char ch = *key;

        if (_IsCharTerminal(ch))
        {
            func(key, *this);
            return;
        }

        for (auto it = children.begin(); it != children.end(); ++it)
        {
            if (it->first == ch)
            {
                auto next = it->second.get();

                next->Remove(++key, func);
                if (next->IsEmpty() and next->children.empty())
                {
                    children.erase(it);
                }
                break;
            }
        }
    }

    // Visit every node from top to bottom without any particular order between
    // siblings.
    template <typename Func>
    void Visit(const Func &func) const
    {
        std::string prefix;
        Visit(prefix, func);
    }

private:

    inline static bool _IsCharTerminal(char ch)
    {
        return !ch || ch == '*';
    }

    // Find the subtree for a given character.
    Trie<T>* Child(char key) const
    {
        for (const auto &child : children)
        {
            if (child.first == key)
                return child.second.get();
        }

        return nullptr;
    }

    // Visit every node from top to bottom without any particular order between
    // siblings. The prefix will be accumulated during the descent.
    template <typename Func>
    void Visit(std::string &prefix, const Func &func) const
    {
        func(prefix, *this);
        for (const auto &child : children)
        {
            prefix.push_back(child.first);
            child.second->Visit(prefix, func);
            prefix.pop_back();
        }
    }
};
