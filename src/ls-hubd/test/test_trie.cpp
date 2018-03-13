// Copyright (c) 2016-2018 LG Electronics, Inc.
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

#define private public
#include "../trie.hpp"
#undef private

#include <gtest/gtest.h>
#include <map>
#include <functional>

const int DATA_EMPTY = -1;

template <typename T>
std::map<std::string, T> TrieToMap(const Trie<T> &t)
{
    typename std::map<std::string, T> ret;

    auto action = [&](const std::string &key, const T &data)
    {
        if (data.value != DATA_EMPTY)
            ret[key] = data;
    };
    t.Visit(action);

    return ret;
}

struct Data
{
    int value;
    Data(int v = DATA_EMPTY) : value{v} { }
    bool operator==(const Data &o) const { return value == o.value; }
    bool IsEmpty() const { return value == DATA_EMPTY; }
};

typedef std::map<std::string, Data> MapT;


TEST(TestTrie, Add)
{
    Trie<Data> t;
    t.Add("abc")->value = 1;
    EXPECT_EQ(TrieToMap(t), MapT({{"abc", 1}}));
    t.Add("abc*")->value = 2;
    EXPECT_EQ(TrieToMap(t), MapT({{"abc", 2}}));
    t.Add("axy")->value = 3;
    EXPECT_EQ(TrieToMap(t), MapT({{"abc", 2}, {"axy", 3}}));
    t.Add("a")->value = 4;
    EXPECT_EQ(TrieToMap(t), MapT({{"abc", 2}, {"axy", 3}, {"a", 4}}));
    t.Add("ac")->value = 5;
    EXPECT_EQ(TrieToMap(t), MapT({{"abc", 2}, {"axy", 3}, {"a", 4}, {"ac", 5}}));
    t.Add("bcd*")->value = 6;
    EXPECT_EQ(TrieToMap(t), MapT({{"abc", 2}, {"axy", 3}, {"a", 4}, {"ac", 5}, {"bcd", 6}}));
}

TEST(TestTrie, Find)
{
    Trie<Data> t;
    t.Add("abc")->value = 1;
    t.Add("axy")->value = 3;
    t.Add("a")->value = 4;
    t.Add("ac")->value = 5;
    t.Add("bcd*")->value = 6;

    EXPECT_EQ(1, t.Find("abc")->value);
    EXPECT_EQ(1, t.Find("abc*")->value);
    EXPECT_EQ(3, t.Find("axy")->value);
    EXPECT_EQ(4, t.Find("a")->value);
    EXPECT_EQ(5, t.Find("ac")->value);
    EXPECT_EQ(6, t.Find("bcd")->value);

    EXPECT_EQ(DATA_EMPTY, t.Find("b")->value);
    EXPECT_EQ(DATA_EMPTY, t.Find("ab")->value);
    EXPECT_EQ(DATA_EMPTY, t.Find("ax")->value);
    EXPECT_EQ(DATA_EMPTY, t.Find("bc")->value);

    EXPECT_EQ(nullptr, t.Find("c"));
    EXPECT_EQ(nullptr, t.Find("acd"));
}

TEST(TestTrie, Search)
{
    Trie<Data> t;
    t.Add("abc")->value = 1;
    t.Add("axy")->value = 3;
    t.Add("a")->value = 4;
    t.Add("ac")->value = 5;
    t.Add("bcd*")->value = 6;
    t.Add("abcdef")->value = 7;

    std::string buffer;

    auto action = [&buffer](const Data &d)
    {
        if (d.value != DATA_EMPTY)
        {
            buffer += ' ' + std::to_string(d.value);
        }
    };

    auto node = t.Search("a", action);
    ASSERT_NE(nullptr, node);
    EXPECT_EQ(" 4", buffer);
    EXPECT_EQ(4, node->value);

    buffer.clear();
    node = t.Search("ab", action);
    ASSERT_NE(nullptr, node);
    EXPECT_EQ(" 4", buffer);
    EXPECT_EQ(DATA_EMPTY, node->value);

    buffer.clear();
    node = t.Search("abc", action);
    ASSERT_NE(nullptr, node);
    EXPECT_EQ(" 4 1", buffer);
    EXPECT_EQ(1, node->value);

    buffer.clear();
    node = t.Search("abcd", action);
    ASSERT_NE(nullptr, node);
    EXPECT_EQ(" 4 1", buffer);
    EXPECT_EQ(DATA_EMPTY, node->value);

    buffer.clear();
    node = t.Search("abcde", action);
    ASSERT_NE(nullptr, node);
    EXPECT_EQ(" 4 1", buffer);
    EXPECT_EQ(DATA_EMPTY, node->value);

    buffer.clear();
    node = t.Search("abcdef", action);
    ASSERT_NE(nullptr, node);
    EXPECT_EQ(" 4 1 7", buffer);
    EXPECT_EQ(7, node->value);
}

TEST(TestTrie, Remove)
{
    Trie<Data> t;
    t.Add("abc")->value = 1;
    t.Add("axy")->value = 3;
    t.Add("a")->value = 4;
    t.Add("ac")->value = 5;
    t.Add("bcd*")->value = 6;
    t.Add("abcdef")->value = 7;

    auto action = [](const char *key, Data &d, const char *expect_key, int expect_value)
    {
        EXPECT_STREQ(expect_key, key);
        EXPECT_EQ(expect_value, d.value);
        d.value = DATA_EMPTY;
    };

    using namespace std::placeholders;

    t.Remove("ac", std::bind(action, _1, _2, "", 5));
    t.Remove("bcd*", std::bind(action, _1, _2, "*", 6));
    t.Remove("abcdef*", std::bind(action, _1, _2, "*", 7));
    t.Remove("a", std::bind(action, _1, _2, "", 4));
    t.Remove("abc", std::bind(action, _1, _2, "", 1));
    t.Remove("axy", std::bind(action, _1, _2, "", 3));

    EXPECT_TRUE(t.children.empty());
}
