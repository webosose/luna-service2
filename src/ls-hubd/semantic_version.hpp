// Copyright (c) 2015-2018 LG Electronics, Inc.
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

#ifndef _SEMANTIC_VERSION_HPP_
#define _SEMANTIC_VERSION_HPP_

#include <utility>
#include <string>


class SemanticVersion
{
public:
    enum class Precedence
    {
        Lower   = -1,
        Equal   =  0,
        Greater =  1,
        Invalid =  2
    };

    Precedence compare(const SemanticVersion &other) const;

    SemanticVersion();
    explicit SemanticVersion(const std::string& v);

    bool operator==(const SemanticVersion& sv) const
    {
        return compare(sv) == Precedence::Equal;
    }

    bool operator<(const SemanticVersion& sv) const
    {
        return compare(sv) == Precedence::Lower;
    }

    bool operator>(const SemanticVersion& sv) const
    {
        return compare(sv) == Precedence::Greater;
    }

    bool operator<=(const SemanticVersion& sv) const
    {
        auto cmpres = compare(sv);
        return cmpres == Precedence::Lower
            || cmpres == Precedence::Equal;
    }

    bool operator>=(const SemanticVersion& sv) const
    {
        auto cmpres = compare(sv);
        return cmpres == Precedence::Greater
            || cmpres == Precedence::Equal;
    }

    bool operator!=(const SemanticVersion& sv) const
    {
        return compare(sv) != Precedence::Equal;
    }

    explicit operator bool() const
    {
        return is_valid;
    }

    bool isValid() const
    {
        return is_valid;
    }

    const std::string& asString() const
    {
        return version;
    }

private:
    class Field
    {
        enum class Type
        {
            NUMBER,
            ALPHANUM,
            ERROR,
            END
        };

        enum class Error
        {
            NONE,
            EMPTY_FIELD,
            LEADING_ZERO
        };

    public:
        const char *begin = nullptr;
        const char *end = nullptr;

        explicit Field(bool is_empty = false)
            : kind(is_empty ? Type::ERROR : Type::END)
            , error(is_empty ? Error::EMPTY_FIELD : Error::NONE)
        {}

        Field(const char *_begin, const char *_end, bool is_num)
            : begin(_begin)
            , end(_end)
            , kind(is_num ? Type::NUMBER : Type::ALPHANUM)
        {
            // Numeric fields MUST NOT include leading zeroes.
            if (isNumber()
                && end - begin > 1
                && *begin == '0')
            {
                kind = Type::ERROR;
                error = Error::LEADING_ZERO;
            }
        }

        Precedence compare(const Field& other) const;

        bool isEnd() const { return kind == Type::END; }
        bool isAlphanum() const { return kind == Type::ALPHANUM; }
        bool isNumber() const { return kind == Type::NUMBER; }
        bool isError() const { return kind == Type::ERROR; }

        const char *textError() const;

    private:
        Type kind;
        Error error = Error::NONE;
    };

    struct Parser
    {
        bool prerelease = false;
        bool field_expected = true;
        const char *cursor = nullptr;

        explicit Parser(const std::string& str) : cursor(str.c_str()) {}

        Field nextField();
    };

private:
    static const char *fields[]; // = {"Major", "Minor", "Patch"};
    bool is_valid;
    std::string version;
};

#endif // _SEMANTIC_VERSION_HPP_
