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

#include <cstdlib>
#include <cstring>
#include <cassert>
#include <algorithm>

#include "semantic_version.hpp"

#include "log.h"
#include "error.h"
#include "util.hpp"


const char *SemanticVersion::fields[] = {"Major", "Minor", "Patch"};

SemanticVersion::SemanticVersion()
    : is_valid(false)
{
}

SemanticVersion::SemanticVersion(const std::string& v)
    : is_valid(true)
{
    Parser p{v};

    const char *begin = v.c_str();

    Field field;

    for (auto name : fields)
    {
        field = p.nextField();
        if (!field.isNumber())
        {
            LOG_LS_ERROR(MSGID_LSHUB_VERSION_PARSE_ERROR, 0,
                "%s: failed to parse version string \"%s\". "
                "Expecting number as %s field.",
                __func__,
                begin,
                name
            );
            is_valid = false;
            return;
        }
    }

    const char *end = field.end;
    if (p.prerelease)
    {
        for (;;)
        {
            field = p.nextField();
            if (field.isError())
            {
                LOG_LS_ERROR(MSGID_LSHUB_VERSION_PARSE_ERROR, 0,
                    "%s: failed to parse version string \"%s\". "
                    "%s error in prerelease string.",
                    __func__,
                    begin,
                    field.textError()
                );
                is_valid = false;
                return;
            }
            if (field.isEnd())
            {
                break;
            }
            end = field.end;
        }
    }

    if (!p.prerelease && !p.nextField().isEnd())
    {
        LOG_LS_ERROR(MSGID_LSHUB_VERSION_PARSE_ERROR, 0,
            "%s: failed to parse version string \"%s\". "
            "End of string expected.",
            __func__,
            begin
        );
        is_valid = false;
        return;
    }

    version = std::string(begin, end);
}

SemanticVersion::Precedence
SemanticVersion::compare(const SemanticVersion& other) const
{
    if (!is_valid || !other.is_valid)
        return Precedence::Invalid;

    Parser pa{version};
    Parser pb{other.version};

    Field fa, fb;
    Precedence res;

    for (G_GNUC_UNUSED auto name : fields)
    {
        fa = pa.nextField();
        fb = pb.nextField();

        res = fa.compare(fb);
        if (res != Precedence::Equal)
            return res;
    }

    // Pre-release versions have a lower precedence
    // than the associated normal version.
    if (pb.prerelease && !pa.prerelease)
        return Precedence::Greater;
    if (pa.prerelease && !pb.prerelease)
        return Precedence::Lower;

    for (;;)
    {
        fa = pa.nextField();
        fb = pb.nextField();

        if (fa.isEnd() && fb.isEnd())
            break;

        // A larger set of pre-release fields has a higher precedence
        // than a smaller set, if all of the preceding fields are equal.
        if (fa.isEnd() && !fb.isEnd())
            return Precedence::Lower;
        if (fb.isEnd() && !fa.isEnd())
            return Precedence::Greater;

        res = fa.compare(fb);
        if (res != Precedence::Equal)
            return res;
    }

    return Precedence::Equal;
}

SemanticVersion::Precedence
SemanticVersion::Field::compare(const Field& other) const
{
    auto _Precedence = [](int cmpres) {
        if (cmpres > 0)
            return Precedence::Greater;
        if (cmpres < 0)
            return Precedence::Lower;
        return Precedence::Equal;
    };

    // Numeric fields always have lower precedence
    // than non-numeric fields.
    if (isNumber() && other.isAlphanum())
        return Precedence::Lower;
    if (isAlphanum() && other.isNumber())
        return Precedence::Greater;

    size_t len = end - begin;
    size_t other_len = other.end - other.begin;
    ssize_t delta = len - other_len;
    int deltacmp = delta > 0 ? 1 : (delta < 0 ? -1 : 0);

    if (isAlphanum() && other.isAlphanum())
    {
        int res = std::memcmp(begin, other.begin, std::min(len, other_len));
        if (res != 0)
            return _Precedence(res);
        return _Precedence(deltacmp);
    }

    if (isNumber() && other.isNumber())
    {
        if (len != other_len)
            return _Precedence(deltacmp);
        int res = std::memcmp(begin, other.begin, len);
        return _Precedence(res);
    }

    return Precedence::Equal;
}

const char *SemanticVersion::Field::textError() const
{
    switch (error)
    {
        case Error::NONE: return "NONE";
        case Error::EMPTY_FIELD: return "EMPTY_FIELD";
        case Error::LEADING_ZERO: return "LEADING_ZERO";
        default:
            return "NO_ERROR";
    }
}

// Method parse fields in input string in accordance
// of specification in http://semver.org
SemanticVersion::Field
SemanticVersion::Parser::nextField()
{
    const char *begin = cursor;
    const char *end = cursor;
    bool is_number = true;

    if (!end || *end == '\0' || *end == '+')
        return Field(field_expected);

    field_expected = false;

    for (;;)
    {
        switch (*cursor)
        {
        case '-':
            // After the first '-' symbol determined as start
            // of pre-release fields all next ones should be determined
            // as usual alphanumeric symbols.
            if (prerelease)
            {
                is_number = false;
                end = ++cursor;
                break;
            }
            prerelease = true;
        case '.':
            // If the symbol is a legal field separator we move cursor forward
            // in order to skip it but don't move end of field pointer.
            ++cursor;
            field_expected = true;

        // After a '+' symbol follow build metadata field that
        // should be ignored when determining version precedence.
        case '+':
        case '\0':
            if (end == begin)
                return Field(true);
            return Field(begin, end, is_number);
        case '0'...'9':
            end = ++cursor;
            break;

        // If a symbol is not a field separator and not a number
        // it should be determined as alphanumeric symbol.
        // Field with alphanumeric symbol can't be a numeric field.
        default:
            is_number = false;
            end = ++cursor;
            break;
        }
    }
    return Field(true);
}
