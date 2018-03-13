// Copyright (c) 2014-2018 LG Electronics, Inc.
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

#include <luna-service2/lunaservice.h>
#include <pbnjson.hpp>

namespace LS {

/**
 * @ingroup LunaServicePP
 * @brief Reference wrapper for LSPyalod, that doesn't own it
 */
class PayloadRef
{

public:
    /**
    * Construct a reference for LSPayload
    *
    * @param payload Underlying LSPayload to ref.
    */
    PayloadRef(LSPayload *payload)
        : _payload(payload)
    {
    }

    PayloadRef(const PayloadRef& other) = default;
    PayloadRef& operator=(const PayloadRef& other) = default;

    /**
     * Destructor for reference
     *
     * @note It doesn't free referenced payload
     */
    virtual ~PayloadRef()
    {
    }

    /**
     * Attaches file descriptor to Payload
     *
     * @param fd file descriptor to attach
     * @note Attached file descriptor isn't managed by PayloadRef, so it
     *       will not be closed automatically. And it should be valid while there
     *       is any PayloadRef references it
     * @see LSPayloadAttachFd
     */
    void attachFd(int fd)
    {
        LSPayloadAttachFd(_payload, fd);
    }

    /**
     * Get file descriptor attached to payload
     *
     * @return File descriptor or -1 if file descriptor is not attached
     * @see LSPayloadGetFd
     */
    int getFd()
    {
        return LSPayloadGetFd(_payload);
    }

    /**
     * Get string representation of json in payload
     *
     * @return Json string or nullptr if string can't be retrieved
     * @see LSPayloadGetJson
     */
    const char* getJson() const
    {
        return LSPayloadGetJson(_payload);
    }

    /**
     * Get pbnjson::Jvalue from json in payload
     *
     * @return A new Jvalue or JNull if Jvalue can't be retrieved
     * @see LSPayloadGetJValue
     */
    pbnjson::JValue getJValue() const
    {
        return pbnjson::JValue::adopt(LSPayloadGetJValue(_payload));
    }

    /**
     * Get string identifier of data type
     *
     * @return Get string identifier of payload data.
     * @see LSPayloadGetDataType
     */
    const char* getDataType() const
    {
        return LSPayloadGetDataType(_payload);
    }

    /**
     * Get raw data
     *
     * @param size reference to size_t in which size of data will be stored
     * @return Pointer to data.
     * @see LSPayloadGetData
     */
    void* getData(size_t& size) const
    {
        return LSPayloadGetData(_payload, &size);
    }

    LSPayload *get() const
    {
        return _payload;
    }

    operator LSPayload *()
    {
        return _payload;
    }

protected:
    LSPayload *_payload;
};

/**
 * @ingroup LunaServicePP
 * @brief Wrapper for LSPyalod.
 */
class Payload : public PayloadRef
{

public:
    /**
     * Construct from string representation of json
     *
     * @see LSPayloadFromJson
     */
    Payload(const char *json)
        : PayloadRef(LSPayloadFromJson(json))
    {

    }

    /**
     * Construct from pbnjson::JValue representation of json
     *
     * @see LSPayloadFromJValue
     */
    Payload(pbnjson::JValue json)
        : PayloadRef(LSPayloadFromJValue(json.peekRaw()))
    {

    }

    /**
     * Construct from raw data
     *
     * @see LSPayloadFromData
     */
    Payload(const char* type, void* data, size_t size)
        : PayloadRef(LSPayloadFromData(type, data, size))
    {

    }

    Payload(const Payload &other) = delete;
    Payload &operator=(const Payload &other) = delete;

    Payload(Payload&& other)
        : PayloadRef(other)
    {
        other._payload = nullptr;
    }

    Payload& operator=(Payload&& other)
    {
        if (this != &other)
        {
            PayloadRef::operator =(other);
            other._payload = nullptr;
        }

        return *this;
    }

    /**
     * Destruct owning payload
     *
     * @see LSPayloadFree
     */
    ~Payload()
    {
        if (_payload)
            LSPayloadFree(_payload);
    }
};

} // namespace LS
