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

#include <thread>

#include <gtest/gtest.h>

#include <pbnjson.hpp>
#include <luna-service2/lunaservice.hpp>

#include "test_util.hpp"
#include "test_security_util.hpp"

static std::string v1_manifest = pbnjson::JObject
{
    { "prefix", volatile_dir },
    { "path", "/manifests/v1/test.manifest.json" }
}.stringify();

static std::string v2_manifest = pbnjson::JObject
{
    { "prefix", volatile_dir },
    { "path", "/manifests/v2/test.manifest.json" }
}.stringify();

static std::string v1_dir = pbnjson::JObject
{
    { "prefix", volatile_dir },
    { "dirpath", "/manifests/v1" }
}.stringify();

static std::string v2_dir = pbnjson::JObject
{
    { "prefix", volatile_dir },
    { "dirpath", "/manifests/v2" }
}.stringify();

static bool MethodStub(LSHandle *sh, LSMessage *message, void *data)
{
    (void)sh;
    (void)data;

    LSMessageRespond(message, R"({"returnValue":true})", nullptr);
    return true;
}

TEST(TestExternalManifest, Error)
{
    MainLoopT mainloop;

    auto configurator = LS::registerService("com.webos.service.configurator");
    configurator.attachToLoop(mainloop.get());

    // check addOneManifest and removeOneManifest call params
    {
        auto reply = configurator.callOneReply("luna://com.webos.service.bus/addOneManifest", R"({})").get();
        auto object = pbnjson::JDomParser::fromString(reply.getPayload());
        EXPECT_FALSE(object["returnValue"].asBool());

        reply = configurator.callOneReply("luna://com.webos.service.bus/removeOneManifest", R"({})").get();
        object = pbnjson::JDomParser::fromString(reply.getPayload());
        EXPECT_FALSE(object["returnValue"].asBool());
    }

    // check addManifestsDir and removeManifestsDir call params
    {
        auto reply = configurator.callOneReply("luna://com.webos.service.bus/addManifestsDir", R"({})").get();
        auto object = pbnjson::JDomParser::fromString(reply.getPayload());
        EXPECT_FALSE(object["returnValue"].asBool());

        reply = configurator.callOneReply("luna://com.webos.service.bus/removeManifestsDir", R"({"prefix": ""})").get();
        object = pbnjson::JDomParser::fromString(reply.getPayload());
        EXPECT_FALSE(object["returnValue"].asBool());
    }

    mainloop.stop();
}

TEST(TestExternalManifest, AddRemoveOne)
{
    MainLoopT mainloop;

    auto configurator = LS::registerService("com.webos.service.configurator");
    configurator.attachToLoop(mainloop.get());

    auto reply = configurator.callOneReply("luna://com.webos.service.bus/addOneManifest", v1_manifest.c_str()).get();
    EXPECT_STREQ(reply.getPayload(), R"({"returnValue":true})");

    ASSERT_NO_THROW(LS::registerApplicationService("com.webos.app.customer", "test"));

    reply = configurator.callOneReply("luna://com.webos.service.bus/removeOneManifest", v1_manifest.c_str()).get();
    EXPECT_STREQ(reply.getPayload(), R"({"returnValue":true})");

    EXPECT_ANY_THROW(LS::registerApplicationService("com.webos.app.customer", "test"));

    mainloop.stop();
}

TEST(TestExternalManifest, UpdateOne)
{
    MainLoopT loop;

    auto configurator = LS::registerService("com.webos.service.configurator");
    configurator.attachToLoop(loop.get());

    auto product = LS::registerService("com.webos.service.product");
    product.attachToLoop(loop.get());

    static LSMethod methods[] =
    {
        { "method", MethodStub, LUNA_METHOD_FLAGS_NONE },
        { nullptr }
    };

    product.registerCategory("/set", methods, nullptr, nullptr);
    product.registerCategory("/get", methods, nullptr, nullptr);

    auto reply = configurator.callOneReply("luna://com.webos.service.bus/addOneManifest", v1_manifest.c_str()).get();
    EXPECT_STREQ(reply.getPayload(), R"({"returnValue":true})");

    // Customer v1 can only call get product's methods
    {
        auto customer = LS::registerApplicationService("com.webos.app.customer", "test");
        customer.attachToLoop(loop.get());

        reply = customer.callOneReply("luna://com.webos.service.product/get/method", "{}").get();
        EXPECT_STREQ(reply.getPayload(), R"({"returnValue":true})");

        reply = customer.callOneReply("luna://com.webos.service.product/set/method", "{}").get();
        EXPECT_TRUE(reply.isHubError());

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    reply = configurator.callOneReply("luna://com.webos.service.bus/addOneManifest", v2_manifest.c_str()).get();
    EXPECT_STREQ(reply.getPayload(), R"({"returnValue":true})");

    // Customer v2 can call get and set product's methods
    {
        auto customer = LS::registerApplicationService("com.webos.app.customer", "test");
        customer.attachToLoop(loop.get());

        reply = customer.callOneReply("luna://com.webos.service.product/get/method", "{}").get();
        EXPECT_STREQ(reply.getPayload(), R"({"returnValue":true})");

        reply = customer.callOneReply("luna://com.webos.service.product/set/method", "{}").get();
        EXPECT_STREQ(reply.getPayload(), R"({"returnValue":true})");

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    // fallback to v1
    reply = configurator.callOneReply("luna://com.webos.service.bus/removeOneManifest", v2_manifest.c_str()).get();
    {
        auto customer = LS::registerApplicationService("com.webos.app.customer", "test");
        customer.attachToLoop(loop.get());

        reply = customer.callOneReply("luna://com.webos.service.product/get/method", "{}").get();
        EXPECT_STREQ(reply.getPayload(), R"({"returnValue":true})");

        reply = customer.callOneReply("luna://com.webos.service.product/set/method", "{}").get();
        EXPECT_TRUE(reply.isHubError());

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    // clear all
    reply = configurator.callOneReply("luna://com.webos.service.bus/removeOneManifest", v1_manifest.c_str()).get();
    {
        EXPECT_ANY_THROW(LS::registerApplicationService("com.webos.app.customer", "test"));

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    loop.stop();
}

TEST(TestExternalManifest,  AddRemoveDirectory)
{
    MainLoopT mainloop;

    auto configurator = LS::registerService("com.webos.service.configurator");
    configurator.attachToLoop(mainloop.get());

    auto reply = configurator.callOneReply("luna://com.webos.service.bus/addManifestsDir", v1_dir.c_str()).get();
    EXPECT_STREQ(reply.getPayload(), R"({"returnValue":true})");

    ASSERT_NO_THROW(LS::registerApplicationService("com.webos.app.customer", "test"));

    reply = configurator.callOneReply("luna://com.webos.service.bus/removeManifestsDir", v1_dir.c_str()).get();
    EXPECT_STREQ(reply.getPayload(), R"({"returnValue":true})");

    EXPECT_ANY_THROW(LS::registerApplicationService("com.webos.app.customer", "test"));

    mainloop.stop();
}

TEST(TestExternalManifest, UpdateDirectory)
{
    MainLoopT loop;

    auto configurator = LS::registerService("com.webos.service.configurator");
    configurator.attachToLoop(loop.get());

    auto product = LS::registerService("com.webos.service.product");
    product.attachToLoop(loop.get());

    static LSMethod methods[] =
    {
        { "method", MethodStub, LUNA_METHOD_FLAGS_NONE },
        { nullptr }
    };

    product.registerCategory("/set", methods, nullptr, nullptr);
    product.registerCategory("/get", methods, nullptr, nullptr);

    auto reply = configurator.callOneReply("luna://com.webos.service.bus/addManifestsDir", v1_dir.c_str()).get();
    EXPECT_STREQ(reply.getPayload(), R"({"returnValue":true})");

    // Customer v1 can only call get product's methods
    {
        auto customer = LS::registerApplicationService("com.webos.app.customer", "test");
        customer.attachToLoop(loop.get());

        reply = customer.callOneReply("luna://com.webos.service.product/get/method", "{}").get();
        EXPECT_STREQ(reply.getPayload(), R"({"returnValue":true})");

        reply = customer.callOneReply("luna://com.webos.service.product/set/method", "{}").get();
        EXPECT_TRUE(reply.isHubError());

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    reply = configurator.callOneReply("luna://com.webos.service.bus/addManifestsDir", v2_dir.c_str()).get();
    EXPECT_STREQ(reply.getPayload(), R"({"returnValue":true})");

    // Customer v2 can call get and set product's methods
    {
        auto customer = LS::registerApplicationService("com.webos.app.customer", "test");
        customer.attachToLoop(loop.get());

        reply = customer.callOneReply("luna://com.webos.service.product/get/method", "{}").get();
        EXPECT_STREQ(reply.getPayload(), R"({"returnValue":true})");

        reply = customer.callOneReply("luna://com.webos.service.product/set/method", "{}").get();
        EXPECT_STREQ(reply.getPayload(), R"({"returnValue":true})");

        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    loop.stop();
}
