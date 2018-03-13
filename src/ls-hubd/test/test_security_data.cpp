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

#include <stdlib.h>
#include <glib.h>
#include <unistd.h>
#include <string>

#include <gtest/gtest.h>

#include "../security.hpp"
#include "../groups_map.hpp"
#include "../patternqueue.hpp"

using namespace std;

TEST(TestHubSecurityData, HubSecurityDataTestPatterns)
{
    GroupsMap sg;
    sg.AddRequired("com.palm.test*", "test");
    sg.AddRequired("com.palm.video.*", "video");
    sg.AddRequired("com.palm.audio*", "audio");
    sg.AddRequired("com.palm.surface*", "surface1");
    sg.AddRequired("com.palm.surface.*", "surface2");

    EXPECT_FALSE(sg.GetRequired("com.palm.test").empty());
    EXPECT_FALSE(sg.GetRequired("com.palm.test1").empty());
    EXPECT_FALSE(sg.GetRequired("com.palm.tests.bar").empty());
    EXPECT_TRUE(sg.GetRequired("com.palm.video").empty());
    EXPECT_TRUE(sg.GetRequired("com.palm.video1").empty());
    EXPECT_FALSE(sg.GetRequired("com.palm.video.foo").empty());
    EXPECT_FALSE(sg.GetRequired("com.palm.audio").empty());
    EXPECT_FALSE(sg.GetRequired("com.palm.audio1").empty());
    EXPECT_FALSE(sg.GetRequired("com.palm.audio.bar").empty());
    EXPECT_FALSE(sg.GetRequired("com.palm.surface").empty());
    EXPECT_FALSE(sg.GetRequired("com.palm.surface1").empty());
    EXPECT_FALSE(sg.GetRequired("com.palm.surface.bar").empty());
    EXPECT_FALSE(sg.GetRequired("com.palm.surface1.bar").empty());
}

TEST(TestHubSecurityData, HubSecurityDataTestRequiresAppend)
{
    Groups groups;

    GroupsMap sg;
    sg.AddRequired("com.palm.test", "test1");
    sg.AddRequired("com.palm.test", "test2");
    sg.AddRequired("com.palm.video*", "video1");
    sg.AddRequired("com.palm.video*", "video2");
    sg.AddRequired("com.palm.audio", "audio1");
    sg.AddRequired("com.palm.audio", "audio2");
    sg.AddRequired("com.palm.audio", "audio3");
    sg.AddRequired("com.palm.audio", "audio1");

    sg.AddRequired("com.palm.audio*", "audio1");
    sg.AddRequired("com.palm.audio*", "audio2");
    sg.AddRequired("com.palm.audio*", "audio1");

    sg.AddRequired("com.palm.audio.*", "audio1");
    sg.AddRequired("com.palm.audio.*", "audio2");
    sg.AddRequired("com.palm.audio.*", "audio3");
    sg.AddRequired("com.palm.audio.*", "audio1");

    const char *test1_str = g_intern_string("test1");
    const char *test2_str = g_intern_string("test2");

    groups = sg.GetRequired("com.palm.test");
    EXPECT_EQ(Groups({test1_str, test2_str}), groups);

    const char *video1_str = g_intern_string("video1");
    const char *video2_str = g_intern_string("video2");

    groups = sg.GetRequired("com.palm.video1");
    EXPECT_EQ(Groups({video1_str, video2_str}), groups);

    groups = sg.GetRequired("com.palm.video.bar");
    EXPECT_EQ(Groups({video1_str, video2_str}), groups);

    const char *audio1_str = g_intern_string("audio1");
    const char *audio2_str = g_intern_string("audio2");
    const char *audio3_str = g_intern_string("audio3");

    groups = sg.GetRequired("com.palm.audio");
    EXPECT_EQ(Groups({audio1_str, audio1_str, audio1_str, audio1_str, audio2_str, audio2_str, audio3_str}), groups);

    groups = sg.GetRequired("com.palm.audio1");
    EXPECT_EQ(Groups({audio1_str, audio1_str, audio2_str}), groups);

    groups = sg.GetRequired("com.palm.audio.foo");
    EXPECT_EQ(Groups({audio1_str, audio1_str, audio1_str, audio1_str, audio2_str, audio2_str, audio3_str}), groups);
}

TEST(TestHubSecurityData, HubSecurityDataTestRequiresCommon)
{
    Groups groups;

    GroupsMap sg;
    sg.AddRequired("*", "all");
    sg.AddRequired("com.palm.*", "palm");
    sg.AddRequired("com.palm.test*", "test1");
    sg.AddRequired("com.palm.test*", "test2");
    sg.AddRequired("com.palm.video.*", "video");
    sg.AddRequired("com.palm.audio*", "audio1");
    sg.AddRequired("com.palm.audio*", "audio2");
    sg.AddRequired("com.palm.audio*", "audio1");
    sg.AddRequired("com.palm.surface*", "surface");
    sg.AddRequired("com.palm.surface.*", "surface-all");
    sg.AddRequired("com.palm.surface.test", "surface-test");

    const char *all_str = g_intern_string("all");

    groups = sg.GetRequired("com.webos");
    EXPECT_EQ(Groups({all_str}), groups);

    groups = sg.GetRequired("com.palm");
    EXPECT_EQ(Groups({all_str}), groups);

    const char *palm_str = g_intern_string("palm");

    groups = sg.GetRequired("com.palm.foo");
    EXPECT_EQ(Groups({palm_str, all_str}), groups);

    const char *test1_str = g_intern_string("test1");
    const char *test2_str = g_intern_string("test2");

    groups = sg.GetRequired("com.palm.test");
    EXPECT_EQ(Groups({all_str, palm_str, test1_str, test2_str}), groups);

    groups = sg.GetRequired("com.palm.test1");
    EXPECT_EQ(Groups({all_str, palm_str, test1_str, test2_str}), groups);

    groups = sg.GetRequired("com.palm.test.bar");
    EXPECT_EQ(Groups({all_str, palm_str, test1_str, test2_str}), groups);

    groups = sg.GetRequired("com.palm.video");
    EXPECT_EQ(Groups({palm_str, all_str}), groups);

    groups = sg.GetRequired("com.palm.video1");
    EXPECT_EQ(Groups({palm_str, all_str}), groups);

    const char *video_str = g_intern_string("video");

    groups = sg.GetRequired("com.palm.video.foo");
    EXPECT_EQ(Groups({all_str, palm_str, video_str}), groups);

    const char *audio1_str = g_intern_string("audio1");
    const char *audio2_str = g_intern_string("audio2");

    groups = sg.GetRequired("com.palm.audio");
    EXPECT_EQ(Groups({all_str, palm_str, audio1_str, audio1_str, audio2_str}), groups);

    groups = sg.GetRequired("com.palm.audio1");
    EXPECT_EQ(Groups({all_str, palm_str, audio1_str, audio1_str, audio2_str}), groups);

    groups = sg.GetRequired("com.palm.audio.bar");
    EXPECT_EQ(Groups({all_str, palm_str, audio1_str, audio1_str, audio2_str}), groups);

    const char *surface_str = g_intern_string("surface");

    groups = sg.GetRequired("com.palm.surface");
    EXPECT_EQ(Groups({all_str, palm_str, surface_str}), groups);

    groups = sg.GetRequired("com.palm.surface1");
    EXPECT_EQ(Groups({all_str, palm_str, surface_str}), groups);

    const char *surface_all_str = g_intern_string("surface-all");

    groups = sg.GetRequired("com.palm.surface.foo");
    EXPECT_EQ(Groups({all_str, palm_str, surface_str, surface_all_str}), groups);

    const char *surface_test_str = g_intern_string("surface-test");

    groups = sg.GetRequired("com.palm.surface.test");
    EXPECT_EQ(Groups({all_str, palm_str, surface_str, surface_all_str, surface_test_str}), groups);
}

TEST(TestHubSecurityData, HubSecurityDataTestProvidesCommon)
{
    CategoryMap cats;
    CategoryMap test_cats{};

    // Example groups definition JSON
    //{
    //  "private" : ["*/com/palm/luna/private/*"],
    //  "public" : ["*/com/palm/luna/private/ping", "*/com/palm/luna/private/cancel"],
    //  "palm" : ["com.palm*/palm/", "com.palm.*/palm/*"],
    //  "palm-test" : ["com.palm.test/palm/test/"],
    //  "palm-test-all" : ["com.palm.test*/palm/test/*"],
    //  "video-all" : ["com.palm.video*/video/", "com.palm.video.*/video/*"],
    //  "video-test" : ["com.palm.video.test/video/test*"]
    //}
    //

    GroupsMap sg;
    sg.AddProvided("*", "/com/palm/luna/private/*", "private");
    sg.AddProvided("*", "/com/palm/luna/private/ping", "public");
    sg.AddProvided("*", "/com/palm/luna/private/cancel", "public");
    sg.AddProvided("com.palm*", "/palm/", "palm");
    sg.AddProvided("com.palm.*", "/palm/*", "palm");
    sg.AddProvided("com.palm.test", "/palm/test/", "palm-test");
    sg.AddProvided("com.palm.test.*", "/palm/test/*", "palm-test-all");
    sg.AddProvided("com.palm.video*", "/video/", "video-all");
    sg.AddProvided("com.palm.video.*", "/video/*", "video-all");
    sg.AddProvided("com.palm.video.test", "/video/test*", "video-test");

    const char *private_str = g_intern_string("private");
    const char *public_str = g_intern_string("public");

    cats = sg.GetProvided("com.webos.test");
    test_cats =
    {
        {"/com/palm/luna/private/*", {private_str}},
        {"/com/palm/luna/private/ping", {public_str}},
        {"/com/palm/luna/private/cancel", {public_str}}
    };
    EXPECT_EQ(test_cats, cats);

    const char *palm_str = g_intern_string("palm");

    cats = sg.GetProvided("com.palm");
    test_cats =
    {
        {"/palm/", {palm_str}},
        {"/com/palm/luna/private/*", {private_str}},
        {"/com/palm/luna/private/ping", {public_str}},
        {"/com/palm/luna/private/cancel", {public_str}}
    };
    EXPECT_EQ(test_cats, cats);

    cats = sg.GetProvided("com.palm1");
    test_cats =
    {
        {"/com/palm/luna/private/*", {private_str}},
        {"/com/palm/luna/private/ping", {public_str}},
        {"/com/palm/luna/private/cancel", {public_str}},
        {"/palm/", {palm_str}}
    };
    EXPECT_EQ(test_cats, cats);

    cats = sg.GetProvided("com.palm.foo");
    test_cats =
    {
        {"/com/palm/luna/private/*", {private_str}},
        {"/com/palm/luna/private/ping", {public_str}},
        {"/com/palm/luna/private/cancel", {public_str}},
        {"/palm/", {palm_str}},
        {"/palm/*", {palm_str}}
    };
    EXPECT_EQ(test_cats, cats);

    const char *palm_test_str = g_intern_string("palm-test");

    cats = sg.GetProvided("com.palm.test");
    test_cats =
    {
        {"/com/palm/luna/private/*", {private_str}},
        {"/com/palm/luna/private/ping", {public_str}},
        {"/com/palm/luna/private/cancel", {public_str}},
        {"/palm/", {palm_str}},
        {"/palm/*", {palm_str}},
        {"/palm/test/", {palm_test_str}}
    };
    EXPECT_EQ(test_cats, cats);

    const char *palm_test_all_str = g_intern_string("palm-test-all");

    cats = sg.GetProvided("com.palm.test.foo");
    test_cats =
    {
        {"/com/palm/luna/private/*", {private_str}},
        {"/com/palm/luna/private/ping", {public_str}},
        {"/com/palm/luna/private/cancel", {public_str}},
        {"/palm/", {palm_str}},
        {"/palm/*", {palm_str}},
        {"/palm/test/*", {palm_test_all_str}}
    };
    EXPECT_EQ(test_cats, cats);

    const char *video_all_str = g_intern_string("video-all");

    cats = sg.GetProvided("com.palm.video");
    test_cats =
    {
        {"/com/palm/luna/private/*", {private_str}},
        {"/com/palm/luna/private/ping", {public_str}},
        {"/com/palm/luna/private/cancel", {public_str}},
        {"/palm/", {palm_str}},
        {"/palm/*", {palm_str}},
        {"/video/", {video_all_str}}
    };
    EXPECT_EQ(test_cats, cats);

    cats = sg.GetProvided("com.palm.video1");
    test_cats =
    {
        {"/com/palm/luna/private/*", {private_str}},
        {"/com/palm/luna/private/ping", {public_str}},
        {"/com/palm/luna/private/cancel", {public_str}},
        {"/palm/", {palm_str}},
        {"/palm/*", {palm_str}},
        {"/video/", {video_all_str}}
    };
    EXPECT_EQ(test_cats, cats);

    cats = sg.GetProvided("com.palm.video.foo");
    test_cats =
    {
        {"/com/palm/luna/private/*", {private_str}},
        {"/com/palm/luna/private/ping", {public_str}},
        {"/com/palm/luna/private/cancel", {public_str}},
        {"/palm/", {palm_str}},
        {"/palm/*", {palm_str}},
        {"/video/", {video_all_str}},
        {"/video/*", {video_all_str}}
    };
    EXPECT_EQ(test_cats, cats);

    const char *video_test_str = g_intern_string("video-test");

    cats = sg.GetProvided("com.palm.video.test");
    test_cats =
    {
        {"/com/palm/luna/private/*",{private_str}},
        {"/com/palm/luna/private/ping", {public_str}},
        {"/com/palm/luna/private/cancel", {public_str}},
        {"/palm/", {palm_str}},
        {"/palm/*", {palm_str}},
        {"/video/", {video_all_str}},
        {"/video/*", {video_all_str}},
        {"/video/test*", {video_test_str}}
    };
    EXPECT_EQ(test_cats, cats);
}


int
main(int argc, char *argv[])
{
    ::testing::InitGoogleTest(&argc, argv);

    return RUN_ALL_TESTS();
}
