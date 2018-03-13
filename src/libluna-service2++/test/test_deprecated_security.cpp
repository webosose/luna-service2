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

#include <luna-service2/lunaservice.hpp>
#include <gtest/gtest.h>

#include "test_util.hpp"

#define SRV_PUB "com.palm.test.pub"
#define SRV_PRV "com.palm.test.prv"
#define SRV_BOTH "com.palm.test.both"

using namespace std;

namespace {
	enum BusType {
		BusPublic,
		BusPrivate
	};

	template <BusType bus_type = BusPrivate>
	bool handleMethod(LSHandle *h, LSMessage *cmsg, void *)
	{
		LS::Message msg {cmsg};
		bool public_bus = bus_type == BusPublic;
		std::string bus = public_bus ? "pub" : "prv";

		std::string method = msg.getMethod();

		if (method == "never_answered")
		{
			return false;
		}
		else if (method == "echo" || method == (bus + "_echo"))
		{
			EXPECT_NO_THROW({ msg.respond(msg.getPayload()); });
			return true;
		}
		else
		{
			ADD_FAILURE() << "Unexpected call from " << msg.getSenderServiceName()
			              << " to " << msg.getCategory() << '/' << method
			              << '@' << bus;
			return false;
		}
	}

	void addMethods(LS::PalmService &srv)
	{
		static LSMethod methods_both[] = {
			{ "never_answered", handleMethod<> },
			{ "echo", handleMethod<> },
			{}
		};
		static LSMethod methods_prv[] = {
			{ "prv_echo", handleMethod<> },
			{}
		};
		static LSMethod methods_pub[] = {
			{ "pub_echo", handleMethod<BusPublic> },
			{}
		};
		srv.registerCategory("/", methods_both, methods_prv, nullptr);
		srv.getPublicHandle().registerCategoryAppend("/", methods_pub, nullptr);
	}

	std::string getAnswer(LS::Handle &h, const std::string &uri, const char *payload = "{}")
	{
		LS::Call call;
		EXPECT_NO_THROW({ call = h.callOneReply(uri.c_str(), payload); })
			<< "Call from " << h.getName() << " to " << uri;
		auto actual_answer = call.get(1000);
		if (actual_answer) return actual_answer.getPayload();
		ADD_FAILURE() << "No answer for " << uri << " with " << payload;
		return {};
	}
} // anonymous namespace

TEST(TestDeprecatedSecurity, allowed_names_match)
{
	EXPECT_NO_THROW({ LS::registerService(SRV_PRV, false); });
	EXPECT_NO_THROW({ LS::registerService(SRV_PUB, true); });
	EXPECT_NO_THROW({ LS::registerService(SRV_BOTH, true); });
	EXPECT_NO_THROW({ LS::registerService(SRV_BOTH, false); });
}

TEST(TestDeprecatedSecurity, allowed_names_mismatch)
{
	EXPECT_THROW({ LS::registerService(SRV_PRV, true); }, LS::Error);
	EXPECT_THROW({ LS::registerService(SRV_PUB, false); }, LS::Error);
}

TEST(TestDeprecatedSecurity, bus_registration_purity)
{
	// keep them alive until test end (we know that transport may be shared
	// between two handles)
	LS::Handle a, b, c, d, e, f;

	EXPECT_THROW({ a = LS::registerService(SRV_PRV, true); }, LS::Error);
	EXPECT_NO_THROW({ b = LS::registerService(SRV_PRV, false); });
	EXPECT_THROW({ c = LS::registerService(SRV_PRV, true); }, LS::Error);

	EXPECT_THROW({ d = LS::registerService(SRV_PUB, false); }, LS::Error);
	EXPECT_NO_THROW({ e = LS::registerService(SRV_PUB, true); });
	EXPECT_THROW({ f = LS::registerService(SRV_PUB, false); }, LS::Error);
}

TEST(TestDeprecatedSecurity, bus_isolation)
{
	LS::Handle pub, prv;
	LS::PalmService srv;

	auto ctx = mk_ptr(g_main_context_new(), g_main_context_unref);
	ASSERT_TRUE(bool(ctx));

	ASSERT_NO_THROW({ prv = LS::registerService(SRV_PRV, false); });
	ASSERT_NO_THROW({ pub = LS::registerService(SRV_PUB, true); });
	ASSERT_NO_THROW({ srv = LS::registerPalmService(SRV_BOTH); });
	ASSERT_NO_THROW({ addMethods(srv); });

	ASSERT_NO_THROW({ prv.attachToLoop(ctx.get()); });
	ASSERT_NO_THROW({ pub.attachToLoop(ctx.get()); });
	ASSERT_NO_THROW({ srv.attachToLoop(ctx.get()); });

	EXPECT_EQ("{}", getAnswer(pub, "luna://" SRV_BOTH "/echo"));
	EXPECT_EQ("{}", getAnswer(pub, "luna://" SRV_BOTH "/pub_echo"));
	EXPECT_NE("{}", getAnswer(pub, "luna://" SRV_BOTH "/prv_echo"));

	EXPECT_EQ("{}", getAnswer(prv, "luna://" SRV_BOTH "/echo"));
	EXPECT_NE("{}", getAnswer(prv, "luna://" SRV_BOTH "/pub_echo"));
	EXPECT_EQ("{}", getAnswer(prv, "luna://" SRV_BOTH "/prv_echo"));

	EXPECT_EQ("{}", getAnswer(srv.getPublicHandle(), "luna://" SRV_BOTH "/echo"));
	EXPECT_EQ("{}", getAnswer(srv.getPublicHandle(), "luna://" SRV_BOTH "/pub_echo"));

	EXPECT_EQ("{}", getAnswer(srv.getPrivateHandle(), "luna://" SRV_BOTH "/echo"));
	EXPECT_EQ("{}", getAnswer(srv.getPrivateHandle(), "luna://" SRV_BOTH "/prv_echo"));

	// We have both public and private security groups in our requires. Thus we
	// should be able to call through any handle method with any of those
	// groups.
	// Old service processes private calls on both buses (handle calls from both old/new clients)
	// Old service processes public calls only on private bus (handle calls only for old clients)
	EXPECT_NE("{}", getAnswer(srv.getPublicHandle(), "luna://" SRV_BOTH "/prv_echo"));
	EXPECT_EQ("{}", getAnswer(srv.getPrivateHandle(), "luna://" SRV_BOTH "/pub_echo"));
}

TEST(TestDeprecatedSecurity, bus_routing)
{
	auto ctx = mk_ptr(g_main_context_new(), g_main_context_unref);
	ASSERT_TRUE(bool(ctx));

	LS::Handle pub, prv;

	ASSERT_NO_THROW({ prv = LS::registerService(SRV_BOTH, false); });
	ASSERT_NO_THROW({ pub = LS::registerService(SRV_BOTH, true); });

	static LSMethod methods_prv[] = {
		{ "prv_echo", handleMethod<BusPrivate> },
		{ "pub_echo", handleMethod<BusPrivate> },
		{}
	};

	static LSMethod methods_pub[] = {
		{ "prv_echo", handleMethod<BusPublic> },
		{ "pub_echo", handleMethod<BusPublic> },
		{}
	};

	ASSERT_NO_THROW({ prv.registerCategory("/", methods_prv, nullptr, nullptr); });
	ASSERT_NO_THROW({ pub.registerCategory("/", methods_pub, nullptr, nullptr); });

	ASSERT_NO_THROW({ prv.attachToLoop(ctx.get()); });
	ASSERT_NO_THROW({ pub.attachToLoop(ctx.get()); });

	EXPECT_EQ("{}", getAnswer(pub, "luna://" SRV_BOTH "/pub_echo"));
	EXPECT_EQ("{}", getAnswer(prv, "luna://" SRV_BOTH "/prv_echo"));
}

// FIXME: fix this test case when we able to register com.palm.test.both-foo but
//        LSCall to that service fails
TEST(TestDeprecatedSecurity, DISABLED_dash_issue)
{
	LS::PalmService srv;

	auto ctx = mk_ptr(g_main_context_new(), g_main_context_unref);
	ASSERT_TRUE(bool(ctx));

	ASSERT_NO_THROW({ srv = LS::registerPalmService(SRV_BOTH "-foo"); });
	ASSERT_NO_THROW({ addMethods(srv); });

	ASSERT_NO_THROW({ srv.attachToLoop(ctx.get()); });

	EXPECT_EQ("{}", getAnswer(srv.getPublicHandle(), "luna://" SRV_BOTH "-foo/echo"));
}

TEST(TestDeprecatedSecurity, inbound_outbound)
{
	//  services allowed directions
	//  A <--  C
	//  A <--> D
	//  B  --> C
	//  B <--> D
	//  E  --> *
	//  F <--  *
	//  G <-->

	enum Srv : int { A, B, C, D, E, F, G };

	auto serviceIds = { A, B, C, D, E, F, G };

	auto srvName = [](Srv id)
		{ return std::string(SRV_BOTH) + '.' + char(id - A + 'a'); };

	LS::PalmService services[G - A + 1];

	auto srv = [&](Srv id) -> LS::PalmService & { return services[id - A]; };

	auto ctx = mk_ptr(g_main_context_new(), g_main_context_unref);
	ASSERT_TRUE(bool(ctx));

	for (auto i : serviceIds)
	{
		auto &service = srv(i);
		ASSERT_NO_THROW({ service = LS::registerPalmService(srvName(i).c_str()); })
			<< "Should be able to register service " << srvName(i);
		ASSERT_NO_THROW({ addMethods(service); });
		ASSERT_NO_THROW({ service.attachToLoop(ctx.get()); });
	}

	auto expectAllow = [&](Srv x, Srv y)
	{
		EXPECT_EQ("{}", getAnswer(srv(x).getPublicHandle(), "luna://" + srvName(y) + "/echo"))
			<< "Expect allowed call from " << srvName(x) << " to " << srvName(y);
	};
	auto expectDeny = [&](Srv x, Srv y)
	{
		EXPECT_NE("{}", getAnswer(srv(x).getPublicHandle(), "luna://" + srvName(y) + "/echo"))
			<< "Expect denial for call from " << srvName(x) << " to " << srvName(y);
	};

	// from A
	for (auto i : serviceIds)
	{
		switch (i)
		{
		case D: expectAllow(A, i); break;
		default: expectDeny(A, i); break;
		}
	}

	// from B
	for (auto i : serviceIds)
	{
		switch (i)
		{
		case C:
		case D:
			expectAllow(B, i);
			break;
		default: expectDeny(B, i); break;
		}
	}

	// from C
	for (auto i : serviceIds)
	{
		switch (i)
		{
		case A: expectAllow(C, i); break;
		default: expectDeny(C, i); break;
		}
	}

	// from D
	for (auto i : serviceIds)
	{
		switch (i)
		{
		case A:
		case B:
			expectAllow(D, i);
			break;
		default: expectDeny(D, i); break;
		}
	}

	// from E
	for (auto i : serviceIds)
	{
		switch (i)
		{
		case A:
		case B:
		case C:
		case D:
			expectDeny(E, i); break;
		default: expectAllow(E, i); break;
		}
	}

	// from F, G
	for (auto i : serviceIds)
	{
		expectDeny(F, i);
		expectDeny(G, i);
	}
}
