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

#include <gtest/gtest.h>
#include "../semantic_version.hpp"


namespace {
    typedef struct {
        int group;
        const char * version;
    } version_type;

    version_type sorted_valid_versions[] = {
        {0, "0.0.0-QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ" \
            "QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ" \
            "QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ-A.5"},
        {0, "0.0.0-QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ" \
            "QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ" \
            "QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ-B.4"},
        {0, "0.0.0-QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ" \
            "QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ" \
            "QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ-C.3"},
        {0, "0.0.0-QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ" \
            "QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ" \
            "QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ-D.2"},
        {0, "0.0.0-QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ" \
            "QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ" \
            "QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ-E.1"},
        {0, "0.0.0-QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ" \
            "QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ" \
            "QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ-F.0"},
        {0, "0.0.0"},
        {0, "0.12.1001-alpha"},
        {0, "0.12.1002-alpha.1-0"},
        {0, "0.12.1002-alpha.1-0.0"},
        {0, "0.12.1003-alpha.1-1"},
        {0, "0.12.1003-alpha.1-1.1"},
        {0, "0.12.1004-alpha.1-2"},
        {0, "0.12.1004-alpha.1-2.2"},
        {0, "0.12.1005-alpha.1-3"},
        {0, "0.12.1005-alpha.1-3.3"},
        {0, "0.12.1007-alpha.1-0.0"},
        {0, "0.12.1007-alpha.1-0.1"},
        {0, "0.12.1007-alpha.1-0.2"},
        {0, "0.12.1007-alpha.1-0.3"},
        {0, "0.12.1011-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
        {0, "0.12.1011-alpha.1-0.0.1"},
        {0, "0.12.1011-alpha.1-0.0.10"},
        {0, "0.12.1011-alpha.1-0.0.100"},
        {0, "0.12.1011-alpha.1-0.0.1000"},
        {0, "0.12.1011-alpha.1-0.0.10000"},
        {0, "0.12.1011-alpha.1-0.0.*1"},
        {0, "0.12.1011-alpha.1-0.0.*10"},
        {0, "0.12.1011-alpha.1-0.0.*100"},
        {0, "0.12.1011-alpha.1-0.0.*1000"},
        {0, "0.12.1011-alpha.1-0.0.*10000"},
        {0, "0.12.1011-alpha.1-0.0.-1"},
        {0, "0.12.1011-alpha.1-0.0.-10"},
        {0, "0.12.1011-alpha.1-0.0.-100"},
        {0, "0.12.1011-alpha.1-0.0.-1000"},
        {0, "0.12.1011-alpha.1-0.0.-10000"},
        {0, "0.12.1011-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
        {0, "0.12.1011-beta"},
        {0, "0.12.1011-beta.1-0.0.-1"},
        {0, "0.12.1011-beta-"},
        {0, "0.12.1011-beta-v0"},
        {0, "0.12.1011-beta-v1"},
        {0, "0.12.1011-gamma.1-0.0.-1"},
        {0, "0.12.1011"},
        {0, "0.12.1020-alpha.1-4"},
        {0, "0.12.1020-alpha.1-4.4"},
        {0, "0.12.3456-beta.1*0.0.-1"},
        {0, "0.12.3456-beta.1-0"},
        {0, "0.12.3456-beta.1-0.0"},
        {0, "0.12.3456-beta.1-0.1"},
        {0, "0.12.3456-beta.1-0.2"},
        {0, "0.12.3456-beta.1-0.3"},

        // Equivalent group #10
        {10, "0.12.3456-beta.1-0.rv+vertbnb"},
        {10, "0.12.3456-beta.1-0.rv+sdfsgdsf"},
        {10, "0.12.3456-beta.1-0.rv+dfv1d6glh"},
        {10, "0.12.3456-beta.1-0.rv"},
        {10, "0.12.3456-beta.1-0.rv+4456974589"},
        {10, "0.12.3456-beta.1-0.rv+odf5gmsxcbj"},

        {0, "0.12.3456-beta.1-1"},
        {0, "0.12.3456-beta.1-1.0.-2"},
        {0, "0.12.3456-beta.1-1.t"},
        {0, "0.12.3456-beta.1-2"},
        {0, "0.12.3456-beta.1-2.0.-3"},
        {0, "0.12.3456-beta.1-2.r"},
        {0, "0.12.3456-beta.1-3"},
        {0, "0.12.3456-beta.1-3.0.4"},
        {0, "0.12.3456-beta.1-3.0.-4"},
        {0, "0.12.3456-beta.1-3.d"},
        {0, "0.12.3456-beta.1-4"},
        {0, "0.12.3456-beta.1-4.0.-5"},
        {0, "0.12.3456-beta.1-4.v"},
        {0, "1.9.0"},
        {0, "1.9.1939-alpha"},
        {0, "1.9.1939-alpha.0"},
        {0, "1.9.1939-alpha.1"},
        {0, "1.9.1939-alpha.2"},
        {0, "1.9.1939-rc.0"},
        {0, "1.9.1939-rc.1"},
        {0, "1.9.1939"},
        {0, "3.14.15-alpha"},
        {0, "3.14.15-beta"},
        {0, "3.14.15-delta"},
        {0, "3.14.15-gamma"},
        {0, "3.14.15-rc.0"},
        {0, "3.14.15-rc.1"},
        {0, "3.14.15-rc.2"},
        {0, "3.14.15-rc0"},
        {0, "3.14.15-rc1"},
        {0, "3.14.15-rc2"},

        // Equivalent group #20
        {20, "3.14.15"},
        {20, "3.14.15+445566"},
        {20, "3.14.15+998877"},

        {0, "7.0.0"},
        {0, "7.0.1"},
        {0, "7.0.2"},
        {0, "7.1.0"},
        {0, "7.1.1"},
        {0, "7.1.2"},
        {0, "7.2.0"},
        {0, "7.2.1"},
        {0, "7.2.2"},
        {0, "8.0.0"},
        {0, "8.0.1"},
        {0, "8.0.2"},
        {0, "8.0.9"},
        {0, "8.0.10"},
        {0, "8.0.11"},
        {0, "8.0.99"},
        {0, "8.0.100"},
        {0, "8.0.101"},
        {0, "8.1.0"},
        {0, "8.1.1"},
        {0, "8.1.2"},
        {0, "8.2.0"},
        {0, "8.2.1"},
        {0, "8.2.2"},
        {0, "8.9.0"},
        {0, "8.10.0"},
        {0, "8.11.0"},
        {0, "8.99.0"},
        {0, "8.100.0"},
        {0, "8.101.0"},
        {0, "9.0.0"},
        {0, "9.0.1"},
        {0, "9.0.2"},
        {0, "9.1.0"},
        {0, "9.1.1"},
        {0, "9.1.2"},
        {0, "9.2.0"},
        {0, "9.2.1"},
        {0, "9.2.2"},
        {0, "10.0.0-alpha"},
        {0, "10.0.0-alpha.1"},
        {0, "10.0.0-beta"},
        {0, "10.0.0-beta.1"},
        {0, "10.0.0-beta.1.2"},
        {0, "10.0.0-beta.2"},
        {0, "10.0.0-beta.025a"},
        {0, "10.0.0-beta.1-2"},
        {0, "10.0.0-beta.1-3"},
        {0, "10.0.0-betaz"},
        {0, "10.0.0-rc"},
        {0, "10.0.0"},

        // Equivalent group #30
        {30, "11.9.2001-4499+3654789874557445"},
        {30, "11.9.2001-4499+3654789874557445"},
        {30, "11.9.2001-4499+3654789874557445"},
        {30, "11.9.2001-4499+3654789874557445"},
        {30, "11.9.2001-4499+3654789874557445"},
        {30, "11.9.2001-4499+-654789874557445"},
        {30, "11.9.2001-4499+3-5478987455744"},
        {30, "11.9.2001-4499+36-47898745574"},
        {30, "11.9.2001-4499+365-789874557"},
        {30, "11.9.2001-4499+3654-8987455"},

        {0, "11.9.2001--"},
        {0, "11.9.2001---"},
        {0, "11.9.2001----"},
        {0, "11.9.2001-----"},
        {0, "11.9.2001------"},
        {0, "11.9.2001-------"},
        {0, "11.9.2001--------"},
        {0, "11.9.2001---------"},
        {0, "11.9.2001----------"},
        {0, "11.9.2001-----------"},
        {0, "11.9.2001------------"},

        // Equivalent group #35
        {35, "11.9.2002-------+---------"},
        {35, "11.9.2002-------+--------"},
        {35, "11.9.2002-------+-------"},
        {35, "11.9.2002-------+------"},
        {35, "11.9.2002-------+-----"},
        {35, "11.9.2002-------+----"},
        {35, "11.9.2002-------+---"},
        {35, "11.9.2002-------+--"},
        {35, "11.9.2002-------"},

        {0, "11.9.2002"},
        {0, "11.33.55-22+sdfasdasdsdvadfgdafdafb"},

        // Equivalent group #40
        {40, "11.33.55"},
        {40, "11.33.55+25699847"},

        // Equivalent group #50
        {50, "11.33.56-33.55.66.99+fgvdfgghklsdvfdgfh"},
        {50, "11.33.56-33.55.66.99+fgvdfgghklsdvfdgfh"},

        // Equivalent group #55
        {55, "11.33.56"},
        {55, "11.33.56+7789644758"},

        {0, "11.33.57-abba+457866426365426845632569874"},
        {0, "11.33.57"},

        // Equivalent group #60
        {60, "44.66.88+4554cvzfv555s4dfsdf56655asdfsvcv"},
        {60, "44.66.88"},
        {60, "44.66.88+4554cvzfv555s4dfsdf56655asdfsvcv-sdfasdgg-sdfsdfgdsfg-sfghsfghfgh-bsdfbdsfb-sdfgsdfgsdf"},
        {60, "44.66.88+4554cvzfv555s4dfsdf56655asdfsvcv.sdfasdgg.sdfsdfgdsfg.sfghsfghfgh.bsdfbdsfb.sdfgsdfgsdf"},
        {60, "44.66.88+256987"},

        {0, "123456789.987654321.123456787-ababagalamaga-alcatras-copacabana-banana"},
        {0, "123456789.987654321.123456787-ababagalamaga-alcatras-copacabana-banana.rc"},
        {0, "123456789.987654321.123456787-ababagalamaga-alcatras-copacabana-banana.rc.0"},
        {0, "123456789.987654321.123456787-ababagalamaga-alcatras-copacabana-banana.rc.1"},
        {0, "123456789.987654321.123456787-ababagalamaga-alcatras-copacabana-banana.rc.2"},
        {0, "123456789.987654321.123456787-ababagalamaga-alcatras-copacabana-banana.rc.3"},
        {0, "123456789.987654321.123456787"},
        {0, "123456789.987654321.123456788"},

        // Equivalent group #70
        {70, "123456789.987654321.123456789-987654321.123456789-987654321.123456787+123456789012"},
        {70, "123456789.987654321.123456789-987654321.123456789-987654321.123456787+12345678901"},
        {70, "123456789.987654321.123456789-987654321.123456789-987654321.123456787+1234567890"},
        {70, "123456789.987654321.123456789-987654321.123456789-987654321.123456787"},
        {70, "123456789.987654321.123456789-987654321.123456789-987654321.123456787+123456789"},
        {70, "123456789.987654321.123456789-987654321.123456789-987654321.123456787+1234567"},

        {0, "123456789.987654321.123456789"},
        {0, "987654321.123456789.987654321-ananab"},
        {0, "987654321.123456789.987654321-ananab.951"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla.1"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla.12"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla.123"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla.1234"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla.12345"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla.123456"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla.1234567"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla.12345678"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla.123456789"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla.1234567898"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla.12345678987"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla.123456789876"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla.1234567898765"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla.12345678987654"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla.123456789876543"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla.1234567898765432"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla.12345678987654321"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla.123456789876543210"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla.1234567898765432101"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla.12345678987654321012"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla.123456789876543210123"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla.1234567898765432101234"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla.12345678987654321012345"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla.123456789876543210123456"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla.1234567898765432101234567"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla.12345678987654321012345678"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla.123456789876543210123456789"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla.1234567898765432101234567898"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla.12345678987654321012345678987"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla.123456789876543210123456789876"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla.1234567898765432101234567898765"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla.12345678987654321012345678987654"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla.123456789876543210123456789876543"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla.1234567898765432101234567898765432"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla.12345678987654321012345678987654321"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla.123456789876543210123456789876543210"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla-"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla-1"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla-12"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla-123"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla-1234"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla-12345"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla-123456"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla-1234567"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla-12345678"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla-123456789"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla-1234567898"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla-12345678987"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla-123456789876"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla-1234567898765"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla-12345678987654"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla-123456789876543"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla-1234567898765432"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla-12345678987654321"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla-123456789876543210"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla-1234567898765432101"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla-12345678987654321012"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla-123456789876543210123"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla-1234567898765432101234"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla-12345678987654321012345"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla-123456789876543210123456"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla-1234567898765432101234567"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla-12345678987654321012345678"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla-123456789876543210123456789"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla-1234567898765432101234567898"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla-12345678987654321012345678987"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla-123456789876543210123456789876"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla-1234567898765432101234567898765"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla-12345678987654321012345678987654"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla-123456789876543210123456789876543"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla-1234567898765432101234567898765432"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla-12345678987654321012345678987654321"},
        {0, "987654321.123456789.987654321-ananab.951.anabacapoc.sartacla.753.agamalagababa.quibbla-123456789876543210123456789876543210"},
        {0, "987654321.123456789.987654321"},
        {0, "123456789876543210123456789876543210123456789876543210.123456789876543210123456789876543210123456789876543210.123456789876543210123456789876543210123456789876543210"},
        {0, "123456789876543210123456789876543210123456789876543210.123456789876543210123456789876543210123456789876543210.123456789876543210123456789876543210123456789876543211"},
        {0, "123456789876543210123456789876543210123456789876543210.123456789876543210123456789876543210123456789876543210.123456789876543210123456789876543210123456789876543212"},
        {0, "123456789876543210123456789876543210123456789876543210.123456789876543210123456789876543210123456789876543210.123456789876543210123456789876543210123456789876543213"},
        {0, "123456789876543210123456789876543210123456789876543210.123456789876543210123456789876543210123456789876543210.123456789876543210123456789876543210123456789876543214"},
        {0, "123456789876543210123456789876543210123456789876543210.123456789876543210123456789876543210123456789876543210.123456789876543210123456789876543210123456789876543215-alpha.1"},
        {0, "123456789876543210123456789876543210123456789876543210.123456789876543210123456789876543210123456789876543210.123456789876543210123456789876543210123456789876543215-alpha.2"},
        {0, "123456789876543210123456789876543210123456789876543210.123456789876543210123456789876543210123456789876543210.123456789876543210123456789876543210123456789876543215-alpha.3"},
        {0, "123456789876543210123456789876543210123456789876543210.123456789876543210123456789876543210123456789876543210.123456789876543210123456789876543210123456789876543215-beta.1"},

        // Equivalent group #80
        {80, "123456789876543210123456789876543210123456789876543210.123456789876543210123456789876543210123456789876543210.123456789876543210123456789876543210123456789876543215-beta.2"},
        {80, "123456789876543210123456789876543210123456789876543210.123456789876543210123456789876543210123456789876543210.123456789876543210123456789876543210123456789876543215-beta.2+asdfg"},
        {80, "123456789876543210123456789876543210123456789876543210.123456789876543210123456789876543210123456789876543210.123456789876543210123456789876543210123456789876543215-beta.2+qwerty"},
        {80, "123456789876543210123456789876543210123456789876543210.123456789876543210123456789876543210123456789876543210.123456789876543210123456789876543210123456789876543215-beta.2+azertyu"},

        {0, "123456789876543210123456789876543210123456789876543210.123456789876543210123456789876543210123456789876543210.123456789876543210123456789876543210123456789876543215-beta.3"},
        {0, "123456789876543210123456789876543210123456789876543210.123456789876543210123456789876543210123456789876543210.123456789876543210123456789876543210123456789876543215-rc.1"},
        {0, "123456789876543210123456789876543210123456789876543210.123456789876543210123456789876543210123456789876543210.123456789876543210123456789876543210123456789876543215-rc.2"},
        {0, "123456789876543210123456789876543210123456789876543210.123456789876543210123456789876543210123456789876543210.123456789876543210123456789876543210123456789876543215-rc.3"},
        {0, "123456789876543210123456789876543210123456789876543210.123456789876543210123456789876543210123456789876543210.123456789876543210123456789876543210123456789876543215"},
    };
};

TEST(TestSemanticVersion, Test)
{
    // Check is sorted.
    const size_t count = sizeof(sorted_valid_versions) / sizeof(sorted_valid_versions[0]);
    for (size_t i = 0; i < count; i++)
    {
        auto& item = sorted_valid_versions[i];
        SemanticVersion item_sv{std::string(item.version)};

        EXPECT_TRUE(item_sv.isValid())
            << "Version string \""
            << item.version
            << "\" must be valid";

        EXPECT_TRUE(bool(item_sv))
            << "Operator bool() error: "
            << "Version string \""
            << item.version
            << "\" must be valid";

        for (size_t j = 0; j < count; j++)
        {
            auto& other = sorted_valid_versions[j];
            SemanticVersion other_sv{std::string(other.version)};

            auto res = other_sv.compare(item_sv);

            if (j != i)
            {
                if (item.group != 0 && item.group == other.group)
                {
                    EXPECT_EQ(res, SemanticVersion::Precedence::Equal)
                        << other.version
                        << " must be equal to "
                        << item.version;

                    EXPECT_TRUE(other_sv == item_sv)
                        << "Operator == error: "
                        << other.version
                        << " must be == to "
                        << item.version;

                    EXPECT_FALSE(other_sv != item_sv)
                        << "Operator != error: "
                        << other.version
                        << " must be not != to "
                        << item.version;

                    EXPECT_FALSE(other_sv > item_sv)
                        << "Operator > error: "
                        << other.version
                        << " must be not > then "
                        << item.version;

                    EXPECT_FALSE(other_sv < item_sv)
                        << "Operator < error: "
                        << other.version
                        << " must be not < then "
                        << item.version;
                }
                else
                {
                    EXPECT_NE(res, SemanticVersion::Precedence::Equal)
                        << other.version
                        << " must be not equal to "
                        << item.version;

                    EXPECT_TRUE(other_sv != item_sv)
                        << "Operator != error: "
                        << other.version
                        << " must be != to "
                        << item.version;
                }
            }

            if (j < i)
            {
                EXPECT_NE(res, SemanticVersion::Precedence::Greater)
                    << other.version
                    << " must be not greater then "
                    << item.version;

                EXPECT_TRUE(other_sv <= item_sv)
                    << "Operator <= error: "
                    << other.version
                    << " must be <= then "
                    << item.version;

                EXPECT_FALSE(other_sv > item_sv)
                    << "Operator > error: "
                    << other.version
                    << " must be not > then "
                    << item.version;
            }

            if (j == i)
            {
                EXPECT_EQ(res, SemanticVersion::Precedence::Equal)
                    << other.version
                    << " must be equal to self ("
                    << item.version
                    << ")";

                EXPECT_TRUE(other_sv == item_sv)
                    << "Operator == error: "
                    << other.version
                    << " must be == to "
                    << item.version;

                EXPECT_FALSE(other_sv != item_sv)
                    << "Operator != error: "
                    << other.version
                    << " must be not != to "
                    << item.version;

                EXPECT_FALSE(other_sv > item_sv)
                    << "Operator > error: "
                    << other.version
                    << " must be not > then "
                    << item.version;

                EXPECT_FALSE(other_sv < item_sv)
                    << "Operator < error: "
                    << other.version
                    << " must be not < then "
                    << item.version;
            }

            if (j > i)
            {
                EXPECT_NE(res, SemanticVersion::Precedence::Lower)
                    << other.version
                    << " must be not greater then "
                    << item.version;

                EXPECT_TRUE(other_sv >= item_sv)
                    << "Operator >= error: "
                    << other.version
                    << " must be >= then "
                    << item.version;

                EXPECT_FALSE(other_sv < item_sv)
                    << "Operator < error: "
                    << other.version
                    << " must be not < then "
                    << item.version;
            }
        }
    }

    // Check invalid SemVer detection.
    EXPECT_FALSE(SemanticVersion("").isValid());
    EXPECT_FALSE(SemanticVersion("0").isValid());
    EXPECT_FALSE(SemanticVersion("0.0").isValid());
    EXPECT_FALSE(SemanticVersion("0.0.0.").isValid());

    EXPECT_FALSE(SemanticVersion("-").isValid());
    EXPECT_FALSE(SemanticVersion("--").isValid());
    EXPECT_FALSE(SemanticVersion("---").isValid());
    EXPECT_FALSE(SemanticVersion(".").isValid());
    EXPECT_FALSE(SemanticVersion("..").isValid());
    EXPECT_FALSE(SemanticVersion("...").isValid());

    EXPECT_FALSE(SemanticVersion("0-ABC").isValid());
    EXPECT_FALSE(SemanticVersion("0.0-ABC").isValid());
    EXPECT_FALSE(SemanticVersion("0.0.0.-ABC").isValid());

    EXPECT_FALSE(SemanticVersion("0.0.0-").isValid());
    EXPECT_FALSE(SemanticVersion("10.0.0-").isValid());
    EXPECT_FALSE(SemanticVersion("11.0.2.").isValid());
    EXPECT_FALSE(SemanticVersion("11.0.2.0").isValid());
    EXPECT_FALSE(SemanticVersion("11.0.2.Q").isValid());
    EXPECT_FALSE(SemanticVersion("12.0.2-.").isValid());

    EXPECT_FALSE(SemanticVersion("A.0.0").isValid());
    EXPECT_FALSE(SemanticVersion("0.B.0").isValid());
    EXPECT_FALSE(SemanticVersion("0.0.C").isValid());

    EXPECT_FALSE(SemanticVersion("a.0.0").isValid());
    EXPECT_FALSE(SemanticVersion("0.b.0").isValid());
    EXPECT_FALSE(SemanticVersion("0.0.c").isValid());

    EXPECT_FALSE(SemanticVersion("a.b.c").isValid());
    EXPECT_FALSE(SemanticVersion("A.B.C").isValid());

    EXPECT_FALSE(SemanticVersion("9.9.9-9.09").isValid());
    EXPECT_FALSE(SemanticVersion("09.9.9-9.9").isValid());
    EXPECT_FALSE(SemanticVersion("9.09.9-9.9").isValid());
    EXPECT_FALSE(SemanticVersion("9.9.09-9.9").isValid());
    EXPECT_FALSE(SemanticVersion("9.9.9-09.9").isValid());

    EXPECT_FALSE(SemanticVersion("9.9.9-9.09.ABC").isValid());
    EXPECT_FALSE(SemanticVersion("09.9.9-9.9.ABC").isValid());
    EXPECT_FALSE(SemanticVersion("9.09.9-9.9.ABC").isValid());
    EXPECT_FALSE(SemanticVersion("9.9.09-9.9.ABC").isValid());
    EXPECT_FALSE(SemanticVersion("9.9.9-09.9.ABC").isValid());

    EXPECT_FALSE(SemanticVersion("12.345.6789-101112.013141516.ABCDEFGH").isValid());
    EXPECT_FALSE(SemanticVersion("012.345.6789-101112.13141516.ABCDEFGH").isValid());
    EXPECT_FALSE(SemanticVersion("12.0345.6789-101112.13141516.ABCDEFGH").isValid());
    EXPECT_FALSE(SemanticVersion("12.345.06789-101112.13141516.ABCDEFGH").isValid());
    EXPECT_FALSE(SemanticVersion("12.345.6789-0101112.13141516.ABCDEFGH").isValid());

    EXPECT_FALSE(SemanticVersion("9.9.9-9.9.").isValid());
    EXPECT_FALSE(SemanticVersion("9.9.9-A.9.").isValid());
    EXPECT_FALSE(SemanticVersion("9.9.9-A.B.").isValid());

    EXPECT_FALSE(SemanticVersion("987.654.321-123.456.").isValid());
    EXPECT_FALSE(SemanticVersion("987.654.321-ABC.456.").isValid());
    EXPECT_FALSE(SemanticVersion("987.654.321-123.ABC.").isValid());
    EXPECT_FALSE(SemanticVersion("987.654.321-ABC.DEF.").isValid());

    EXPECT_FALSE(SemanticVersion("9.9.9-9.9..").isValid());
    EXPECT_FALSE(SemanticVersion("9.9.9-A.9..").isValid());
    EXPECT_FALSE(SemanticVersion("9.9.9-A.B..").isValid());

    EXPECT_FALSE(SemanticVersion("987.654.321-123.456..").isValid());
    EXPECT_FALSE(SemanticVersion("987.654.321-ABC.456..").isValid());
    EXPECT_FALSE(SemanticVersion("987.654.321-123.ABC..").isValid());
    EXPECT_FALSE(SemanticVersion("987.654.321-ABC.DEF..").isValid());

    EXPECT_FALSE(SemanticVersion("9.9..9-9.9").isValid());
    EXPECT_FALSE(SemanticVersion("9.9..9-A.9").isValid());
    EXPECT_FALSE(SemanticVersion("9.9..9-A.B").isValid());

    EXPECT_FALSE(SemanticVersion("987.654..321-123.456").isValid());
    EXPECT_FALSE(SemanticVersion("987..654.321-ABC.456").isValid());
    EXPECT_FALSE(SemanticVersion("987.654.321-123..ABC").isValid());

    EXPECT_FALSE(SemanticVersion("987.654-321-123.456").isValid());
    EXPECT_FALSE(SemanticVersion("987.654..321-ABC.456").isValid());
    EXPECT_FALSE(SemanticVersion("987.654..321-123.ABC").isValid());
    EXPECT_FALSE(SemanticVersion("987.654..321-ABC.DEF").isValid());

    EXPECT_FALSE(SemanticVersion("sdvrbgtynhdftyhnfghbfghdftumufghundyudbudftghfbghfdtgh").isValid());
    EXPECT_FALSE(SemanticVersion("bdtybsntynfydftbyxfbyhjklghfikmfyudd").isValid());
    EXPECT_FALSE(SemanticVersion("987.sbrtytmyftybsdfysdrtyntydrtfybvsryaeryneryrty").isValid());
    EXPECT_FALSE(SemanticVersion("987.654.vretbrtymtutynioluikfyumidtyntyud").isValid());
}
