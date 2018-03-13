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


#ifndef _JSON_OUTPUT_H
#define _JSON_OUTPUT_H

#include "transport.h"

class JsonOutputFormatter{
    FILE *file;

    const char *FormatType(const _LSMonitorMessageType message_type);
    double ComputeTime(const struct timespec *time);

public:
    explicit JsonOutputFormatter(FILE *file);
    void PrintMessage(_LSTransportMessage *message);
};

#endif  /* _JSON_OUTPUT_H */
