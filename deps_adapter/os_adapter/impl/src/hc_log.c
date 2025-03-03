/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "hc_log.h"

#include <inttypes.h>
#include "securec.h"
#include "hc_types.h"

static __thread int32_t g_logMode = 0;
static __thread int64_t g_traceId = 0;

void SetLogMode(LogMode mode)
{
    g_logMode = mode;
    g_traceId = 0;
}

void SetTraceId(int64_t traceId)
{
    g_traceId = traceId;
}
