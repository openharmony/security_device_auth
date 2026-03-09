/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdbool.h>
#include "hc_parcel_mock.h"

static bool g_hcMallocFail = false;
static bool g_memmoveFail = false;

void SetHcMallocFail(bool shouldFail)
{
    g_hcMallocFail = shouldFail;
}

bool GetHcMallocFail(void)
{
    return g_hcMallocFail;
}

void ResetHcMallocFail(void)
{
    g_hcMallocFail = false;
}

void SetMemmoveFail(bool shouldFail)
{
    g_memmoveFail = shouldFail;
}

bool GetMemmoveFail(void)
{
    return g_memmoveFail;
}

void ResetMemmoveFail(void)
{
    g_memmoveFail = false;
}
