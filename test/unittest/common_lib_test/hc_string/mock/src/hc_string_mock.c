/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include "hc_string_mock.h"

static bool g_shouldFail = false;
static bool g_getParcelDataSizeMockEnabled = false;
static uint32_t g_getParcelDataSizeMockValue = 0;

void SetParcelWriteInt8Mock(bool shouldFail)
{
    g_shouldFail = shouldFail;
}

bool GetParcelWriteInt8Mock(void)
{
    return g_shouldFail;
}

void SetGetParcelDataSizeMock(uint32_t mockSize)
{
    g_getParcelDataSizeMockEnabled = true;
    g_getParcelDataSizeMockValue = mockSize;
}

uint32_t GetGetParcelDataSizeMock(void)
{
    return g_getParcelDataSizeMockValue;
}

bool IsGetParcelDataSizeMockEnabled(void)
{
    return g_getParcelDataSizeMockEnabled;
}

void ResetGetParcelDataSizeMock(void)
{
    g_getParcelDataSizeMockEnabled = false;
    g_getParcelDataSizeMockValue = 0;
}
