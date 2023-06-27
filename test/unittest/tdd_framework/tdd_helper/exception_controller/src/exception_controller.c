/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "exception_controller.h"

#include <securec.h>
#include "hc_mutex.h"

static volatile bool g_isInit = false;
static volatile bool g_isNeedThrowException = false;
static uint32_t g_throwExceptionIndex = UINT32_MAX;
static uint32_t g_callNum = 0;
static HcMutex *g_mutex = NULL;

bool IsNeedThrowException(void)
{
    if (!g_isInit) {
        return false;
    }
    if (!g_isNeedThrowException) {
        return false;
    }
    bool result = (g_callNum == g_throwExceptionIndex);
    if (result) {
        printf("throw exception.\n");
    }
    return result;
}

uint32_t GetCallNum(void)
{
    if (!g_isInit) {
        return 0;
    }
    if (!g_isNeedThrowException) {
        return 0;
    }
    return g_callNum;
}

void AddCallNum(void)
{
    if (!g_isInit) {
        return;
    }
    if (!g_isNeedThrowException) {
        return;
    }
    g_mutex->lock(g_mutex);
    g_callNum += 1;
    g_mutex->unlock(g_mutex);
}

void SetControllerMode(bool isNeedThrowException)
{
    if (!g_isInit) {
        return;
    }
    g_isNeedThrowException = isNeedThrowException;
}

void SetThrowExceptionIndex(uint32_t index)
{
    if (!g_isInit) {
        return;
    }
    if (!g_isNeedThrowException) {
        return;
    }
    g_mutex->lock(g_mutex);
    g_callNum = 0;
    g_throwExceptionIndex = index;
    g_mutex->unlock(g_mutex);
}

void InitExceptionController(void)
{
    if (g_isInit) {
        return;
    }
    g_isInit = true;
    g_isNeedThrowException = false;
    g_throwExceptionIndex = UINT32_MAX;
    g_callNum = 0;
    g_mutex = (HcMutex *)malloc(sizeof(HcMutex));
    InitHcMutex(g_mutex);
}

void DestroyExceptionController(void)
{
    if (!g_isInit) {
        return;
    }
    g_isInit = false;
    g_mutex->lock(g_mutex);
    g_isNeedThrowException = false;
    g_throwExceptionIndex = UINT32_MAX;
    g_callNum = 0;
    g_mutex->unlock(g_mutex);
    DestroyHcMutex(g_mutex);
    free(g_mutex);
    g_mutex = NULL;
}