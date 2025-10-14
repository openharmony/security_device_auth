/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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


#include "critical_handler.h"
#include "mem_mgr_client.h"
#include "mem_mgr_proxy.h"
#include "hc_log.h"
#include <system_ability_definition.h>

static int32_t g_count = 0;
static bool g_saIsStopping = false;
static std::mutex g_criticalLock;

void NotifyProcessIsActive(void)
{
    LOGI("start to notify memmgr sa active.");
    OHOS::Memory::MemMgrClient::GetInstance().NotifyProcessStatus(getpid(), 1, 1, OHOS::DEVICE_AUTH_SERVICE_ID);
}

void NotifyProcessIsStop(void)
{
    LOGI("start to notify memmgr sa stop.");
    OHOS::Memory::MemMgrClient::GetInstance().NotifyProcessStatus(getpid(), 1, 0, OHOS::DEVICE_AUTH_SERVICE_ID);
}

void IncreaseCriticalCnt(int addCnt)
{
    std::lock_guard<std::mutex> autoLock(g_criticalLock);
    if (g_count == 0) {
        LOGI("Try to set critical to true.");
        OHOS::Memory::MemMgrClient::GetInstance().SetCritical(getpid(), true, OHOS::DEVICE_AUTH_SERVICE_ID);
    }
    g_count = g_count + addCnt;
}

void DecreaseCriticalCnt(void)
{
    std::lock_guard<std::mutex> autoLock(g_criticalLock);
    g_count = g_count - 1;
    if (g_count == 0) {
        LOGI("Try to set critical to false.");
        OHOS::Memory::MemMgrClient::GetInstance().SetCritical(getpid(), false, OHOS::DEVICE_AUTH_SERVICE_ID);
    }
}

int32_t GetCriticalCnt(void)
{
    std::lock_guard<std::mutex> autoLock(g_criticalLock);
    return g_count;
}

void SetStatusIsStopping(bool isStopping)
{
    std::lock_guard<std::mutex> autoLock(g_criticalLock);
    LOGI("Set status isStopping is %" LOG_PUB "d", isStopping);
    g_saIsStopping = isStopping;
}

bool CheckIsStopping(void)
{
    std::lock_guard<std::mutex> autoLock(g_criticalLock);
    return g_saIsStopping;
}