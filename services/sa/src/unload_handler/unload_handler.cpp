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


#include "unload_handler.h"
#include "hc_log.h"
#include "event_runner.h"
#include "event_handler.h"
#include <system_ability_definition.h>
#include "iservice_registry.h"

static std::shared_ptr<OHOS::AppExecFwk::EventHandler> g_unloadHandler;
static const std::string DEVAUTH_UNLOAD_TASK_ID = "devauth_unload_task";
static const std::string DEVAUTH_UNLOAD_SA_HANDLER = "devauth_unload_sa_handler";
static const int32_t DEVAUTH_LIFE_TIME = 90000; // 90 * 1000
static std::mutex g_unloadMutex;

bool CreateUnloadHandler()
{
    std::lock_guard<std::mutex> autoLock(g_unloadMutex);
    if (g_unloadHandler != nullptr) {
        return true;
    }
    auto unloadRunner = OHOS::AppExecFwk::EventRunner::Create(DEVAUTH_UNLOAD_SA_HANDLER);
    if (unloadRunner == nullptr) {
        LOGE("Create unloadRunner failed.");
        return false;
    }
    g_unloadHandler = std::make_shared<OHOS::AppExecFwk::EventHandler>(unloadRunner);
    if (g_unloadHandler == nullptr) {
        LOGE("Create unloadHandler failed.");
        return false;
    }
    return true;
}

void DestroyUnloadHandler()
{
    std::lock_guard<std::mutex> autoLock(g_unloadMutex);
    if (g_unloadHandler == nullptr) {
        LOGE("unloadHandler is nullptr.");
        return;
    }
    g_unloadHandler->RemoveTask(DEVAUTH_UNLOAD_TASK_ID);
    g_unloadHandler = nullptr;
}

void DelayUnload()
{
    if (!CreateUnloadHandler()) {
        LOGE("UnloadHandler is nullptr.");
        return;
    }
    std::lock_guard<std::mutex> autoLock(g_unloadMutex);
    auto utask = []() {
        LOGI("The Service starts unloading.");
        auto saMgr = OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (saMgr == nullptr) {
            LOGE("Get systemabilitymanager instance failed.");
            return;
        }
        int32_t ret = saMgr->UnloadSystemAbility(OHOS::DEVICE_AUTH_SERVICE_ID);
        if (ret != OHOS::ERR_OK) {
            LOGE("Unload system ability failed.");
            return;
        }
        LOGI("Service unloaded successfully.");
    };
    g_unloadHandler->RemoveTask(DEVAUTH_UNLOAD_TASK_ID);
    g_unloadHandler->PostTask(utask, DEVAUTH_UNLOAD_TASK_ID, DEVAUTH_LIFE_TIME);
}
