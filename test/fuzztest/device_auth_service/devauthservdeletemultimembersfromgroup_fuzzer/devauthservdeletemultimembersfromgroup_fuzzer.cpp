/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "devauthservdeletemultimembersfromgroup_fuzzer.h"
#include "device_auth.h"
#include "device_auth_defines.h"
#include "hc_dev_info.h"
#include "hc_log.h"
#include "json_utils.h"
#include "securec.h"
#include <unistd.h>

namespace OHOS {
    static char g_groupId[128] = { 0 };

    static void OnError(int64_t requestId, int operationCode, int errorCode, const char *errorReturn)
    {
        LOGE("error return: %" LOG_PUB "s", errorReturn);
    }

    static void OnFinish(int64_t requestId, int operationCode, const char *authReturn)
    {
        LOGI("return value: %" LOG_PUB "s", authReturn);
        if (operationCode == GROUP_CREATE) {
            CJson *json = CreateJsonFromString(authReturn);
            if (json != nullptr) {
                const char *data = GetStringFromJson(json, FIELD_GROUP_ID);
                if (data != nullptr) {
                    (void)memcpy_s(g_groupId, sizeof(g_groupId), data, strlen(data));
                    g_groupId[strlen(data)] = 0;
                }
                FreeJson(json);
            }
        }
    }

    static void OnSessionKeyReturned(int64_t requestId, const uint8_t *sessionKey, uint32_t sessionKeyLen) {}

    static bool OnTransmit(int64_t requestId, const uint8_t *data, uint32_t dataLen)
    {
        return true;
    }

    static char *OnRequest(int64_t requestId, int operationCode, const char* reqParam)
    {
        return nullptr;
    }

    static DeviceAuthCallback g_gmCallback = {
        .onTransmit = OnTransmit,
        .onSessionKeyReturned = OnSessionKeyReturned,
        .onFinish = OnFinish,
        .onError = OnError,
        .onRequest = OnRequest,
    };

    static void GenerateDeleteMultiMembersParamsJson(CJson *json, const char *deleteId)
    {
        AddStringToJson(json, FIELD_GROUP_ID, g_groupId);
        AddStringToJson(json, FIELD_DELETE_ID, deleteId);
        AddBoolToJson(json, FIELD_IS_FORCE_DELETE, true);
        AddBoolToJson(json, FIELD_IS_IGNORE_CHANNEL, true);
    }

    bool FuzzDoDeleteMultiMembersFromGroup(const uint8_t* data, size_t size)
    {
        if (data == nullptr) {
            return false;
        }
        InitDeviceAuthService();
        std::string appId(reinterpret_cast<const char *>(data), size);
        const DeviceGroupManager *gmInstance = GetGmInstance();
        gmInstance->regCallback(appId.c_str(), &g_gmCallback);
        CJson *createJson = CreateJson();
        AddStringToJson(createJson, FIELD_GROUP_NAME, appId.c_str());
        char localUdid[INPUT_UDID_LEN] = { 0 };
        HcGetUdid(reinterpret_cast<uint8_t *>(localUdid), INPUT_UDID_LEN);
        AddStringToJson(createJson, FIELD_DEVICE_ID, localUdid);
        AddIntToJson(createJson, FIELD_GROUP_TYPE, PEER_TO_PEER_GROUP);
        char *createParams = PackJsonToString(createJson);
        FreeJson(createJson);
        int64_t reqId = 123;
        gmInstance->createGroup(0, reqId, appId.c_str(), createParams);
        sleep(1);
        ClearAndFreeJsonString(createParams);
        std::string deleteId(reinterpret_cast<const char *>(data), size);
        CJson *deleteMultiMembersJson = CreateJson();
        GenerateDeleteMultiMembersParamsJson(deleteMultiMembersJson, deleteId.c_str());
        char *deleteMultiMembersParams = PackJsonToString(deleteMultiMembersJson);
        FreeJson(deleteMultiMembersJson);
        LOGI("delete multi members params str:%" LOG_PUB "s", deleteMultiMembersParams);
        gmInstance->delMultiMembersFromGroup(0, appId.c_str(), deleteMultiMembersParams);
        sleep(1);
        ClearAndFreeJsonString(deleteMultiMembersParams);
        DestroyDeviceAuthService();
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::FuzzDoDeleteMultiMembersFromGroup(data, size);
    return 0;
}

