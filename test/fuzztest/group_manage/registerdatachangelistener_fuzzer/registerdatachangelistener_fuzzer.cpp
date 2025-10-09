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

#include "registerdatachangelistener_fuzzer.h"

namespace OHOS {
    void OnGroupCreated(const char *groupInfo)
    {
        (void)groupInfo;
    }

    void OnGroupDeleted(const char *groupInfo)
    {
        (void)groupInfo;
    }

    void OnDeviceBound(const char *peerUdid, const char *groupInfo)
    {
        (void)peerUdid;
        (void)groupInfo;
    }

    void OnDeviceUnBound(const char *peerUdid, const char *groupInfo)
    {
        (void)peerUdid;
        (void)groupInfo;
    }

    void OnDeviceNotTrusted(const char *peerUdid)
    {
        (void)peerUdid;
    }

    void OnLastGroupDeleted(const char *peerUdid, int groupType)
    {
        (void)peerUdid;
        (void)groupType;
    }

    void OnTrustedDeviceNumChanged(int curTrustedDeviceNum)
    {
        (void)curTrustedDeviceNum;
    }

    bool FuzzDoRegDataChangeListener(const uint8_t* data, size_t size)
    {
        const DeviceGroupManager *gmInstance = GetGmInstance();
        if (gmInstance == nullptr) {
            return false;
        }
        if (data == nullptr) {
            return false;
        }
        std::string appId(reinterpret_cast<const char *>(data), size);
        DataChangeListener listener;
        listener.onGroupCreated = OnGroupCreated;
        listener.onGroupDeleted = OnGroupDeleted;
        listener.onDeviceBound = OnDeviceBound;
        listener.onDeviceUnBound = OnDeviceUnBound;
        listener.onDeviceNotTrusted = OnDeviceNotTrusted;
        listener.onLastGroupDeleted = OnLastGroupDeleted;
        listener.onTrustedDeviceNumChanged = OnTrustedDeviceNumChanged;
        gmInstance->regDataChangeListener(appId.c_str(), &listener);
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::FuzzDoRegDataChangeListener(data, size);
    return 0;
}

