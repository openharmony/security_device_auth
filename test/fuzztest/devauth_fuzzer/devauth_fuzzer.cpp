/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "devauth_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "access_token.h"
#include "accesstoken_kit.h"
#include "access_token_error.h"
#include "hc_log.h"
#include "ipc_adapt.h"
#include "ipc_callback_stub.h"
#include "ipc_dev_auth_stub.h"
#include "ipc_sdk.h"
#include "ipc_service.h"
#include "message_parcel.h"
#include "nativetoken_kit.h"
#include "securec.h"
#include "token_setproc.h"

namespace OHOS {
const std::u16string DEV_AUTH_SERVICE_INTERFACE_TOKEN = u"deviceauth.IMethodsIpcCall";

static void NativeTokenSet(const char *procName)
{
    const char *acls[] = {"ACCESS_IDS"};
    const char *perms[] = {
        "ohos.permission.PLACE_CALL",
        "ohos.permission.ACCESS_IDS"
    };
    uint64_t tokenId;
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 2,
        .aclsNum = 1,
        .dcaps = NULL,
        .perms = perms,
        .acls = acls,
        .processName = procName,
        .aplStr = "system_core",
    };
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}

bool FuzzDoRegCallback(const uint8_t* data, size_t size)
{
    (void)InitDeviceAuthService();
    (void)MainRescInit();
    ServiceDevAuth *serviceObj = new(std::nothrow) ServiceDevAuth();
    if (serviceObj == nullptr) {
        return false;
    }
    sptr<ServiceDevAuth> sptrObj = serviceObj;
    uintptr_t serviceCtx = reinterpret_cast<uintptr_t>(serviceObj);
    (void)AddMethodMap(serviceCtx);
    for (int32_t i = IPC_CALL_ID_REG_CB; i <= IPC_CALL_ID_GET_PSEUDONYM_ID; i++) {
        if (i == IPC_CALL_ID_AUTH_DEVICE || i == IPC_CALL_ID_GA_PROC_DATA || i == IPC_CALL_GA_CANCEL_REQUEST) {
            NativeTokenSet("softbus_server");
        } else if (i == IPC_CALL_ID_GET_PK_INFO_LIST) {
            NativeTokenSet("dslm_service");
        } else {
            NativeTokenSet("device_manager");
        }
        MessageParcel datas;
        datas.WriteInterfaceToken(DEV_AUTH_SERVICE_INTERFACE_TOKEN);
        datas.WriteInt32(i);
        datas.WriteInt32(size + sizeof(int32_t));
        datas.WriteInt32(0);
        datas.WriteInt32(size);
        datas.WriteBuffer(data, size);
        datas.RewindRead(0);
        MessageParcel reply;
        MessageOption option;
        (void)serviceObj->OnRemoteRequest(1, datas, reply, option);
    }
    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::FuzzDoRegCallback(data, size);
    return 0;
}

