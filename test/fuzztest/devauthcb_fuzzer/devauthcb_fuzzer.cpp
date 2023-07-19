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

#include "devauthcb_fuzzer.h"

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
const std::u16string DEV_AUTH_CB_INTERFACE_TOKEN = u"deviceauth.ICommIpcCallback";

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

bool FuzzDoCallback(const uint8_t* data, size_t size)
{
    NativeTokenSet("device_manager");
    StubDevAuthCb *remoteObj = new(std::nothrow) StubDevAuthCb();
    if (remoteObj == nullptr) {
        return false;
    }
    sptr<StubDevAuthCb> remoteSptr = remoteObj;
    MessageParcel datas;
    datas.WriteInterfaceToken(DEV_AUTH_CB_INTERFACE_TOKEN);
    datas.WriteInt32(0);
    datas.WritePointer(0x0);
    datas.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    (void)remoteObj->OnRemoteRequest(1, datas, reply, option);
    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::FuzzDoCallback(data, size);
    return 0;
}

