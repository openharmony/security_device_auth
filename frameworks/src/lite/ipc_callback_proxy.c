/*
 * Copyright (C) 2021-2024 Huawei Device Co., Ltd.
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

#include "ipc_callback_proxy.h"
#include "hc_log.h"
#include "hc_types.h"
#include "ipc_adapt.h"
#include "ipc_skeleton.h"
#include "securec.h"

#ifdef __cplusplus
extern "C" {
#endif

static void CbProxyFormReplyData(int32_t reqRetVal, IpcIo *replyDst, const IpcIo *replySrc)
{
    errno_t eno;

    if (reqRetVal != 0) {
        *(int32_t *)(replyDst->bufferCur) = reqRetVal;
        replyDst->bufferLeft = sizeof(int32_t);
        return;
    }

    LOGI("with reply data, length(%" LOG_PUB "zu), flag(%" LOG_PUB "u)", replySrc->bufferLeft, replySrc->flag);
    eno = memcpy_s(replyDst->bufferCur, replyDst->bufferLeft, replySrc->bufferCur, replySrc->bufferLeft);
    if (eno != EOK) {
        replyDst->flag = 0;
        LOGE("memory copy reply data failed");
        return;
    }
    replyDst->bufferLeft = replySrc->bufferLeft;
    LOGI("out reply data, length(%" LOG_PUB "zu)", replyDst->bufferLeft);
    return;
}

void CbProxySendRequest(SvcIdentity sid, int32_t callbackId, uintptr_t cbHook, IpcIo *data, IpcIo *reply)
{
    int32_t ret;
    IpcIo *reqData = NULL;
    int32_t dataSz;
    uintptr_t outMsg = 0x0;
    IpcIo replyTmp;

    ShowIpcSvcInfo(&(sid));
    reqData = (IpcIo *)InitIpcDataCache(IPC_DATA_BUFF_MAX_SZ);
    if (reqData == NULL) {
        return;
    }
    WriteInt32(reqData, callbackId);
    WritePointer(reqData, cbHook);
    dataSz = GetIpcIoDataLength((const IpcIo *)data);
    LOGI("to form callback params data length(%" LOG_PUB "d)", dataSz);
    if (dataSz > 0) {
        WriteUint32(reqData, dataSz);
        if (!WriteBuffer(reqData, data->bufferBase + IpcIoBufferOffset(), dataSz)) {
            HcFree((void *)reqData);
            return;
        }
    }
    /* callFlag: ipc mode is blocking or non blocking. */
    MessageOption option;
    MessageOptionInit(&option);
    option.flags = ((reply != NULL) ? TF_OP_SYNC : TF_OP_ASYNC);
    ret = SendRequest(sid, DEV_AUTH_CALLBACK_REQUEST, reqData, &replyTmp, option, &outMsg);
    LOGI("SendRequest(%" LOG_PUB "d) done, return(%" LOG_PUB "d)", option.flags, ret);
    HcFree((void *)reqData);
    if (reply == NULL) {
        return;
    }
    CbProxyFormReplyData(ret, reply, &replyTmp);
    FreeBuffer((void *)outMsg);
    return;
}

#ifdef __cplusplus
}
#endif
