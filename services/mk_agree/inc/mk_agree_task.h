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

#ifndef MK_AGREE_TASK_H
#define MK_AGREE_TASK_H

#include "alg_defs.h"
#include "json_utils.h"
#include "string_util.h"

#define MK_AGREE_MESSAGE_CODE "mkAgreeMsg"
#define SALT_LEN 16

typedef enum {
    TASK_TYPE_ISO = 0,
    TASK_TYPE_PAKE = 1,
} MkAgreeTaskType;

typedef enum {
    START_MK_AGREE_REQUEST,
    SEND_MK_AGREE_RESPONSE,
} MkAgreeMessageCode;

typedef enum {
    STATUS_INIT,
    STATUS_WAIT_MK_REQUEST,
    STATUS_WAIT_MK_RESPONSE,
    STATUS_FINISH,
} MkAgreeTaskStatus;

typedef struct MkAgreeTaskBaseT {
    void (*destroy)(struct MkAgreeTaskBaseT *);
    int32_t (*process)(struct MkAgreeTaskBaseT *, const CJson *in, CJson *out);
    MkAgreeTaskType taskType;
    MkAgreeTaskStatus taskStatus;
    int32_t osAccountId;
    char *peerInfo;
    char *pdidIndex;
    char *peerUdid;
    const AlgLoader *loader;
} MkAgreeTaskBase;

typedef struct {
    MkAgreeTaskBase taskBase;
} IsoMkAgreeTask;

typedef struct {
    MkAgreeTaskBase taskBase;
    uint8_t clientSalt[SALT_LEN];
    uint8_t serverSalt[SALT_LEN];
} PakeMkAgreeTask;

#ifdef __cplusplus
extern "C" {
#endif

int32_t CreateMkAgreeTask(int protocolType, const CJson *in, MkAgreeTaskBase **returnTask);

#ifdef __cplusplus
}
#endif
#endif
