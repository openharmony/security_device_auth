/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef TASK_MAIN_H
#define TASK_MAIN_H

#include "common_defs.h"
#include "hc_vector.h"
#include "json_utils.h"
#include "das_version_util.h"
#include "das_token_manager.h"

DECLARE_HC_VECTOR(SubTaskVec, void *)

typedef struct TaskT {
    int taskId;
    VersionInfo versionInfo;
    void(*destroyTask)(struct TaskT *);
    int(*processTask)(struct TaskT *, const CJson *in, CJson *out, int32_t *status);
    SubTaskVec vec;
} Task;

#ifdef __cplusplus
extern "C" {
#endif

Task *CreateTaskT(int32_t *taskId, const CJson *in, CJson *out);

int32_t InitDasProtocolEntities(void);
void DestroyDasProtocolEntities(void);

int32_t RegisterLocalIdentityInTask(const TokenManagerParams *params);
int32_t UnregisterLocalIdentityInTask(const TokenManagerParams *params);
int32_t DeletePeerAuthInfoInTask(const TokenManagerParams *params);
int32_t GetPublicKeyInTask(const TokenManagerParams *params, Uint8Buff *returnPk);

#ifdef __cplusplus
}
#endif
#endif
