/*
 * Copyright (C) 2021-2022 Huawei Device Co., Ltd.
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

#ifndef DEV_AUTH_MODULE_MANAGER_H
#define DEV_AUTH_MODULE_MANAGER_H

#include "json_utils.h"
#include "string_util.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct AuthModuleBaseT {
    int moduleType;
    int32_t (*init)(void);
    void (*destroy)(void);
    bool (*isMsgNeedIgnore)(const CJson *in);
    int (*createTask)(int32_t *, const CJson *in, CJson *out);
    int (*processTask)(int32_t, const CJson *in, CJson *out, int32_t *status);
    void (*destroyTask)(int);
} AuthModuleBase;

typedef struct {
    int32_t osAccountId;
    const char *pkgName;
    const char *serviceType;
    Uint8Buff *authId;
    int userType;
} AuthModuleParams;

int32_t InitModules(void);
void DestroyModules(void);

int32_t AddAuthModulePlugin(const AuthModuleBase *plugin);
void DelAuthModulePlugin(int32_t moduleType);

int32_t CreateTask(int32_t *taskId, const CJson *in, CJson *out, int moduleType);
int32_t ProcessTask(int taskId, const CJson *in, CJson *out, int32_t *status, int moduleType);
void DestroyTask(int taskId, int moduleType);
int32_t CheckMsgRepeatability(const CJson *in, int moduleType);

// for DAS
int32_t RegisterLocalIdentity(const AuthModuleParams *moduleParams, int moduleType);
int32_t UnregisterLocalIdentity(const AuthModuleParams *moduleParams, int moduleType);
int32_t DeletePeerAuthInfo(const AuthModuleParams *moduleParams, int moduleType);
int32_t GetPublicKey(int moduleType, AuthModuleParams *moduleParams, Uint8Buff *returnPk);

#ifdef __cplusplus
}
#endif
#endif
