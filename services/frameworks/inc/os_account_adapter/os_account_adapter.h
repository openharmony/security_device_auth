/*
 * Copyright (C) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef OS_ACCOUNT_ADAPTER_H
#define OS_ACCOUNT_ADAPTER_H

#include <stdint.h>
#include "hc_vector.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    GROUP_DATA_CALLBACK = 0,
    ASY_TOKEN_DATA_CALLBACK,
    SYM_TOKEN_DATA_CALLBACK,
    PSEUDONYM_DATA_CALLBACK
} EventCallbackId;

typedef void (*OnOsAccountUnlockedFunc)(int32_t osAccountId);
typedef void (*OnOsAccountRemovedFunc)(int32_t osAccountId);
typedef void (*LoadDataIfNotLoadedFunc)(int32_t osAccountId);

typedef struct {
    EventCallbackId callbackId;
    OnOsAccountUnlockedFunc onOsAccountUnlocked;
    OnOsAccountRemovedFunc onOsAccountRemoved;
    LoadDataIfNotLoadedFunc loadDataIfNotLoaded;
} OsAccountEventCallback;
DECLARE_HC_VECTOR(EventCallbackVec, OsAccountEventCallback*)

int32_t AddOsAccountEventCallback(OsAccountEventCallback *callback);
OsAccountEventCallback *RemoveOsAccountEventCallback(EventCallbackId callbackId);
bool IsOsAccountUnlocked(int32_t osAccountId);
bool CheckOsAccountStatus(int32_t osAccountId);
int32_t GetCurrentActiveOsAccountId(void);
int32_t DevAuthGetRealOsAccountLocalId(int32_t inputId);

#ifdef SUPPORT_OS_ACCOUNT
void InitOsAccountAdapter(void);
void DestroyOsAccountAdapter(void);
#define INIT_OS_ACCOUNT_ADAPTER() InitOsAccountAdapter()
#define DESTROY_OS_ACCOUNT_ADAPTER() DestroyOsAccountAdapter()
void LoadAllAccountsData(void);
#else
#define INIT_OS_ACCOUNT_ADAPTER()
#define DESTROY_OS_ACCOUNT_ADAPTER()
#endif

#ifdef __cplusplus
}
#endif
#endif
