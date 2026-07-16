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
    PSEUDONYM_DATA_CALLBACK,
    CRED_DATA_CALLBACK
} EventCallbackId;

typedef void (*OsAccountCallbackFunc)(int32_t osAccountId);

#ifdef DEVAUTH_ENABLE_OS_ACCOUNT_MULTI_PROFILE
typedef enum {
    GROUP_RELATION_ACTIVE = 0,
    GROUP_RELATION_INACTIVE,
    DEVICE_RELATION_ACTIVE,
    DEVICE_RELATION_INACTIVE
} GroupRelationChangeType;

typedef enum {
    CRED_RELATION_ACTIVE = 0,
    CRED_RELATION_INACTIVE
} CredRelationChangeType;

typedef void (*GroupRelationChangeCallback)(GroupRelationChangeType type, int32_t osAccountId,
    const char *subProfileIdStr, const char *groupId, const char *udid);

typedef void (*CredRelationChangeCallback)(CredRelationChangeType type, int32_t osAccountId,
    const char *subProfileIdStr, const char *credId);

typedef void (*ProfileDeleteCallback)(int32_t osAccountId, const char *subProfileIdStr);

typedef void (*ProfileSwitchStartCallback)(void);

typedef void (*ProfileSwitchedCallback)(int32_t osAccountId, const char *subProfileIdStr);
#endif

void NotifyOsAccountUnlocked(int32_t osAccountId);
void NotifyOsAccountRemoved(int32_t osAccountId);
void AddOsAccountEventCallback(EventCallbackId callbackId, OsAccountCallbackFunc unlockFunc,
    OsAccountCallbackFunc removeFunc);
void RemoveOsAccountEventCallback(EventCallbackId callbackId);
bool IsOsAccountUnlocked(int32_t osAccountId);
int32_t DevAuthGetRealOsAccountLocalId(int32_t inputId);
bool CheckIsForegroundOsAccountId(int32_t osAccountId);
void InitOsAccountAdapter(void);
void DestroyOsAccountAdapter(void);
int32_t GetAllOsAccountIds(int32_t **osAccountIds, uint32_t *size);
bool IsOsAccountSupported(void);
int32_t GetCurrentActiveOsAccountId(void);

#ifdef DEVAUTH_ENABLE_OS_ACCOUNT_MULTI_PROFILE
int32_t GetForegroundSubProfileIdStr(int32_t osAccountId, char *subProfileIdStr, uint32_t subProfileIdStrLen);
void SetProfileDeleteCallbackForGroup(ProfileDeleteCallback callback);
void SetProfileDeleteCallbackForCred(ProfileDeleteCallback callback);
void SetProfileSwitchStartCallbackForGroup(ProfileSwitchStartCallback callback);
void SetProfileSwitchedCallbackForGroup(ProfileSwitchedCallback callback);
void SetGroupRelationChangeCallback(GroupRelationChangeCallback callback);
void SetCredRelationChangeCallback(CredRelationChangeCallback callback);
#endif

#ifdef __cplusplus
}
#endif
#endif
