/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#ifndef GROUP_DATA_MANAGER_UTIL_H
#define GROUP_DATA_MANAGER_UTIL_H

#include "group_data_manager.h"

#ifdef __cplusplus
extern "C" {
#endif

int32_t GenerateReturnGroupInfo(const TrustedGroupEntry *groupEntry, CJson *returnJson);
int32_t GenerateReturnDevInfo(const TrustedDeviceEntry *deviceEntry, CJson *returnJson);
int32_t GenerateMessage(int32_t osAccountId, const char *subProfileIdStr, const TrustedGroupEntry *groupEntry,
    char **returnMessage);
bool IsSelfDeviceEntry(const TrustedDeviceEntry *deviceEntry);
void RecordAddTrustDeviceEvent(int32_t osAccountId, const TrustedDeviceEntry *deviceEntry);

#ifdef DEV_AUTH_HIVIEW_ENABLE
void DumpGroupsAndDevices(int fd, int32_t osAccountId, const GroupEntryVec *groups, const DeviceEntryVec *devices);
#endif

#ifdef DEVAUTH_ENABLE_OS_ACCOUNT_MULTI_PROFILE
bool IsSelfDeviceExistInGroup(int32_t osAccountId, const char *groupId);
bool IsSelfDeviceExistInGroupForUser(int32_t osAccountId, const char *subProfileIdStr, const char *groupId);
#endif

#ifdef __cplusplus
}
#endif
#endif
