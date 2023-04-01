/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef HISYSEVENT_ADAPTER_H
#define HISYSEVENT_ADAPTER_H

#ifndef HIVIEW_ENABLE

#define DEV_AUTH_REPORT_CALL_EVENT(a, b, c, d)
#define DEV_AUTH_REPORT_CORE_EVENT(a, b, c)

#else

#include <stdint.h>

#define CREATE_GROUP_EVENT "CreateGroup"
#define DELETE_GROUP_EVENT "DeleteGroup"
#define ADD_MEMBER_EVENT "AddMember"
#define DEL_MEMBER_EVENT "DelMember"
#define ADD_MULTI_MEMBER_EVENT "AddMultiMember"
#define DEL_MULTI_MEMBER_EVENT "DelMultiMember"
#define AUTH_DEV_EVENT "AuthDevice"

#define DEV_AUTH_REPORT_CALL_EVENT(a, b, c, d) DevAuthReportCallEvent(a, b, c, d)
#define DEV_AUTH_REPORT_CORE_EVENT(a, b, c) DevAuthReportCoreEvent(a, b, c)

#ifdef __cplusplus
extern "C" {
#endif

void DevAuthReportCallEvent(const char *funcName, int32_t osAccountId, int64_t reqId, const char *appId);
void DevAuthReportCoreEvent(const char *funcName, int64_t reqId, const char *info);

#ifdef __cplusplus
}
#endif

#endif

#endif
