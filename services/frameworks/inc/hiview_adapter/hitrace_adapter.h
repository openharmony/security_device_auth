/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef HITRACE_ADAPTER_H
#define HITRACE_ADAPTER_H

#define TRACE_TAG_CALL_ADD_MEMBER "CallAddMember"
#define TRACE_TAG_CALL_AUTH_DEVICE "CallAuthDevice"
#define TRACE_TAG_CALL_PROCESS_BIND_DATA "CallProcessBindData"
#define TRACE_TAG_CALL_PROCESS_AUTH_DATA "CallProcessAuthData"
#define TRACE_TAG_PROC_ADD_MEMBER_WORK_TASK "ProcAddMemberWorkTask"
#define TRACE_TAG_PROC_BIND_DATA_WORK_TASK "ProcBindDataWorkTask"
#define TRACE_TAG_PROC_AUTH_DEVICE_WORK_TASK "ProcAuthDeviceWorkTask"
#define TRACE_TAG_PROC_AUTH_DATA_WORK_TASK "ProcAuthDataWorkTask"
#define TRACE_TAG_CREATE_SESSION "CreateSession"
#define TRACE_TAG_PROCESS_SESSION "ProcessSession"
#define TRACE_TAG_ON_SESSION_FINISH "OnSessionFinish"
#define TRACE_TAG_CREATE_KEY_PAIR "CreateKeyPair"
#define TRACE_TAG_OPEN_CHANNEL "OpenChannel"
#define TRACE_TAG_CHANNEL_OPENED "ChannelOpened"
#define TRACE_TAG_SEND_DATA "SendData"
#define TRACE_TAG_CREATE_AUTH_TASK "CreateAuthTask"
#define TRACE_TAG_PROCESS_AUTH_TASK "ProcessAuthTask"
#define TRACE_TAG_ON_REQUEST "OnRequest"
#define TRACE_TAG_ADD_TRUSTED_DEVICE "AddTrustedDevice"

#ifndef DEV_AUTH_HIVIEW_ENABLE

#define DEV_AUTH_START_TRACE(tag)
#define DEV_AUTH_FINISH_TRACE()

#else

#include <stdint.h>

#define DEV_AUTH_START_TRACE(tag) DevAuthStartTrace(tag)
#define DEV_AUTH_FINISH_TRACE() DevAuthFinishTrace()

#ifdef __cplusplus
extern "C" {
#endif

void DevAuthStartTrace(const char *value);

void DevAuthFinishTrace(void);

#ifdef __cplusplus
}
#endif

#endif

#endif
