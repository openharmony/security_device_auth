/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef HISYSEVENT_COMMON_H
#define HISYSEVENT_COMMON_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "hisysevent_adapter.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PEER_OCCUR_ERROR 12
#define ACCOUNT_NOT_LOGIN 36875
#define ACCOUNT_LOGINED_NOT_SAME_AS_PEER 36876

#ifdef DEV_AUTH_HIVIEW_ENABLE
DevAuthBizScene GetBizScene(bool isBind, bool isClient);
void BuildStageRes(DevAuthBehaviorEvent *eventData, int32_t errorCode);
#endif

const char *GetAddMemberCallEventFuncName(const char *addParams);

void ReportBehaviorBeginEvent(bool isBind, bool isClient, int64_t reqId);
void ReportBehaviorBeginResultEvent(bool isBind, bool isClient, int64_t reqId, const char *peerUdid, int32_t res);
void ReportRadarEvent(int32_t res);

#ifdef __cplusplus
}
#endif
#endif
