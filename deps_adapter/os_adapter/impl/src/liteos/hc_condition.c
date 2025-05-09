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

#include "hc_condition.h"

#include "hc_log.h"

int HcCondWait(struct HcConditionT* hcCond)
{
    if (hcCond == NULL) {
        return -1;
    }

    int res = sem_wait(&hcCond->sem);
    if (res != 0) {
        LOGE("[OS]: sem_wait fail. [Res]: %" LOG_PUB "d", res);
    }
    return res;
}

void HcCondNotify(struct HcConditionT* hcCond)
{
    if (hcCond == NULL) {
        return;
    }

    int res = sem_post(&hcCond->sem);
    if (res != 0) {
        LOGW("[OS]: sem_post fail. [Res]: %" LOG_PUB "d", res);
    }
}

int32_t InitHcCond(HcCondition* hcCond, HcMutex* mutex)
{
    (void)mutex;
    if (hcCond == NULL) {
        return -1;
    }
    hcCond->wait = HcCondWait;
    hcCond->notify = HcCondNotify;
    hcCond->waitWithoutLock = HcCondWait;
    hcCond->notifyWithoutLock = HcCondNotify;

    // init the signal value to zero
    int res = sem_init(&hcCond->sem, 0, 0);
    if (res != 0) {
        LOGE("[OS]: sem_init fail. [Res]: %" LOG_PUB "d", res);
    }
    return res;
}

void DestroyHcCond(HcCondition* hcCond)
{
    if (hcCond == NULL) {
        return;
    }

    int res = sem_destroy(&hcCond->sem);
    if (res != 0) {
        LOGW("[OS]: sem_destroy fail. [Res]: %" LOG_PUB "d", res);
    }
}