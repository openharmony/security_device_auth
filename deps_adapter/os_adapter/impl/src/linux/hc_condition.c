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

#ifdef __cplusplus
extern "C" {
#endif

int Wait(pthread_cond_t* cond, HcMutex* mutex)
{
    if (cond == NULL || mutex == NULL) {
        return -1;
    }
    int res = pthread_cond_wait(cond, &mutex->mutex);
    if (res != 0) {
        LOGE("[OS]: pthread_cond_wait fail. [Res]: %" LOG_PUB "d", res);
    }
    return res;
}

void Notify(pthread_cond_t* cond)
{
    if (cond == NULL) {
        return;
    }
    int res = pthread_cond_signal(cond);
    if (res != 0) {
        LOGW("[OS]: pthread_cond_signal fail. [Res]: %" LOG_PUB "d", res);
    }
}

int HcCondWaitWithoutLock(struct HcConditionT* hcCond)
{
    if (hcCond == NULL || hcCond->mutex == NULL) {
        return -1;
    }
    if (hcCond->notified) {
        hcCond->notified = HC_FALSE;
        return 0;
    } else {
        int ret;
        hcCond->waited = HC_TRUE;
        ret = Wait(&hcCond->cond, hcCond->mutex);
        hcCond->waited = HC_FALSE;
        hcCond->notified = HC_FALSE;
        return ret;
    }
}

void HcCondNotifyWithoutLock(struct HcConditionT* hcCond)
{
    if (hcCond == NULL || hcCond->mutex == NULL) {
        return;
    }

    if (!hcCond->waited) {
        hcCond->notified = HC_TRUE;
    } else {
        hcCond->notified = HC_FALSE;
    }
    Notify(&hcCond->cond);
}

int HcCondWait(struct HcConditionT* hcCond)
{
    if (hcCond == NULL) {
        return -1;
    }
    if (hcCond->mutex == NULL) {
        return -1;
    }

    (void)LockHcMutex(hcCond->mutex);
    if (hcCond->notified) {
        hcCond->notified = HC_FALSE;
        UnlockHcMutex(hcCond->mutex);
        return 0;
    } else {
        int ret;
        hcCond->waited = HC_TRUE;
        ret = Wait(&hcCond->cond, hcCond->mutex);
        hcCond->waited = HC_FALSE;
        hcCond->notified = HC_FALSE;
        UnlockHcMutex(hcCond->mutex);
        return ret;
    }
}

void HcCondNotify(struct HcConditionT* hcCond)
{
    if (hcCond == NULL || hcCond->mutex == NULL) {
        return;
    }

    (void)LockHcMutex(hcCond->mutex);

    if (!hcCond->waited) {
        hcCond->notified = HC_TRUE;
    } else {
        hcCond->notified = HC_FALSE;
    }
    Notify(&hcCond->cond);
    UnlockHcMutex(hcCond->mutex);
}

int32_t InitHcCond(HcCondition* hcCond, HcMutex* mutex)
{
    if (hcCond == NULL) {
        return -1;
    }
    hcCond->notified = HC_FALSE;
    hcCond->waited = HC_FALSE;
    hcCond->wait = HcCondWait;
    hcCond->notify = HcCondNotify;
    hcCond->waitWithoutLock = HcCondWaitWithoutLock;
    hcCond->notifyWithoutLock = HcCondNotifyWithoutLock;

    pthread_condattr_t attr;
    pthread_condattr_init(&attr);
    int res = pthread_cond_init(&hcCond->cond, &attr);
    pthread_condattr_destroy(&attr);
    if (res != 0) {
        LOGE("[OS]: pthread_cond_init fail. [Res]: %" LOG_PUB "d", res);
        return -1;
    }

    if (mutex != NULL) {
        hcCond->mutex = mutex;
        hcCond->innerMutex = HC_FALSE;
    } else {
        hcCond->mutex = (HcMutex*)HcMalloc(sizeof(HcMutex), 0);
        if (hcCond->mutex != NULL) {
            res = InitHcMutex(hcCond->mutex, false);
            if (res != 0) {
                HcFree(hcCond->mutex);
                hcCond->mutex = NULL;
                return res;
            }
            hcCond->innerMutex = HC_TRUE;
        } else {
            return -1;
        }
    }
    return 0;
}

void DestroyHcCond(HcCondition* hcCond)
{
    if (hcCond == NULL) {
        return;
    }

    if (hcCond->innerMutex && hcCond->mutex) {
        DestroyHcMutex(hcCond->mutex);
        HcFree(hcCond->mutex);
        hcCond->mutex = NULL;
    }
    int res = pthread_cond_destroy(&hcCond->cond);
    if (res != 0) {
        LOGW("[OS]: pthread_cond_destroy fail. [Res]: %" LOG_PUB "d", res);
    }
}

#ifdef __cplusplus
}
#endif