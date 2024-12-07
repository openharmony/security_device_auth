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

#include "hc_mutex.h"

#include "hc_log.h"

#ifdef __cplusplus
extern "C" {
#endif

static int HcMutexLock(HcMutex *mutex)
{
    if (mutex == NULL) {
        return -1;
    }
    int res = 0;
    if (mutex->isReentrant) {
        pthread_t currThread = pthread_self();
        if (mutex->owner == currThread) {
            mutex->count++;
            return 0;
        }
        res = pthread_mutex_lock(&mutex->mutex);
        mutex->owner = currThread;
        mutex->count = 1;
    } else {
        res = pthread_mutex_lock(&mutex->mutex);
    }
    if (res != 0) {
        LOGW("[OS]: pthread_mutex_lock fail. [Res]: %d", res);
    }
    return res;
}

static void HcMutexUnlock(HcMutex *mutex)
{
    if (mutex == NULL) {
        return;
    }
    int res = 0;
    if (mutex->isReentrant) {
        pthread_t currThread = pthread_self();
        if (mutex->owner != currThread) {
            LOGE("[OS]: HcMutexUnlock fail. Not owner.");
            return;
        }
        mutex->count--;
        if (mutex->count == 0) {
            mutex->owner = 0;
            res = pthread_mutex_unlock(&mutex->mutex);
        }
    } else {
        res = pthread_mutex_unlock(&mutex->mutex);
    }
    if (res != 0) {
        LOGW("[OS]: pthread_mutex_unlock fail. [Res]: %d", res);
    }
}

int32_t InitHcMutex(struct HcMutexT *mutex, bool isReentrant)
{
    if (mutex == NULL) {
        return -1;
    }
    int res = pthread_mutex_init(&mutex->mutex, NULL);
    if (res != 0) {
        LOGE("[OS]: pthread_mutex_init fail. [Res]: %d", res);
        return res;
    }
    mutex->lock = HcMutexLock;
    mutex->unlock = HcMutexUnlock;
    mutex->owner = 0;
    mutex->count = 0;
    mutex->isReentrant = isReentrant;
    return 0;
}

void DestroyHcMutex(struct HcMutexT *mutex)
{
    if (mutex == NULL) {
        return;
    }
    mutex->owner = 0;
    mutex->count = 0;
    mutex->isReentrant = false;
    int res = pthread_mutex_destroy(&mutex->mutex);
    if (res != 0) {
        LOGW("[OS]: pthread_mutex_destroy fail. [Res]: %d", res);
    }
}

int LockHcMutex(HcMutex* mutex)
{
    if (mutex == NULL) {
        LOGE("[OS]: mutex is null pointer!");
        return -1;
    }
    return mutex->lock(mutex);
}

void UnlockHcMutex(HcMutex* mutex)
{
    if (mutex == NULL) {
        LOGE("[OS]: mutex is null pointer!");
        return;
    }
    mutex->unlock(mutex);
}

#ifdef __cplusplus
}
#endif