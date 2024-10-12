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

int32_t InitHcMutex(HcMutex *mutex)
{
    if (mutex == NULL) {
        return -1;
    }
    int res = pthread_mutex_init(mutex, NULL);
    if (res != 0) {
        LOGE("[OS]: pthread_mutex_init fail. [Res]: %d", res);
        return res;
    }
    return HC_SUCCESS;
}

void DestroyHcMutex(HcMutex *mutex)
{
    if (mutex == NULL) {
        return;
    }
    int res = pthread_mutex_destroy(mutex);
    if (res != 0) {
        LOGW("[OS]: pthread_mutex_destroy fail. [Res]: %d", res);
    }
}

void LockHcMutex(HcMutex* mutex)
{
    if (mutex == NULL) {
        LOGE("[OS]: mutex is null pointer!");
    }
    int res = pthread_mutex_lock(mutex);
    if (res != 0) {
        LOGW("[OS]: pthread_mutex_lock fail. [Res]: %d", res);
    }
}

void UnlockHcMutex(HcMutex* mutex)
{
    if (mutex == NULL) {
        LOGE("[OS]: mutex is null pointer!");
    }
    int res = pthread_mutex_unlock(mutex);
    if (res != 0) {
        LOGW("[OS]: pthread_mutex_unlock fail. [Res]: %d", res);
    }
}

#ifdef __cplusplus
}
#endif