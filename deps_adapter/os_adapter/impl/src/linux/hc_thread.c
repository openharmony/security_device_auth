/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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

#include "hc_thread.h"
#include "hal_error.h"
#include "hc_log.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_THREAD_STACK_SIZE (8 * 1024 * 1024)

void *StaticThreadFunc(void *args)
{
    if (args == NULL) {
        return NULL;
    }
    HcThread* thread = (HcThread*)args;
    if (thread == NULL) {
        return NULL;
    }

#if defined(SET_THREAD_NAME)
    int res = pthread_setname_np(pthread_self(), StringGet(&thread->name));
    if (res != 0) {
        LOGW("[OS]: pthread_setname_np fail. [Res]: %" LOG_PUB "d", res);
    } else {
        LOGI("[OS]: pthread_setname_np success. [StackSize]: %" LOG_PUB "zu, [Name]: %" LOG_PUB "s", thread->stackSize,
            StringGet(&thread->name));
    }
#endif

    if (thread->threadFunc) {
        thread->threadFunc(args);
    }
    (void)LockHcMutex(&thread->threadLock);
    thread->running = HC_FALSE;
    thread->threadWaitObj.notifyWithoutLock(&thread->threadWaitObj);
    UnlockHcMutex(&thread->threadLock);
    return NULL;
}

int Start(struct HcThreadT *thread)
{
    if (thread == NULL) {
        return HAL_ERR_NULL_PTR;
    }
    (void)LockHcMutex(&thread->threadLock);
    if (thread->running) {
        UnlockHcMutex(&thread->threadLock);
        return 0;
    }
    thread->running = HC_TRUE;

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    if (thread->stackSize > 0 && thread->stackSize <= MAX_THREAD_STACK_SIZE) {
        pthread_attr_setstacksize(&attr, thread->stackSize);
    }

    LOGI("[OS]: pthread_create enter.");
    int res = pthread_create(&thread->thread, &attr, StaticThreadFunc, thread);
    LOGI("[OS]: pthread_create quit. [Res]: %" LOG_PUB "d", res);
    pthread_attr_destroy(&attr);
    if (res != 0) {
        LOGE("[OS]: pthread_create fail. [Res]: %" LOG_PUB "d", res);
        thread->running = HC_FALSE;
    }
    UnlockHcMutex(&thread->threadLock);
    return res;
}

void Join(struct HcThreadT *thread)
{
    if (thread == NULL) {
        return;
    }
    (void)LockHcMutex(&thread->threadLock);
    if (thread->running) {
        thread->threadWaitObj.waitWithoutLock(&thread->threadWaitObj);
    }
    UnlockHcMutex(&thread->threadLock);
}

void BizNotify(struct HcThreadT *thread)
{
    if (thread == NULL) {
        return;
    }
    thread->bizWaitObj.notify(&thread->bizWaitObj);
}

void BizWait(struct HcThreadT *thread)
{
    if (thread == NULL) {
        return;
    }
    thread->bizWaitObj.wait(&thread->bizWaitObj);
}

int32_t InitThread(HcThread *thread, ThreadFunc func, size_t stackSize, const char *threadName)
{
    if (thread == NULL) {
        return -1;
    }

    thread->threadFunc = func;
    thread->start = Start;
    thread->wait = BizWait;
    thread->notify = BizNotify;
    thread->join = Join;
    thread->stackSize = stackSize;
    thread->running = HC_FALSE;
    thread->name = CreateString();
    if (StringSetPointer(&thread->name, threadName) != HC_TRUE) {
        return -1;
    }

    int32_t res = InitHcMutex(&thread->threadLock, false);
    if (res != 0) {
        DeleteString(&thread->name);
        return res;
    }
    res = InitHcCond(&thread->threadWaitObj, &thread->threadLock);
    if (res != 0) {
        DeleteString(&thread->name);
        DestroyHcMutex(&thread->threadLock);
        return res;
    }
    res = InitHcCond(&thread->bizWaitObj, NULL);
    if (res != 0) {
        DeleteString(&thread->name);
        DestroyHcMutex(&thread->threadLock);
        DestroyHcCond(&thread->threadWaitObj);
    }
    return res;
}

void DestroyThread(HcThread *thread)
{
    if (thread == NULL) {
        return;
    }

    DestroyHcCond(&thread->bizWaitObj);
    DestroyHcCond(&thread->threadWaitObj);
    DestroyHcMutex(&thread->threadLock);
    DeleteString(&thread->name);
}

#ifdef __cplusplus
}
#endif