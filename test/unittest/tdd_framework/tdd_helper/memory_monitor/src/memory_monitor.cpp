/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include <iostream>
#include <map>
#include <string>
#include <cstdio>
#include <cstdlib>
#include <securec.h>
#include "hc_mutex.h"
#include "memory_monitor.h"

using namespace std;

#define MAX_MALLOC_SIZE 8192
#define MALLOC_MAX_LINE_STR_LEN 11

static const int MALLOC_SIZE[] = { 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192 };

static int GetRealMallocSize(int size)
{
    for (unsigned int i = 0; i < sizeof(MALLOC_SIZE) / sizeof(int); ++i) {
        if (size <= MALLOC_SIZE[i]) {
            return MALLOC_SIZE[i];
        }
    }
    return MAX_MALLOC_SIZE;
}

typedef struct {
    uint32_t id;
    uint32_t size;
    uint32_t realSize;
    string str;
} MemoryBlock;

static map<void*, MemoryBlock> gMemoryMap;

static bool g_isInit = false;

static int g_mallocCount = 0;
static int g_maxCount = 0;
static int g_maxSingleCount = 0;
static int g_count = 0;

static HcMutex *g_mutex = NULL;

void HcMonitorMalloc(void *addr, uint32_t size, const char *strFile, int nLine)
{
    if (!g_isInit) {
        return;
    }
    g_mutex->lock(g_mutex);
    map<void *, MemoryBlock>::iterator iter = gMemoryMap.find(addr);
    if (iter != gMemoryMap.end()) {
        cout << "############## Monitor Malloc error, addr is alread exist!" << endl;
    } else {
        int realSize = GetRealMallocSize(size);
        MemoryBlock mb;
        mb.size = size;
        mb.realSize = realSize;
        mb.id = g_count++;
        char strLine[MALLOC_MAX_LINE_STR_LEN];
        if (sprintf_s(strLine, MALLOC_MAX_LINE_STR_LEN, "%d", nLine) <= 0) {
            g_mutex->unlock(g_mutex);
            return;
        }
        mb.str = strFile;
        mb.str += ":";
        mb.str += strLine;
        gMemoryMap[addr] = mb;
        g_mallocCount += realSize;
        if (g_maxCount < g_mallocCount) {
            g_maxCount = g_mallocCount;
        }
        if (g_maxSingleCount < realSize) {
            g_maxSingleCount = realSize;
        }
    }
    g_mutex->unlock(g_mutex);
}

void HcMonitorFree(void *addr)
{
    if (!g_isInit) {
        return;
    }
    g_mutex->lock(g_mutex);
    map<void *, MemoryBlock>::iterator iter = gMemoryMap.find(addr);
    if (iter != gMemoryMap.end()) {
        g_mallocCount -= GetRealMallocSize(iter->second.size);
        gMemoryMap.erase(iter);
    } else {
        cout << "############## Monitor Free error, addr is not exist!" << endl;
    }
    g_mutex->unlock(g_mutex);
}

void ReportMonitor(void)
{
    if (!g_isInit) {
        return;
    }
    g_mutex->lock(g_mutex);
    printf("\n############## Monitor Report ##############\nMemoryBlock Num: %zu\nMemory Used Size: %d\n"
        "Memory Max Used Size: %d\nMemory Max Single Size: %d\n",
        gMemoryMap.size(), g_mallocCount, g_maxCount, g_maxSingleCount);
    for (map<void *, MemoryBlock>::iterator iter = gMemoryMap.begin(); iter != gMemoryMap.end(); ++iter) {
        printf("\n############## Memory Block ##############\nMemoryBlock Id: %d\nMemoryBlock Size: %d\n"
            "MemoryBlock Size: %d\nMemoryBlock Location: %s\n",
            iter->second.id, iter->second.size, iter->second.realSize, iter->second.str.c_str());
    }
    g_mutex->unlock(g_mutex);
}

bool IsMemoryLeak(void)
{
    return g_mallocCount > 0;
}

void HcInitMallocMonitor(void)
{
    if (g_isInit) {
        return;
    }
    g_isInit = true;
    g_mutex = static_cast<HcMutex *>(malloc(sizeof(HcMutex)));
    InitHcMutex(g_mutex);
}

void HcDestroyMallocMonitor(void)
{
    if (!g_isInit) {
        return;
    }
    g_isInit = false;
    g_mutex->lock(g_mutex);
    gMemoryMap.clear();
    g_mallocCount = 0;
    g_maxCount = 0;
    g_maxSingleCount = 0;
    g_count = 0;
    g_mutex->unlock(g_mutex);
    DestroyHcMutex(g_mutex);
    free(g_mutex);
    g_mutex = NULL;
}
