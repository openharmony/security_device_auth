/*
 * Copyright (C) 2022-2025 Huawei Device Co., Ltd.
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

#include "hc_file.h"
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include "hc_log.h"
#include "hc_types.h"
#include "securec.h"
#include "string_util.h"

#define MAX_FOLDER_NAME_SIZE 128
#define DEFAULT_FILE_PERMISSION 0600

static int32_t CreateDirectory(const char *filePath)
{
    int32_t res;
    char *chPtr = NULL;
    char dirCache[MAX_FOLDER_NAME_SIZE];

    chPtr = (char *)filePath;
    while ((chPtr = strchr(chPtr, '/')) != NULL) {
        unsigned long len = (unsigned long)((uintptr_t)chPtr - (uintptr_t)filePath);
        if (len == 0uL) {
            chPtr++;
            continue;
        }
        if (len >= MAX_FOLDER_NAME_SIZE || memcpy_s(dirCache, sizeof(dirCache), filePath, len) != EOK) {
            LOGE("memory copy failed");
            return -1;
        }
        dirCache[len] = 0;
        res = access(dirCache, F_OK);
        if (res == 0) {
            chPtr++;
            continue;
        }
        LOGI("[OS]: CreateDirectory access fail. [Res]: %" LOG_PUB "d, [errno]: %" LOG_PUB "d", res, errno);
        DIR *dir = opendir(dirCache);
        if (dir == NULL) {
            LOGI("[OS]: opendir fail. [errno]: %" LOG_PUB "d", errno);
            res = mkdir(dirCache, DEFAULT_FILE_PERMISSION);
            if (res != 0) {
                LOGE("[OS]: mkdir fail. [Res]: %" LOG_PUB "d, [errno]: %" LOG_PUB "d", res, errno);
                return -1;
            }
        } else {
            closedir(dir);
        }
        chPtr++;
    }
    return 0;
}

static FILE *HcFileOpenRead(const char *path)
{
    LOGI("[OS]: file open enter.");
    FILE *fp = fopen(path, "rb");
    LOGI("[OS]: file open quit.");
    if (fp == NULL) {
        LOGE("[OS]: file open fail. [Errno]: %" LOG_PUB "d", errno);
    }
    return fp;
}

static FILE *HcFileOpenWrite(const char *path)
{
    if (access(path, F_OK) != 0) {
        LOGI("[OS]: HcFileOpenWrite access fail. [errno]: %" LOG_PUB "d", errno);
        if (CreateDirectory(path) != 0) {
            return NULL;
        }
    }
    LOGI("[OS]: file open enter.");
    FILE *fp = fopen(path, "wb+");
    LOGI("[OS]: file open quit.");
    if (fp == NULL) {
        LOGE("[OS]: file open fail. [Errno]: %" LOG_PUB "d", errno);
        return NULL;
    }
    return fp;
}

int HcFileOpen(const char *path, int mode, FileHandle *file)
{
    if (path == NULL || file == NULL) {
        return -1;
    }
    if (mode == MODE_FILE_READ) {
        file->fileHandle.pfd = HcFileOpenRead(path);
    } else {
        file->fileHandle.pfd = HcFileOpenWrite(path);
    }
    if (file->fileHandle.pfd == NULL) {
        return -1;
    } else {
        return 0;
    }
}

int HcFileSize(FileHandle file)
{
    FILE *fp = file.fileHandle.pfd;
    if (fp == NULL) {
        return -1;
    }
    if (fseek(fp, 0L, SEEK_END) != 0) {
        LOGE("[OS]: fseek fail. [Errno]: %" LOG_PUB "d", errno);
        return -1;
    }
    int size = ftell(fp);
    if (fseek(fp, 0L, SEEK_SET) != 0) {
        LOGE("[OS]: fseek fail. [Errno]: %" LOG_PUB "d", errno);
        return -1;
    }
    return size;
}

int HcFileRead(FileHandle file, void *dst, int dstSize)
{
    FILE *fp = file.fileHandle.pfd;
    if (fp == NULL || dstSize < 0 || dst == NULL) {
        return -1;
    }

    char *dstBuffer = (char *)dst;
    int total = 0;
    LOGI("[OS]: file read enter. [OriSize]: %" LOG_PUB "d", dstSize);
    while (total < dstSize) {
        int readCount = (int)fread(dstBuffer + total, 1, dstSize - total, fp);
        if (ferror(fp) != 0) {
            LOGE("[OS]: read size error. [Errno]: %" LOG_PUB "d", errno);
            return -1;
        }
        if (readCount == 0) {
            LOGE("read size = 0, errno = %" LOG_PUB "d", errno);
            return total;
        }
        total += readCount;
    }
    LOGI("[OS]: file read quit. [ReadSize]: %" LOG_PUB "d", total);
    return total;
}

int HcFileWrite(FileHandle file, const void *src, int srcSize)
{
    FILE *fp = file.fileHandle.pfd;
    if (fp == NULL || srcSize < 0 || src == NULL) {
        return -1;
    }

    const char *srcBuffer = (const char *)src;
    int total = 0;
    LOGI("[OS]: file write enter. [OriSize]: %" LOG_PUB "d", srcSize);
    while (total < srcSize) {
        int writeCount = (int)fwrite(srcBuffer + total, 1, srcSize - total, fp);
        if (ferror(fp) != 0) {
            LOGE("[OS]: write size error. [Errno]: %" LOG_PUB "d", errno);
            return -1;
        }
        if (writeCount == 0) {
            LOGE("write size = 0, errno = %" LOG_PUB "d", errno);
            return total;
        }
        total += writeCount;
    }
    LOGI("[OS]: file write quit. [WriteSize]: %" LOG_PUB "d", total);
    return total;
}

void HcFileClose(FileHandle file)
{
    FILE *fp = file.fileHandle.pfd;
    if (fp == NULL) {
        return;
    }

    int res = fclose(fp);
    if (res != 0) {
        LOGW("close file failed, res = %" LOG_PUB "d", res);
    }
}

void HcFileRemove(const char *path)
{
    if (path == NULL) {
        LOGE("Invalid file path");
        return;
    }
    int res = unlink(path);
    if (res != 0) {
        LOGW("[OS]: delete file fail. [Res]: %" LOG_PUB "d", res);
    }
}

void HcFileGetSubFileName(const char *path, StringVector *nameVec)
{
    DIR *dir = NULL;
    struct dirent *entry = NULL;
    if ((dir = opendir(path)) == NULL) {
        LOGI("open dir failed!");
        return;
    }
    while ((entry = readdir(dir)) != NULL) {
        if (IsStrEqual(entry->d_name, ".") || IsStrEqual(entry->d_name, "..")) {
            continue;
        }
        HcString subFileName = CreateString();
        if (!StringSetPointer(&subFileName, entry->d_name)) {
            LOGE("Failed to copy name to subFileName!");
            DeleteString(&subFileName);
            continue;
        }
        if (nameVec->pushBackT(nameVec, subFileName) == NULL) {
            LOGE("Failed to push subFileName to nameVec!");
            DeleteString(&subFileName);
        }
    }
    if (closedir(dir) < 0) {
        LOGE("Failed to close file");
    }
}
