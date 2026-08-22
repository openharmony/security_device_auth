#ifndef HC_FILE_MOCK_H
#define HC_FILE_MOCK_H

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "hc_file.h"

class MockHcFile {
public:
    MOCK_METHOD(int, HcFileOpen, (const char *path, int mode, FileHandle *file));
    MOCK_METHOD(int, HcFileSize, (FileHandle file));
    MOCK_METHOD(int, HcFileRead, (FileHandle file, void *dst, int dstSize));
    MOCK_METHOD(int, HcFileWrite, (FileHandle file, const void *src, int srcSize));
    MOCK_METHOD(void, HcFileClose, (FileHandle file));
    MOCK_METHOD(void, HcFileRemove, (const char *path));
    MOCK_METHOD(void, HcFileGetSubFileName, (const char *path, StringVector *nameVec));
};

void SetMockHcFile(MockHcFile *mock);

#endif
