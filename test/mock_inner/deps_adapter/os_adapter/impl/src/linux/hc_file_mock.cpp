#include "hc_file_mock.h"
#include "hc_log.h"

static MockHcFile *g_mockHcFile = nullptr;

void SetMockHcFile(MockHcFile *mock)
{
    g_mockHcFile = mock;
}

extern "C" int HcFileOpen(const char *path, int mode, FileHandle *file)
{
    if (g_mockHcFile) {
        return g_mockHcFile->HcFileOpen(path, mode, file);
    }
    LOGE("HcFileOpen called without mock!");
    return -1;
}

extern "C" int HcFileSize(FileHandle file)
{
    if (g_mockHcFile) {
        return g_mockHcFile->HcFileSize(file);
    }
    LOGE("HcFileSize called without mock!");
    return -1;
}

extern "C" int HcFileRead(FileHandle file, void *dst, int dstSize)
{
    if (g_mockHcFile) {
        return g_mockHcFile->HcFileRead(file, dst, dstSize);
    }
    LOGE("HcFileRead called without mock!");
    return -1;
}

extern "C" int HcFileWrite(FileHandle file, const void *src, int srcSize)
{
    if (g_mockHcFile) {
        return g_mockHcFile->HcFileWrite(file, src, srcSize);
    }
    LOGE("HcFileWrite called without mock!");
    return -1;
}

extern "C" void HcFileClose(FileHandle file)
{
    if (g_mockHcFile) {
        g_mockHcFile->HcFileClose(file);
        return;
    }
    LOGE("HcFileClose called without mock!");
}

extern "C" void HcFileRemove(const char *path)
{
    if (g_mockHcFile) {
        g_mockHcFile->HcFileRemove(path);
        return;
    }
    LOGE("HcFileRemove called without mock!");
}

extern "C" void HcFileGetSubFileName(const char *path, StringVector *nameVec)
{
    if (g_mockHcFile) {
        g_mockHcFile->HcFileGetSubFileName(path, nameVec);
        return;
    }
    LOGE("HcFileGetSubFileName called without mock!");
}
