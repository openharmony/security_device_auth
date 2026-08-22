#include "hc_dev_info_mock.h"
#include "hc_log.h"

static MockHcDevInfo *g_mockHcDevInfo = nullptr;

void SetMockHcDevInfo(MockHcDevInfo *mock)
{
    g_mockHcDevInfo = mock;
}

extern "C" int32_t HcGetUdid(uint8_t *udid, int32_t udidLen)
{
    if (g_mockHcDevInfo) {
        return g_mockHcDevInfo->HcGetUdid(udid, udidLen);
    }
    LOGE("HcGetUdid called without mock!");
    return -1;
}

extern "C" const char *GetStoragePath(void)
{
    if (g_mockHcDevInfo) {
        return g_mockHcDevInfo->GetStoragePath();
    }
    LOGE("GetStoragePath called without mock!");
    return nullptr;
}

extern "C" const char *GetStorageDirPathCe(void)
{
    if (g_mockHcDevInfo) {
        return g_mockHcDevInfo->GetStorageDirPathCe();
    }
    LOGE("GetStorageDirPathCe called without mock!");
    return nullptr;
}

extern "C" const char *GetStorageDirPath(void)
{
    if (g_mockHcDevInfo) {
        return g_mockHcDevInfo->GetStorageDirPath();
    }
    LOGE("GetStorageDirPath called without mock!");
    return nullptr;
}

extern "C" const char *GetAccountStoragePath(void)
{
    if (g_mockHcDevInfo) {
        return g_mockHcDevInfo->GetAccountStoragePath();
    }
    LOGE("GetAccountStoragePath called without mock!");
    return nullptr;
}

extern "C" const char *GetPseudonymStoragePath(void)
{
    if (g_mockHcDevInfo) {
        return g_mockHcDevInfo->GetPseudonymStoragePath();
    }
    LOGE("GetPseudonymStoragePath called without mock!");
    return nullptr;
}
