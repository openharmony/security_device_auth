#ifndef HC_DEV_INFO_MOCK_H
#define HC_DEV_INFO_MOCK_H

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "hc_dev_info.h"

class MockHcDevInfo {
public:
    MOCK_METHOD(int32_t, HcGetUdid, (uint8_t *udid, int32_t udidLen));
    MOCK_METHOD(const char *, GetStoragePath, ());
    MOCK_METHOD(const char *, GetStorageDirPathCe, ());
    MOCK_METHOD(const char *, GetStorageDirPath, ());
    MOCK_METHOD(const char *, GetAccountStoragePath, ());
    MOCK_METHOD(const char *, GetPseudonymStoragePath, ());
};

void SetMockHcDevInfo(MockHcDevInfo *mock);

#endif
