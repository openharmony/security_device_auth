#include <gtest/gtest.h>
#include "hc_log.h"
#include "hc_types.h"

using namespace testing::ext;

class HcLogTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

HWTEST_F(HcLogTest, LogAndRecordErrorTest001, TestSize.Level0)
{
    LOGE("test log message");
}

HWTEST_F(HcLogTest, LogAndRecordErrorTest002, TestSize.Level0)
{
    LOGE("test with int: %d", 42);
}

HWTEST_F(HcLogTest, LogAndRecordErrorTest003, TestSize.Level0)
{
    LOGE("test with string: %s", "hello");
}

HWTEST_F(HcLogTest, LogAndRecordErrorNullParamsTest001, TestSize.Level0)
{
    LogAndRecordError(NULL, 42, "test");
}

HWTEST_F(HcLogTest, LogAndRecordErrorNullParamsTest002, TestSize.Level0)
{
    LogAndRecordError("Func", 42, NULL);
}

HWTEST_F(HcLogTest, PrintSensitiveDataTest001, TestSize.Level0)
{
    const char *longStr = "01234567890123456789";
    PRINT_SENSITIVE_DATA("TEST", longStr);
}

HWTEST_F(HcLogTest, PrintSensitiveDataTest002, TestSize.Level0)
{
    const char *shortStr = "abc";
    PRINT_SENSITIVE_DATA("TEST", shortStr);
}

HWTEST_F(HcLogTest, PrintSensitiveByteTest001, TestSize.Level0)
{
    uint8_t byte[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c};
    PRINT_SENSITIVE_BYTE("TEST", byte, 12);
}

HWTEST_F(HcLogTest, PrintSensitiveByteTest002, TestSize.Level0)
{
    uint8_t byte[] = {0x01, 0x02};
    PRINT_SENSITIVE_BYTE("TEST", byte, 2);
}

HWTEST_F(HcLogTest, LogLevelsTest001, TestSize.Level0)
{
    LOGD("debug message");
    LOGI("info message");
    LOGW("warning message");
}
