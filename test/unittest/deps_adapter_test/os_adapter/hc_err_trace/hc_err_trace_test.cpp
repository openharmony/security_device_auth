#include <gtest/gtest.h>
#include <string>
#include "hc_err_trace.h"

using namespace testing::ext;

class HcErrTraceTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

HWTEST_F(HcErrTraceTest, SetLogModeAndErrTraceTest001, TestSize.Level0)
{
    SetLogModeAndErrTrace(NORMAL_MODE, true);
    EXPECT_NE(GetErrTrace(), nullptr);
    EXPECT_EQ(GetErrTraceLen(), 0);
}

HWTEST_F(HcErrTraceTest, SetLogModeAndErrTraceTest002, TestSize.Level0)
{
    SetLogModeAndErrTrace(TRACE_MODE, true);
    EXPECT_EQ(GetErrTraceLen(), 0);
}

HWTEST_F(HcErrTraceTest, SetLogModeAndErrTraceTest003, TestSize.Level0)
{
    SetLogModeAndErrTrace(NORMAL_MODE, false);
    EXPECT_EQ(GetErrTraceLen(), 0);
}

HWTEST_F(HcErrTraceTest, RecordErrTraceTest001, TestSize.Level0)
{
    SetLogModeAndErrTrace(NORMAL_MODE, true);
    va_list emptyArgs;
    RecordErrTrace("TestFunc", 42, "test_msg", emptyArgs);
    EXPECT_GT(GetErrTraceLen(), 0);
    std::string trace(GetErrTrace());
    EXPECT_NE(trace.find("TestFunc"), std::string::npos);
    EXPECT_NE(trace.find("42"), std::string::npos);
}

HWTEST_F(HcErrTraceTest, RecordErrTraceTest002, TestSize.Level0)
{
    SetLogModeAndErrTrace(NORMAL_MODE, true);
    va_list emptyArgs;
    RecordErrTrace(NULL, 42, "test_msg", emptyArgs);
    EXPECT_EQ(GetErrTraceLen(), 0);
}

HWTEST_F(HcErrTraceTest, RecordErrTraceTest003, TestSize.Level0)
{
    SetLogModeAndErrTrace(NORMAL_MODE, true);
    va_list emptyArgs;
    RecordErrTrace("TestFunc", 42, NULL, emptyArgs);
    EXPECT_EQ(GetErrTraceLen(), 0);
}

HWTEST_F(HcErrTraceTest, RecordErrTraceTest004, TestSize.Level0)
{
    SetLogModeAndErrTrace(NORMAL_MODE, false);
    va_list emptyArgs;
    RecordErrTrace("TestFunc", 42, "test_msg", emptyArgs);
    EXPECT_EQ(GetErrTraceLen(), 0);
}

HWTEST_F(HcErrTraceTest, RecordErrTraceTest005, TestSize.Level0)
{
    SetLogModeAndErrTrace(NORMAL_MODE, true);
    va_list emptyArgs;
    RecordErrTrace("Func1", 10, "msg1", emptyArgs);
    EXPECT_GT(GetErrTraceLen(), 0);
    std::string trace1(GetErrTrace());
    EXPECT_NE(trace1.find("Func1"), std::string::npos);
    RecordErrTrace("Func2", 20, "msg2", emptyArgs);
    std::string trace2(GetErrTrace());
    EXPECT_NE(trace2.find("Func1"), std::string::npos);
    EXPECT_NE(trace2.find("Func2"), std::string::npos);
    EXPECT_NE(trace2.find(" < "), std::string::npos);
}

HWTEST_F(HcErrTraceTest, GetErrTraceTest001, TestSize.Level0)
{
    SetLogModeAndErrTrace(NORMAL_MODE, true);
    EXPECT_STREQ(GetErrTrace(), "");
}

HWTEST_F(HcErrTraceTest, GetErrTraceLenTest001, TestSize.Level0)
{
    SetLogModeAndErrTrace(NORMAL_MODE, true);
    EXPECT_EQ(GetErrTraceLen(), 0);
}

HWTEST_F(HcErrTraceTest, ClearErrTraceTest001, TestSize.Level0)
{
    SetLogModeAndErrTrace(NORMAL_MODE, true);
    va_list emptyArgs;
    RecordErrTrace("TestFunc", 42, "msg", emptyArgs);
    EXPECT_GT(GetErrTraceLen(), 0);
    ClearErrTrace();
    EXPECT_EQ(GetErrTraceLen(), 0);
    EXPECT_STREQ(GetErrTrace(), "");
}

HWTEST_F(HcErrTraceTest, SetTraceIdTest001, TestSize.Level0)
{
    SetLogModeAndErrTrace(TRACE_MODE, true);
    SetTraceId(12345);
    va_list emptyArgs;
    RecordErrTrace("FuncWithTrace", 1, "trace_msg", emptyArgs);
    std::string trace(GetErrTrace());
    EXPECT_NE(trace.find("12345"), std::string::npos);
    EXPECT_NE(trace.find("FuncWithTrace"), std::string::npos);
}

HWTEST_F(HcErrTraceTest, GetTraceInfoTest001, TestSize.Level0)
{
    SetLogModeAndErrTrace(NORMAL_MODE, true);
    va_list emptyArgs;
    RecordErrTrace("NormalModeFunc", 1, "normal_msg", emptyArgs);
    std::string trace(GetErrTrace());
    EXPECT_NE(trace.find("NormalModeFunc"), std::string::npos);
}
