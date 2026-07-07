/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>
#include <cstdio>
#include <cstring>
#include "hc_file.h"

using namespace testing::ext;

class HcFileTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

static const char *TEST_FILE_PATH = "/tmp/hc_file_test.dat";

HWTEST_F(HcFileTest, HcFileOpenReadTest001, TestSize.Level0)
{
    FileHandle file;
    file.pfd = nullptr;
    int ret = HcFileOpen("/nonexistent/path/file.dat", MODE_FILE_READ, &file);
    EXPECT_EQ(ret, -1);
}

HWTEST_F(HcFileTest, HcFileOpenNullPathTest001, TestSize.Level0)
{
    FileHandle file;
    file.pfd = nullptr;
    int ret = HcFileOpen(nullptr, MODE_FILE_READ, &file);
    EXPECT_EQ(ret, -1);
}

HWTEST_F(HcFileTest, HcFileOpenNullFileTest001, TestSize.Level0)
{
    int ret = HcFileOpen("/tmp/test.dat", MODE_FILE_READ, nullptr);
    EXPECT_EQ(ret, -1);
}

HWTEST_F(HcFileTest, HcFileWriteAndReadTest001, TestSize.Level0)
{
    FileHandle writeFile;
    writeFile.pfd = nullptr;
    int ret = HcFileOpen(TEST_FILE_PATH, MODE_FILE_WRITE, &writeFile);
    EXPECT_EQ(ret, 0);
    EXPECT_NE(writeFile.pfd, nullptr);

    const char *data = "hello world test data";
    int writeSize = HcFileWrite(writeFile, data, strlen(data));
    EXPECT_EQ(writeSize, (int)strlen(data));

    HcFileClose(writeFile);

    FileHandle readFile;
    readFile.pfd = nullptr;
    ret = HcFileOpen(TEST_FILE_PATH, MODE_FILE_READ, &readFile);
    EXPECT_EQ(ret, 0);
    EXPECT_NE(readFile.pfd, nullptr);

    int fileSize = HcFileSize(readFile);
    EXPECT_EQ(fileSize, (int)strlen(data));

    char readBuf[64] = {0};
    int readSize = HcFileRead(readFile, readBuf, fileSize);
    EXPECT_EQ(readSize, fileSize);
    EXPECT_STREQ(readBuf, data);

    HcFileClose(readFile);
    HcFileRemove(TEST_FILE_PATH);
}

HWTEST_F(HcFileTest, HcFileSizeNullTest001, TestSize.Level0)
{
    FileHandle file;
    file.pfd = nullptr;
    int size = HcFileSize(file);
    EXPECT_EQ(size, -1);
}

HWTEST_F(HcFileTest, HcFileReadNullFpTest001, TestSize.Level0)
{
    FileHandle file;
    file.pfd = nullptr;
    char buf[10];
    int ret = HcFileRead(file, buf, 10);
    EXPECT_EQ(ret, -1);
}

HWTEST_F(HcFileTest, HcFileReadNullDstTest001, TestSize.Level0)
{
    FileHandle writeFile;
    writeFile.pfd = nullptr;
    int ret = HcFileOpen(TEST_FILE_PATH, MODE_FILE_WRITE, &writeFile);
    EXPECT_EQ(ret, 0);
    HcFileWrite(writeFile, "data", 4);
    HcFileClose(writeFile);

    FileHandle readFile;
    readFile.pfd = nullptr;
    ret = HcFileOpen(TEST_FILE_PATH, MODE_FILE_READ, &readFile);
    EXPECT_EQ(ret, 0);
    int readRet = HcFileRead(readFile, nullptr, 10);
    EXPECT_EQ(readRet, -1);
    HcFileClose(readFile);
    HcFileRemove(TEST_FILE_PATH);
}

HWTEST_F(HcFileTest, HcFileWriteNullFpTest001, TestSize.Level0)
{
    FileHandle file;
    file.pfd = nullptr;
    int ret = HcFileWrite(file, "data", 4);
    EXPECT_EQ(ret, -1);
}

HWTEST_F(HcFileTest, HcFileWriteNullSrcTest001, TestSize.Level0)
{
    FileHandle writeFile;
    writeFile.pfd = nullptr;
    int ret = HcFileOpen(TEST_FILE_PATH, MODE_FILE_WRITE, &writeFile);
    EXPECT_EQ(ret, 0);
    int writeRet = HcFileWrite(writeFile, nullptr, 4);
    EXPECT_EQ(writeRet, -1);
    HcFileClose(writeFile);
    HcFileRemove(TEST_FILE_PATH);
}

HWTEST_F(HcFileTest, HcFileCloseNullTest001, TestSize.Level0)
{
    FileHandle file;
    file.pfd = nullptr;
    HcFileClose(file);
}

HWTEST_F(HcFileTest, HcFileRemoveNullPathTest001, TestSize.Level0)
{
    HcFileRemove(nullptr);
}

HWTEST_F(HcFileTest, HcFileRemoveTest001, TestSize.Level0)
{
    FileHandle writeFile;
    writeFile.pfd = nullptr;
    int ret = HcFileOpen(TEST_FILE_PATH, MODE_FILE_WRITE, &writeFile);
    EXPECT_EQ(ret, 0);
    HcFileWrite(writeFile, "test", 4);
    HcFileClose(writeFile);
    HcFileRemove(TEST_FILE_PATH);

    FileHandle readFile;
    readFile.pfd = nullptr;
    ret = HcFileOpen(TEST_FILE_PATH, MODE_FILE_READ, &readFile);
    EXPECT_EQ(ret, -1);
}
