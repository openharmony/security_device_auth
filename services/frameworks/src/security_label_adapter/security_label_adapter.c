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

#include "security_label_adapter.h"

#include <sys/xattr.h>
#include "device_auth_defines.h"
#include "hc_types.h"
#include "hc_log.h"

#define SECURITY_LABEL_XATTR_KEY "user.security"

static int32_t GetSecurityLabel(const char *filePath, char **returnLabel)
{
    int32_t labelSize = getxattr(filePath, SECURITY_LABEL_XATTR_KEY, NULL, 0);
    if (labelSize <= 0 || errno == ENOTSUP) {
        LOGE("Failed to get security label size, labelSize: %d, [errno]: %d", labelSize, errno);
        return HC_ERROR;
    }
    char *label = (char *)HcMalloc(labelSize + 1, 0);
    if (label == NULL) {
        LOGE("Failed to alloc memory for label!");
        return HC_ERR_ALLOC_MEMORY;
    }
    labelSize = getxattr(filePath, SECURITY_LABEL_XATTR_KEY, label, labelSize);
    if (labelSize <= 0 || errno == ENOTSUP) {
        LOGE("Failed to get security label, labelSize: %d, [errno]: %d", labelSize, errno);
        HcFree(label);
        return HC_ERROR;
    }
    *returnLabel = label;
    return HC_SUCCESS;
}

static bool IsSetLabelNeeded(const char *filePath, const char *labelToSet)
{
    char *existLabel = NULL;
    if (GetSecurityLabel(filePath, &existLabel) != HC_SUCCESS) {
        return true;
    }
    if (strcmp(existLabel, labelToSet) != 0) {
        LOGI("Incorrect security level, need to reset.");
        HcFree(existLabel);
        return true;
    }
    HcFree(existLabel);
    return false;
}

void SetSecurityLabel(const char *filePath, const char *labelToSet)
{
    if (!IsSetLabelNeeded(filePath, labelToSet)) {
        return;
    }
    int32_t res = setxattr(filePath, SECURITY_LABEL_XATTR_KEY, labelToSet,
        strlen(labelToSet), 0);
    LOGI("Set security label [Res]: %d", res);
}