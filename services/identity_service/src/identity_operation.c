/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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


#include "identity_operation.h"

#include "alg_defs.h"
#include "alg_loader.h"
#include "clib_error.h"
#include "cred_listener.h"
#include "device_auth.h"
#include "device_auth_defines.h"
#include "hal_error.h"
#include "hc_log.h"
#include "hc_time.h"
#include "identity_service_defines.h"
#include "permission_adapter.h"

int32_t GetCredentialById(int32_t osAccountId, const char *credId, Credential **returnEntry)
{
    if (credId == NULL) {
        LOGE("The input credId is NULL!");
        return IS_ERR_INVALID_PARAMS;
    }
    uint32_t index;
    CredentialVec credentialVec = CreateCredentialVec();
    QueryCredentialParams params = InitQueryCredentialParams();
    params.credId = credId;
    int32_t ret = QueryCredentials(osAccountId, &params, &credentialVec);
    if (ret != IS_SUCCESS) {
        LOGE("Failed to query credentials!");
        ClearCredentialVec(&credentialVec);
        return ret;
    }
    Credential **credential = NULL;
    FOR_EACH_HC_VECTOR(credentialVec, index, credential) {
        *returnEntry = DeepCopyCredential(*credential);
        ClearCredentialVec(&credentialVec);
        if (*returnEntry == NULL) {
            LOGE("Failed to copy credential!");
            return IS_ERR_ALLOC_MEMORY;
        }
        return IS_SUCCESS;
    }
    ClearCredentialVec(&credentialVec);
    LOGI("This credId does not exist!");
    return IS_ERR_LOCAL_CRED_NOT_EXIST;
}

static int32_t Int64ToString(int64_t num, char **result)
{
    const int bufferSize = MAX_INT64_SIZE + 1;
    char *tempStr = (char *)HcMalloc(bufferSize, 0);
    if (tempStr == NULL) {
        LOGE("Failed to allocate memory!");
        return IS_ERR_ALLOC_MEMORY;
    }
    if (sprintf_s(tempStr, bufferSize, "%" PRId64, num) < 0) {
        LOGE("Failed to convert int64 to string!");
        HcFree(tempStr);
        return IS_ERR_CONVERT_FAILED;
    }
    *result = tempStr;
    return IS_SUCCESS;
}

static int32_t CombineBaseCredId(const char *credentialOwner, const char *deviceId, char **baseCredIdStr)
{
    if (credentialOwner == NULL || deviceId == NULL) {
        LOGE("Invalid input parameters!");
        return IS_ERR_INVALID_PARAMS;
    }
    char *timeStr = NULL;
    int32_t ret = Int64ToString(HcGetCurTimeInMillis(), &timeStr);
    if (ret != IS_SUCCESS) {
        LOGE("Failed to convert time to string!");
        return ret;
    }
    size_t totalLength = HcStrlen(credentialOwner) + HcStrlen(deviceId) + HcStrlen(timeStr) + 1;
    char *tempCredId = (char *)HcMalloc(totalLength, 0);
    if (tempCredId == NULL) {
        LOGE("Failed to allocate memory for tempCredId!");
        HcFree(timeStr);
        return IS_ERR_ALLOC_MEMORY;
    }

    if (strcpy_s(tempCredId, totalLength, credentialOwner) != EOK) {
        LOGE("Failed to copy credentialOwner to tempCredId!");
        HcFree(timeStr);
        HcFree(tempCredId);
        return IS_ERR_CONVERT_FAILED;
    }
    if (strcat_s(tempCredId, totalLength, deviceId) != EOK) {
        LOGE("Failed to concatenate deviceId to tempCredId!");
        HcFree(timeStr);
        HcFree(tempCredId);
        return IS_ERR_CONVERT_FAILED;
    }
    if (strcat_s(tempCredId, totalLength, timeStr) != EOK) {
        LOGE("Failed to concatenate timeStr to tempCredId!");
        HcFree(timeStr);
        HcFree(tempCredId);
        return IS_ERR_CONVERT_FAILED;
    }
    HcFree(timeStr);
    *baseCredIdStr = tempCredId;
    return IS_SUCCESS;
}

static int32_t Uint8BuffToString(Uint8Buff *byte, char **str)
{
    uint32_t strLen = byte->length * BYTE_TO_HEX_OPER_LENGTH + 1;
    char *tempStr = (char *)HcMalloc(strLen, 0);
    if (tempStr == NULL) {
        LOGE("Failed to malloc tempStr");
        return IS_ERR_ALLOC_MEMORY;
    }
    int32_t ret = ByteToHexString(byte->val, byte->length, tempStr, strLen);
    if (ret != IS_SUCCESS) {
        LOGE("Failed to convert byte to hex string");
        HcFree(tempStr);
        return ret;
    }
    *str = tempStr;
    return IS_SUCCESS;
}

static int32_t Sha256BaseCredId(const char *baseCredIdStr, Uint8Buff *credIdByte, char **credIdStr)
{
    Uint8Buff returnCredIdByte = { NULL, SHA256_LEN };
    returnCredIdByte.val = (uint8_t *)HcMalloc(SHA256_LEN, 0);
    if (returnCredIdByte.val == NULL) {
        LOGE("Failed to malloc memory for returnCredIdByte");
        return IS_ERR_ALLOC_MEMORY;
    }

    Uint8Buff baseCredIdBuff = { (uint8_t *)baseCredIdStr, (uint32_t)HcStrlen(baseCredIdStr) };
    int32_t ret = GetLoaderInstance()->sha256(&baseCredIdBuff, &returnCredIdByte);
    if (ret == HAL_ERR_HUKS) {
        LOGE("Huks sha256 error");
        HcFree(returnCredIdByte.val);
        return IS_ERR_HUKS_SHA256_FAILED;
    }
    if (ret != IS_SUCCESS) {
        LOGE("Failed to sha256 credId, ret = %" LOG_PUB "d", ret);
        HcFree(returnCredIdByte.val);
        return ret;
    }

    char *returnCredIdStr = NULL;
    ret = Uint8BuffToString(&returnCredIdByte, &returnCredIdStr);
    if (ret != IS_SUCCESS) {
        LOGE("Failed to convert credIdByte to credIdStr, ret = %" LOG_PUB "d", ret);
        HcFree(returnCredIdByte.val);
        return ret;
    }
    *credIdStr = returnCredIdStr;
    credIdByte->val = returnCredIdByte.val;
    credIdByte->length = SHA256_LEN;
    return IS_SUCCESS;
}

static int32_t GenerateCredIdInner(const char *credentialOwner, const char *deviceId,
    Uint8Buff *credIdByte, char **credIdStr)
{
    char *baseCredIdStr = NULL;
    int32_t ret = CombineBaseCredId(credentialOwner, deviceId, &baseCredIdStr);
    if (ret != IS_SUCCESS) {
        LOGE("Failed to combine credId!");
        return ret;
    }
    
    ret = Sha256BaseCredId(baseCredIdStr, credIdByte, credIdStr);
    HcFree(baseCredIdStr);
    return ret;
}

static bool IsCredIdExist(int32_t osAccountId, const char *credIdStr)
{
    Credential *existedCredential = NULL;
    int32_t ret = GetCredentialById(osAccountId, credIdStr, &existedCredential);
    DestroyCredential(existedCredential);

    return ret == IS_SUCCESS;
}

static int32_t UseImportedCredId(int32_t osAccountId, Credential *credential, Uint8Buff *credIdByte)
{
    if (IsCredIdExist(osAccountId, StringGet(&credential->credId))) {
        LOGE("Imported credId existed");
        return IS_ERR_IMPORTED_CRED_ID_EXISTED;
    }
    LOGI("Imported credId not existed in DB, use imported credId");

    uint32_t credIdByteLen = HcStrlen(StringGet(&credential->credId)) / BYTE_TO_HEX_OPER_LENGTH;
    credIdByte->length = credIdByteLen;
    uint8_t *returnCredIdByteVal = (uint8_t *)HcMalloc(credIdByteLen, 0);
    if (returnCredIdByteVal == NULL) {
        LOGE("Failed to malloc memory for credIdByte");
        return IS_ERR_ALLOC_MEMORY;
    }

    int32_t ret = HexStringToByte(StringGet(&credential->credId), returnCredIdByteVal, credIdByte->length);
    if (ret != IS_SUCCESS) {
        LOGE("Failed to convert credId to byte, ret = %" LOG_PUB "d", ret);
        HcFree(returnCredIdByteVal);
        return IS_ERR_INVALID_HEX_STRING;
    }
    credIdByte->val = returnCredIdByteVal;
    return IS_SUCCESS;
}

static int32_t GenerateUniqueCredId(int32_t osAccountId,
    Credential *credential, Uint8Buff *credIdByte, char **credIdStr)
{
    char *returnCredId = NULL;
    const char *credOwner = StringGet(&credential->credOwner);
    const char *deviceId = StringGet(&credential->deviceId);
    int32_t ret = GenerateCredIdInner(credOwner, deviceId, credIdByte, &returnCredId);
    if (ret != IS_SUCCESS) {
        return ret;
    }
    if (IsCredIdExist(osAccountId, returnCredId)) {
        LOGW("CredId already exists, regenerate credId");
        HcFree(returnCredId);
        returnCredId = NULL;
        ret = GenerateCredIdInner(credOwner, deviceId, credIdByte, &returnCredId);
        if (ret != IS_SUCCESS) {
            return ret;
        }
    }
    *credIdStr = returnCredId;
    return IS_SUCCESS;
}

int32_t GenerateCredId(int32_t osAccountId, Credential *credential, Uint8Buff *credIdByte)
{
    if (HcStrlen(StringGet(&credential->credId)) > 0) {
        return UseImportedCredId(osAccountId, credential, credIdByte); // credId is set by user
    }

    char *credIdStr = NULL;
    int32_t ret = GenerateUniqueCredId(osAccountId, credential, credIdByte, &credIdStr);
    if (ret != IS_SUCCESS) {
        return ret;
    }

    if (!StringSetPointer(&credential->credId, credIdStr)) {
        LOGE("Failed to set credId");
        HcFree(credIdByte->val);
        HcFree(credIdStr);
        return IS_ERR_MEMORY_COPY;
    }
    HcFree(credIdStr);
    LOGI("Generate credId success");
    return IS_SUCCESS;
}

static int32_t CheckOutMaxCredSize(int32_t osAccountId, const char *credOwner)
{
    QueryCredentialParams queryParams = InitQueryCredentialParams();
    queryParams.credOwner = credOwner;
    CredentialVec credentialVec = CreateCredentialVec();
    int32_t ret = QueryCredentials(osAccountId, &queryParams, &credentialVec);
    if (ret != IS_SUCCESS) {
        LOGE("Failed to query credentials");
        ClearCredentialVec(&credentialVec);
        return ret;
    }
    if (credentialVec.size(&credentialVec) > MAX_CRED_SIZE) {
        LOGE("The number of credentials exceeds the maximum limit");
        ClearCredentialVec(&credentialVec);
        return IS_ERR_BEYOND_LIMIT;
    }
    ClearCredentialVec(&credentialVec);
    return IS_SUCCESS;
}

static Algorithm GetAlgoFromCred(uint8_t algorithmType)
{
    switch (algorithmType) {
        case ALGO_TYPE_P256:
            return P256;
        case ALGO_TYPE_ED25519:
            return ED25519;
        default:
            return AES;
    }
}

static int32_t GenerateKeyValue(int32_t osAccountId,
    Credential *credential, KeyParams keyParams, Algorithm algo, ExtraInfo exInfo)
{
    Uint8Buff keyAlias = { keyParams.keyBuff.key, keyParams.keyBuff.keyLen };
    if (GetLoaderInstance()->checkKeyExist(&keyAlias, false, osAccountId) != HAL_ERR_KEY_NOT_EXIST) {
        LOGI("The keyValue corresponding to the credId already exists in HUKS, no need to generate.");
        return IS_SUCCESS;
    }
    LOGI("The keyValue corresponding to the credId does not exist in HUKS, generate keyValue.");
    uint32_t keyLen = (credential->algorithmType == ALGO_TYPE_AES_128) ? AES_128_KEY_LEN : ALGO_KEY_LEN;
    int32_t ret = GetLoaderInstance()->generateKeyPairWithStorage(&keyParams, keyLen, algo,
        KEY_PURPOSE_KEY_AGREE, &exInfo);
    if (ret == HAL_ERR_HUKS) {
        LOGE("Huks generateKeyPair failed!");
        return IS_ERR_HUKS_GENERATE_KEY_FAILED;
    }
    if (ret != IS_SUCCESS) {
        LOGE("Failed to generate key pair!");
        return ret;
    }
    LOGI("Generate key pair success!");
    return IS_SUCCESS;
}

static int32_t ImportKeyValue(KeyParams keyParams,
    Uint8Buff *keyValue, Algorithm algo, ExtraInfo exInfo, uint8_t subject)
{
    int32_t ret;

    if (algo == AES) {
        KeyPurpose keyPurpose = subject == SUBJECT_MASTER_CONTROLLER ? KEY_PURPOSE_MAC : KEY_PURPOSE_DERIVE;
        ret = GetLoaderInstance()->importSymmetricKey(&keyParams, keyValue, keyPurpose, &exInfo);
    } else {
        ret = GetLoaderInstance()->importPublicKey(&keyParams, keyValue, algo, &exInfo);
    }

    if (ret == HAL_ERR_HUKS) {
        LOGE("Huks import key failed!");
        return IS_ERR_HUKS_IMPORT_KEY_FAILED;
    }
    if (ret != IS_SUCCESS) {
        LOGE("Failed to import key pair!");
        return ret;
    }
    LOGI("Import key pair success!");
    return IS_SUCCESS;
}

int32_t AddKeyValueToHuks(int32_t osAccountId, Uint8Buff *credIdByte, Credential *credential, uint8_t method,
    Uint8Buff *keyValue)
{
    if (credential->credType == ACCOUNT_SHARED && keyValue->val == NULL) {
        return IS_SUCCESS;
    }
    KeyParams keyParams = { { credIdByte->val, credIdByte->length, true }, false, osAccountId };
    int32_t authId = 0;
    Uint8Buff authIdBuff = { (uint8_t *)&authId, sizeof(int32_t) };
    ExtraInfo exInfo = { authIdBuff, DEFAULT_EX_INFO_VAL, DEFAULT_EX_INFO_VAL };
    Algorithm algo = GetAlgoFromCred(credential->algorithmType);
    switch (method) {
        case METHOD_GENERATE:
            return GenerateKeyValue(osAccountId, credential, keyParams, algo, exInfo);
        case METHOD_IMPORT:
            return ImportKeyValue(keyParams, keyValue, algo, exInfo, credential->subject);
        default:
            return IS_ERR_INVALID_PARAMS;
    }
}

int32_t GetValidKeyAlias(int32_t osAccountId, const char *credId, Uint8Buff *credIdHashBuff)
{
    uint32_t credIdByteLen = HcStrlen(credId) / BYTE_TO_HEX_OPER_LENGTH;
    Uint8Buff returnCredIdByte = { NULL, credIdByteLen };
    returnCredIdByte.val = (uint8_t *)HcMalloc(credIdByteLen, 0);
    if (returnCredIdByte.val == NULL) {
        LOGE("Failed to malloc credIdByteLen");
        return IS_ERR_ALLOC_MEMORY;
    }
    int32_t ret = HexStringToByte(credId, returnCredIdByte.val, returnCredIdByte.length);
    if (ret != IS_SUCCESS) {
        LOGE("Failed to convert credId to byte, invalid credId, ret = %" LOG_PUB "d", ret);
        HcFree(returnCredIdByte.val);
        return IS_ERR_INVALID_HEX_STRING;
    }

    ret = GetLoaderInstance()->checkKeyExist(&returnCredIdByte, false, osAccountId);
    if (ret != IS_SUCCESS) {
        HcFree(returnCredIdByte.val);
        return ret;
    }
    credIdHashBuff->val = returnCredIdByte.val;
    credIdHashBuff->length = credIdByteLen;
    return IS_SUCCESS;
}

int32_t AddCredAndSaveDb(int32_t osAccountId, Credential *credential)
{
    int32_t ret = AddCredToDb(osAccountId, credential);
    if (ret != IS_SUCCESS) {
        LOGE("Failed to add credential to database");
        return ret;
    }
    ret = SaveOsAccountCredDb(osAccountId);
    if (ret != IS_SUCCESS) {
        LOGE("Failed to save CredDb, ret: %" LOG_PUB "d", ret);
        return ret;
    }
    return IS_SUCCESS;
}


static bool IsValueInArray(uint8_t value, uint8_t *array, uint32_t length)
{
    for (uint32_t i = 0; i < length; i++) {
        if (array[i] == value) {
            return true;
        }
    }
    return false;
}

static int32_t SetVectorFromList(StringVector *dataVector, CJson *dataList)
{
    int32_t dataListNum = GetItemNum(dataList);
    for (int32_t i = 0; i < dataListNum; i++) {
        CJson *item = GetItemFromArray(dataList, i);
        if (item == NULL) {
            LOGE("item is null.");
            return IS_ERR_JSON_GET;
        }
        const char *data = GetStringValue(item);
        if (data == NULL) {
            LOGE("the data of list is null.");
            return IS_ERR_JSON_GET;
        }
        HcString strData = CreateString();
        if (!StringSetPointer(&strData, data)) {
            LOGE("Failed to set strData!");
            DeleteString(&strData);
            return IS_ERR_MEMORY_COPY;
        }
        if (dataVector->pushBackT(dataVector, strData) == NULL) {
            LOGE("Failed to push strData to vector!");
            DeleteString(&strData);
            return IS_ERR_MEMORY_COPY;
        }
    }
    return IS_SUCCESS;
}

static int32_t SetMethodFromJson(CJson *json, uint8_t *method)
{
    int32_t methodInt32 = DEFAULT_VAL;
    if (GetIntFromJson(json, FIELD_METHOD, &methodInt32) != IS_SUCCESS) {
        LOGE("Failed to get method from credReqParam");
        return IS_ERR_JSON_GET;
    }
    *method = (uint8_t)methodInt32;

    uint8_t methodRange[] = { METHOD_GENERATE, METHOD_IMPORT };
    uint32_t length = sizeof(methodRange) / sizeof(methodRange[0]);
    if (!IsValueInArray(*method, methodRange, length)) {
        LOGE("method is invalid.");
        return IS_ERR_INVALID_PARAMS;
    }
    return IS_SUCCESS;
}

static int32_t SetCredType(Credential *credential, CJson *json)
{
    if (GetUint8FromJson(json, FIELD_CRED_TYPE, &credential->credType) != IS_SUCCESS) {
        LOGE("Failed to get credential type from credReqParam");
        return IS_ERR_JSON_GET;
    }

    uint8_t credTypeRange[] = { ACCOUNT_RELATED, ACCOUNT_UNRELATED, ACCOUNT_SHARED };
    uint32_t length = sizeof(credTypeRange) / sizeof(credTypeRange[0]);
    if (!IsValueInArray(credential->credType, credTypeRange, length)) {
        LOGE("credential type is invalid.");
        return IS_ERR_INVALID_PARAMS;
    }
    return IS_SUCCESS;
}

static int32_t SetKeyFormat(Credential *credential, CJson *json, uint8_t method)
{
    if (GetUint8FromJson(json, FIELD_KEY_FORMAT, &credential->keyFormat) != IS_SUCCESS) {
        LOGE("Failed to get key format from credReqParam");
        return IS_ERR_JSON_GET;
    }
    uint8_t keyFormatRange[] = { SYMMETRIC_KEY, ASYMMETRIC_PUB_KEY, ASYMMETRIC_KEY, X509_CERT};
    uint32_t length = sizeof(keyFormatRange) / sizeof(keyFormatRange[0]);
    if (!IsValueInArray(credential->keyFormat, keyFormatRange, length)) {
        LOGE("key format is invalid.");
        return IS_ERR_INVALID_PARAMS;
    }
    if (credential->keyFormat == SYMMETRIC_KEY && method != METHOD_IMPORT) {
        LOGE("Symmetric key is only supported for import");
        return IS_ERR_INVALID_PARAMS;
    }
    if (credential->keyFormat == ASYMMETRIC_PUB_KEY && method != METHOD_IMPORT) {
        LOGE("Asymmetric public key is only supported for import");
        return IS_ERR_INVALID_PARAMS;
    }
    if (credential->keyFormat == ASYMMETRIC_KEY && method != METHOD_GENERATE) {
        LOGE("Asymmetric key is only supported for generate");
        return IS_ERR_INVALID_PARAMS;
    }
    return IS_SUCCESS;
}

static int32_t SetAuthorizedScope(Credential *credential, CJson *json)
{
    if (GetUint8FromJson(json, FIELD_AUTHORIZED_SCOPE, &credential->authorizedScope) != IS_SUCCESS) {
        LOGE("Failed to get authorizedScope from credReqParam");
        return IS_ERR_JSON_GET;
    }
    uint8_t scopeRange[] = { SCOPE_DEVICE, SCOPE_USER, SCOPE_APP };
    uint32_t length = sizeof(scopeRange) / sizeof(scopeRange[0]);
    if (!IsValueInArray(credential->authorizedScope, scopeRange, length)) {
        LOGE("Invalid authorizedScope");
        return IS_ERR_INVALID_PARAMS;
    }
    return IS_SUCCESS;
}

static int32_t SetAlgorithmType(Credential *credential, CJson *json)
{
    if (GetUint8FromJson(json, FIELD_ALGORITHM_TYPE, &credential->algorithmType) != IS_SUCCESS) {
        LOGE("Failed to get algorithm type from credReqParam");
        return IS_ERR_JSON_GET;
    }
    uint8_t algorithmTypeRange[] = { ALGO_TYPE_AES_256, ALGO_TYPE_P256, ALGO_TYPE_ED25519 };
    uint32_t length = sizeof(algorithmTypeRange) / sizeof(algorithmTypeRange[0]);
    if (!IsValueInArray(credential->algorithmType, algorithmTypeRange, length)) {
        LOGE("Invalid algorithm type");
        return IS_ERR_INVALID_PARAMS;
    }
    return IS_SUCCESS;
}

static int32_t SetSubject(Credential *credential, CJson *json)
{
    if (GetUint8FromJson(json, FIELD_SUBJECT, &credential->subject) != IS_SUCCESS) {
        LOGE("Failed to get subject from credReqParam");
        return IS_ERR_JSON_GET;
    }
    uint8_t subjectRange[] = { SUBJECT_MASTER_CONTROLLER, SUBJECT_ACCESSORY_DEVICE };
    uint32_t length = sizeof(subjectRange) / sizeof(subjectRange[0]);
    if (!IsValueInArray(credential->subject, subjectRange, length)) {
        LOGE("Invalid subject");
        return IS_ERR_INVALID_PARAMS;
    }
    return IS_SUCCESS;
}

static int32_t SetIssuer(Credential *credential, CJson *json)
{
    if (GetUint8FromJson(json, FIELD_ISSUER, &credential->issuer) != IS_SUCCESS) {
        LOGW("Failed to get issuer from credReqParam");
    }
    if (credential->credType == ACCOUNT_UNRELATED) {
        return IS_SUCCESS;
    }
    uint8_t issuerRange[] = { SYSTEM_ACCOUNT, APP_ACCOUNT, DOMANIN_ACCOUNT };
    uint32_t length = sizeof(issuerRange) / sizeof(issuerRange[0]);
    if (credential->issuer == DEFAULT_VAL || !IsValueInArray(credential->issuer, issuerRange, length)) {
        LOGE("Invalid issuer");
        return IS_ERR_INVALID_PARAMS;
    }
    return IS_SUCCESS;
}

static int32_t SetDeviceId(Credential *credential, CJson *json)
{
    const char *deviceId = GetStringFromJson(json, FIELD_DEVICE_ID);
    if (deviceId == NULL || strcmp(deviceId, "") == 0) {
        LOGE("Failed to get deviceId from credReqParam");
        return IS_ERR_JSON_GET;
    }
    if (!StringSetPointer(&credential->deviceId, deviceId)) {
        LOGE("Failed to set deviceId");
        return IS_ERR_MEMORY_COPY;
    }
    return IS_SUCCESS;
}

static int32_t SetCredOwner(Credential *credential, CJson *json)
{
    const char *credOwner = GetStringFromJson(json, FIELD_CRED_OWNER);
    if (credOwner == NULL || strcmp(credOwner, "") == 0) {
        LOGE("Failed to get credOwner from credReqParam");
        return IS_ERR_JSON_GET;
    }
    if (!StringSetPointer(&credential->credOwner, credOwner)) {
        LOGE("Failed to set credOwner");
        return IS_ERR_MEMORY_COPY;
    }
    return IS_SUCCESS;
}

static int32_t SetProofType(Credential *credential, CJson *json)
{
    if (GetUint8FromJson(json, FIELD_PROOF_TYPE, &credential->proofType) != IS_SUCCESS) {
        LOGE("Failed to get proofType from credReqParam");
        return IS_ERR_JSON_GET;
    }
    uint8_t proofTypeRange[] = { PROOF_TYPE_PSK, PROOF_TYPE_PKI };
    uint32_t length = sizeof(proofTypeRange) / sizeof(proofTypeRange[0]);
    if (!IsValueInArray(credential->proofType, proofTypeRange, length)) {
        LOGE("Invalid proofType");
        return IS_ERR_INVALID_PARAMS;
    }
    return IS_SUCCESS;
}

static int32_t SetUserId(Credential *credential, CJson *json)
{
    const char *userId = GetStringFromJson(json, FIELD_USER_ID);
    if (credential->credType == ACCOUNT_RELATED && (userId == NULL || strcmp(userId, "") == 0)) {
        LOGE("Invalid params, when credType is account, userId is NULL");
        return IS_ERR_INVALID_PARAMS;
    }
    if (userId == NULL) {
        return IS_SUCCESS;
    }
    if (!StringSetPointer(&credential->userId, userId)) {
        LOGW("Failed to set userId");
    }
    
    return IS_SUCCESS;
}

static int32_t SetKeyValueFromJson(CJson *json, Credential *credential, uint8_t method, Uint8Buff *keyValue)
{
    const char *keyValueStr = GetStringFromJson(json, FIELD_KEY_VALUE);
    if (credential->credType == ACCOUNT_SHARED && keyValueStr == NULL) {
        return IS_SUCCESS;
    }
    if (method == METHOD_GENERATE) {
        if (HcStrlen(keyValueStr) > 0) {
            LOGE("Invalid params, when method is generate, keyValue should not be passed in");
            return IS_ERR_KEYVALUE_METHOD_CONFLICT;
        }
        return IS_SUCCESS;
    }
    if (keyValueStr == NULL || HcStrlen(keyValueStr) <= 0) {
        LOGE("Invalid params, when method is imoprt, keyValue is NULL");
        return IS_ERR_INVALID_PARAMS;
    }
    uint32_t keyValueLen = HcStrlen(keyValueStr) / BYTE_TO_HEX_OPER_LENGTH;
    keyValue->length = keyValueLen;
    uint8_t *returnKeyVal = (uint8_t *)HcMalloc(keyValueLen, 0);
    if (returnKeyVal == NULL) {
        LOGE("Failed to malloc memory for keyValue");
        return IS_ERR_ALLOC_MEMORY;
    }
    if (GetByteFromJson(json, FIELD_KEY_VALUE, returnKeyVal, keyValue->length) != IS_SUCCESS) {
        LOGE("set keyValue fail.");
        HcFree(returnKeyVal);
        return IS_ERR_JSON_GET;
    }
    keyValue->val = returnKeyVal;
    return IS_SUCCESS;
}

static int32_t SetPeerUserSpaceId(Credential *credential, CJson *json, uint8_t method)
{
    const char *peerUserSpaceId = GetStringFromJson(json, FIELD_PEER_USER_SPACE_ID);
    if (credential->credType == ACCOUNT_UNRELATED && method == METHOD_IMPORT &&
        (peerUserSpaceId == NULL || strcmp(peerUserSpaceId, "") == 0)) {
        LOGE("Invalid params, when credType is not account and method is import, peer osaccount id is NULL");
        return IS_ERR_INVALID_PARAMS;
    }
    if (peerUserSpaceId == NULL) {
        return IS_SUCCESS;
    }
    if (!StringSetPointer(&credential->peerUserSpaceId, peerUserSpaceId)) {
        LOGW("Failed to set peerUserSpaceId");
    }
    return IS_SUCCESS;
}

static int32_t SetAppList(Credential *credential, CJson *json)
{
    CJson *appList = GetObjFromJson(json, FIELD_AUTHORIZED_APP_LIST);
    if (appList == NULL) {
        if (credential->authorizedScope == SCOPE_APP) {
            LOGE("when authorizedScope is APP, authorizedAppList is required");
            return IS_ERR_INVALID_PARAMS;
        }
        return IS_SUCCESS;
    }

    int32_t ret = SetVectorFromList(&credential->authorizedAppList, appList);
    if (ret != IS_SUCCESS) {
        LOGE("Failed to set authorized app list from credReqParam");
        return ret;
    }
    return IS_SUCCESS;
}

static int32_t SetExtendInfo(Credential *credential, CJson *json)
{
    const char *extendInfo = GetStringFromJson(json, FIELD_EXTEND_INFO);
    if (extendInfo == NULL || strcmp(extendInfo, "") == 0) {
        LOGW("Failed to get extendInfo from credReqParam");
    }
    if (extendInfo == NULL) {
        LOGW("Failed to get extendInfo from credReqParam");
        return IS_SUCCESS;
    }
    if (!StringSetPointer(&credential->extendInfo, extendInfo)) {
        LOGW("Failed to set extendInfo!");
    }
    return IS_SUCCESS;
}

static int32_t SetCredIdFromJson(Credential *credential, CJson *json)
{
    const char *credIdStr = GetStringFromJson(json, FIELD_CRED_ID);
    if (credIdStr == NULL || HcStrlen(credIdStr) == 0) {
        LOGI("No imported credId in credReqParam, credId will be generated by IS.");
        return IS_SUCCESS;
    }
    if (!StringSetPointer(&credential->credId, credIdStr)) {
        LOGE("Failed to set credId");
        return IS_ERR_ALLOC_MEMORY;
    }
    return IS_SUCCESS;
}

static int32_t SetRequiredField(Credential *credential, CJson *json, uint8_t *method)
{
    int32_t ret = SetMethodFromJson(json, method);
    if (ret != IS_SUCCESS) {
        return ret;
    }

    ret = SetCredType(credential, json);
    if (ret != IS_SUCCESS) {
        return ret;
    }

    ret = SetKeyFormat(credential, json, *method);
    if (ret != IS_SUCCESS) {
        return ret;
    }

    ret = SetAuthorizedScope(credential, json);
    if (ret != IS_SUCCESS) {
        return ret;
    }

    ret = SetAlgorithmType(credential, json);
    if (ret != IS_SUCCESS) {
        return ret;
    }

    ret = SetSubject(credential, json);
    if (ret != IS_SUCCESS) {
        return ret;
    }

    ret = SetDeviceId(credential, json);
    if (ret != IS_SUCCESS) {
        return ret;
    }

    ret = SetCredOwner(credential, json);
    if (ret != IS_SUCCESS) {
        return ret;
    }

    ret = SetProofType(credential, json);
    if (ret != IS_SUCCESS) {
        return ret;
    }
    credential->ownerUid = GetCallingUid();
    LOGI("UID: %" LOG_PUB "d", credential->ownerUid);
    return IS_SUCCESS;
}

static int32_t SetSpecialRequiredField(Credential *credential, CJson *json, uint8_t *method, Uint8Buff *keyValue)
{
    int32_t ret = SetUserId(credential, json);
    if (ret != IS_SUCCESS) {
        return ret;
    }

    ret = SetIssuer(credential, json);
    if (ret != IS_SUCCESS) {
        return ret;
    }

    ret = SetKeyValueFromJson(json, credential, *method, keyValue);
    if (ret != IS_SUCCESS) {
        return ret;
    }

    ret = SetPeerUserSpaceId(credential, json, *method);
    if (ret != IS_SUCCESS) {
        HcFree(keyValue->val);
        return ret;
    }

    ret = SetAppList(credential, json);
    if (ret != IS_SUCCESS) {
        HcFree(keyValue->val);
        return ret;
    }
    return IS_SUCCESS;
}

static int32_t SetOptionalField(Credential *credential, CJson *json)
{
    int32_t ret = SetExtendInfo(credential, json);
    if (ret != IS_SUCCESS) {
        return ret;
    }

    return SetCredIdFromJson(credential, json);
}

int32_t CheckAndSetCredInfo(int32_t osAccountId,
    Credential *credential, CJson *json, uint8_t *method, Uint8Buff *keyValue)
{
    int32_t ret = SetRequiredField(credential, json, method);
    if (ret != IS_SUCCESS) {
        return ret;
    }

    ret = SetSpecialRequiredField(credential, json, method, keyValue);
    if (ret != IS_SUCCESS) {
        return ret;
    }

    ret = SetOptionalField(credential, json);
    if (ret != IS_SUCCESS) {
        HcFree(keyValue->val);
        return ret;
    }

    ret = CheckOutMaxCredSize(osAccountId, StringGet(&credential->credOwner));
    if (ret != IS_SUCCESS) {
        HcFree(keyValue->val);
    }
    return ret;
}

int32_t SetQueryParamsFromJson(QueryCredentialParams *queryParams, CJson *json)
{
    queryParams->credId = GetStringFromJson(json, FIELD_CRED_ID);

    queryParams->deviceId = GetStringFromJson(json, FIELD_DEVICE_ID);

    queryParams->peerUserSpaceId = GetStringFromJson(json, FIELD_PEER_USER_SPACE_ID);

    if (GetUint8FromJson(json, FIELD_SUBJECT, &queryParams->subject) != IS_SUCCESS) {
        LOGW("Failed to set query params: subject");
    }

    queryParams->userId = GetStringFromJson(json, FIELD_USER_ID);

    if (GetUint8FromJson(json, FIELD_ISSUER, &queryParams->issuer) != IS_SUCCESS) {
        LOGW("Failed to set query params: issuer");
    }

    if (GetUint8FromJson(json, FIELD_CRED_TYPE, &queryParams->credType) != IS_SUCCESS) {
        LOGW("Failed to set query params: credType");
    }

    if (GetUint8FromJson(json, FIELD_KEY_FORMAT, &queryParams->keyFormat) != IS_SUCCESS) {
        LOGW("Failed to set query params: keyFormat");
    }

    if (GetUint8FromJson(json, FIELD_ALGORITHM_TYPE, &queryParams->algorithmType) != IS_SUCCESS) {
        LOGW("Failed to set query params: algorithmType");
    }

    if (GetUint8FromJson(json, FIELD_PROOF_TYPE, &queryParams->proofType) != IS_SUCCESS) {
        LOGW("Failed to set query params: proofType");
    }

    if (GetUint8FromJson(json, FIELD_AUTHORIZED_SCOPE, &queryParams->authorizedScope) != IS_SUCCESS) {
        LOGW("Failed to set query params: authorizedScope");
    }

    queryParams->credOwner = GetStringFromJson(json, FIELD_CRED_OWNER);

    return IS_SUCCESS;
}

static int32_t IsOriginalStrHashMatch(const char *originalStr, const char *subHashedStr)
{
    Uint8Buff originalStrBuffer = { (uint8_t *)originalStr, (uint32_t)HcStrlen(originalStr) };
    uint8_t hashedStrBytes[SHA256_LEN] = { 0 };
    Uint8Buff hashedStrBuffer = { hashedStrBytes, sizeof(hashedStrBytes) };
    int32_t result = GetLoaderInstance()->sha256(&originalStrBuffer, &hashedStrBuffer);
    if (result != IS_SUCCESS) {
        LOGE("sha256 failed, ret:%" LOG_PUB "d", result);
        return result;
    }
    uint32_t hashedStrHexLength = SHA256_LEN * BYTE_TO_HEX_OPER_LENGTH + 1;
    char *hashedStrHex = (char *)HcMalloc(hashedStrHexLength, 0);
    if (hashedStrHex == NULL) {
        LOGE("malloc hashedStrHex string failed");
        return IS_ERR_ALLOC_MEMORY;
    }
    result = ByteToHexString(hashedStrBytes, SHA256_LEN, hashedStrHex, hashedStrHexLength);
    if (result != IS_SUCCESS) {
        LOGE("Byte to hexString failed, ret:%" LOG_PUB "d", result);
        HcFree(hashedStrHex);
        return result;
    }
    char *upperSubHashedStr = NULL;
    result = ToUpperCase(subHashedStr, &upperSubHashedStr);
    if (result != IS_SUCCESS) {
        LOGE("Failed to convert the input sub hashed string to upper case!");
        HcFree(hashedStrHex);
        return result;
    }
    if (strstr((const char *)hashedStrHex, upperSubHashedStr) != NULL) {
        LOGI("Original string hash is match!");
        HcFree(hashedStrHex);
        HcFree(upperSubHashedStr);
        return IS_SUCCESS;
    }
    HcFree(hashedStrHex);
    HcFree(upperSubHashedStr);
    return IS_ERROR;
}

bool IsCredHashMatch(Credential *credential, CJson *reqJson)
{
    const char *deviceIdHash = GetStringFromJson(reqJson, FIELD_DEVICE_ID_HASH);
    if (deviceIdHash != NULL &&
        IsOriginalStrHashMatch(StringGet(&credential->deviceId), deviceIdHash) != IS_SUCCESS) {
        return false;
    }

    const char *userIdHash = GetStringFromJson(reqJson, FIELD_USER_ID_HASH);
    if (userIdHash != NULL &&
        IsOriginalStrHashMatch(StringGet(&credential->userId), userIdHash) != IS_SUCCESS) {
        return false;
    }

    return true;
}

static int32_t CheckCredKeyExist(int32_t osAccountId, const Credential *credential, const char *credId)
{
    // ACCOUNT_SHARED type dose not need check key
    if (credential->credType == ACCOUNT_SHARED) {
        return HC_SUCCESS;
    }
    uint32_t credIdByteLen = HcStrlen(credId) / BYTE_TO_HEX_OPER_LENGTH;
    Uint8Buff credIdByte = { NULL, credIdByteLen };
    credIdByte.val = (uint8_t *)HcMalloc(credIdByteLen, 0);
    if (credIdByte.val == NULL) {
        LOGE("Failed to malloc credIdByteLen");
        return IS_ERR_ALLOC_MEMORY;
    }
    int32_t ret = HexStringToByte(credId, credIdByte.val, credIdByte.length);
    if (ret != IS_SUCCESS) {
        LOGE("Failed to convert credId to byte, invalid credId, ret = %" LOG_PUB "d", ret);
        HcFree(credIdByte.val);
        return IS_ERR_INVALID_HEX_STRING;
    }
    ret = GetLoaderInstance()->checkKeyExist(&credIdByte, false, osAccountId);
    HcFree(credIdByte.val);
    switch (ret) {
        // delete invaild credId
        case HAL_ERR_KEY_NOT_EXIST:
            LOGE("Huks key not exist!");
            DelCredById(osAccountId, credId);
            break;
        case HAL_ERR_HUKS:
            LOGE("Failed to check key exist in huks");
            break;
        case IS_SUCCESS:
            break;
        default:
            LOGE("CheckKeyExist failed");
            break;
    }
    return ret;
}

int32_t GetCredIdsFromCredVec(int32_t osAccountId, CJson *reqJson, CredentialVec *credentialVec, CJson *credIdJson)
{
    uint32_t index;
    int32_t ret;
    Credential **ptr;
    FOR_EACH_HC_VECTOR(*credentialVec, index, ptr) {
        if (*ptr == NULL) {
            continue;
        }
        Credential *credential = (Credential *)(*ptr);
        const char *credId = StringGet(&credential->credId);
        if (CheckCredKeyExist(osAccountId, credential, credId) != IS_SUCCESS) {
            LOGE("CredKey not Exist!");
            continue;
        }
        if (!IsCredHashMatch(credential, reqJson)) {
            continue;
        }

        ret = AddStringToArray(credIdJson, credId);
        if (ret != IS_SUCCESS) {
            LOGE("Failed to add credId to json");
            return IS_ERR_JSON_ADD;
        }
    }

    return IS_SUCCESS;
}

static int32_t UpdateExtendInfo(Credential *credential, const char *extendInfo)
{
    if (!StringSetPointer(&credential->extendInfo, extendInfo)) {
        LOGE("Failed to update extendInfo");
        return IS_ERR_MEMORY_COPY;
    }
    return IS_SUCCESS;
}

static int32_t UpdateAppList(Credential *credential, CJson *appList)
{
    DestroyStrVector(&credential->authorizedAppList);
    credential->authorizedAppList = CreateStrVector();
    int32_t ret = SetVectorFromList(&credential->authorizedAppList, appList);
    if (ret != IS_SUCCESS) {
        LOGE("Failed to update authorizedAppList");
        return ret;
    }
    return IS_SUCCESS;
}

int32_t UpdateInfoFromJson(Credential *credential, CJson *json)
{
    const char *extendInfo = GetStringFromJson(json, FIELD_EXTEND_INFO);
    CJson *appList = GetObjFromJson(json, FIELD_AUTHORIZED_APP_LIST);

    if (extendInfo == NULL && appList == NULL) {
        LOGE("Failed to set update info: no valid field");
        return IS_ERR_INVALID_PARAMS;
    }

    int32_t ret;

    if (extendInfo != NULL) {
        ret = UpdateExtendInfo(credential, extendInfo);
        if (ret != IS_SUCCESS) {
            return ret;
        }
    }

    if (appList != NULL) {
        ret = UpdateAppList(credential, appList);
    }

    return ret;
}

int32_t DelCredById(int32_t osAccountId, const char *credId)
{
    QueryCredentialParams delParams = InitQueryCredentialParams();
    delParams.credId = credId;
    int32_t ret = DelCredential(osAccountId, &delParams);
    if (ret != IS_SUCCESS) {
        LOGE("Failed to delete credential, ret: %" LOG_PUB "d", ret);
        return ret;
    }
    ret = SaveOsAccountCredDb(osAccountId);
    if (ret != IS_SUCCESS) {
        LOGE("Failed to save CredDb, ret: %" LOG_PUB "d", ret);
        return ret;
    }
    return IS_SUCCESS;
}

int32_t AddKeyValueToReturn(Uint8Buff keyValue, char **returnData)
{
    CJson *keyValueJson = CreateJson();
    if (keyValueJson == NULL) {
        LOGE("Failed to create keyValueJson");
        return IS_ERR_JSON_CREATE;
    }
    int32_t ret = AddByteToJson(keyValueJson, FIELD_KEY_VALUE, keyValue.val, keyValue.length);
    if (ret != IS_SUCCESS) {
        LOGE("Failed to add key value to json");
        FreeJson(keyValueJson);
        return IS_ERR_JSON_ADD;
    }
    *returnData = PackJsonToString(keyValueJson);
    FreeJson(keyValueJson);
    if (*returnData == NULL) {
        LOGE("Failed to pack key value json to string");
        return IS_ERR_PACKAGE_JSON_TO_STRING_FAIL;
    }
    return IS_SUCCESS;
}

int32_t GenerateReturnEmptyArrayStr(char **returnVec)
{
    CJson *json = CreateJsonArray();
    if (json == NULL) {
        LOGE("Failed to allocate json memory!");
        return IS_ERR_JSON_CREATE;
    }
    *returnVec = PackJsonToString(json);
    FreeJson(json);
    if (*returnVec == NULL) {
        LOGE("Failed to convert json to string!");
        return IS_ERR_PACKAGE_JSON_TO_STRING_FAIL;
    }
    return IS_SUCCESS;
}

int32_t CheckOwnerUidPermission(Credential *credential)
{
    int32_t currentUid = GetCallingUid();
    if (currentUid != credential->ownerUid) {
        LOGE("currentUid is not the same as the ownerUid of the credential");
        return IS_ERR_OWNER_UID;
    }
    return IS_SUCCESS;
}

int32_t GenerateCredKeyAlias(const char *credId, const char *deviceId, Uint8Buff *alias)
{
    if ((credId == NULL) || (deviceId == NULL) || (alias == NULL)) {
        LOGE("Invalid input params");
        return IS_ERR_NULL_PTR;
    }
    uint32_t credIdLen = HcStrlen(credId);
    uint32_t deviceIdLen = HcStrlen(deviceId);
    uint32_t aliasStrLen = credIdLen + deviceIdLen + 1;
    uint8_t *aliasStr = (uint8_t *)HcMalloc(aliasStrLen, 0);
    if (aliasStr == NULL) {
        LOGE("Failed to malloc for key aliasStr.");
        return IS_ERR_ALLOC_MEMORY;
    }
    Uint8Buff aliasBuff = {
        aliasStr,
        aliasStrLen
    };
    if (memcpy_s(aliasBuff.val, aliasBuff.length, credId, credIdLen) != EOK) {
        LOGE("Failed to copy credId.");
        HcFree(aliasStr);
        return IS_ERR_MEMORY_COPY;
    }
    if (memcpy_s(aliasBuff.val + credIdLen, deviceIdLen,
        deviceId, deviceIdLen) != EOK) {
        LOGE("Failed to copy deviceId.");
        HcFree(aliasStr);
        return IS_ERR_MEMORY_COPY;
    }
    int32_t ret = GetLoaderInstance()->sha256(&aliasBuff, alias);
    HcFree(aliasStr);
    if (ret != HAL_SUCCESS) {
        LOGE("Compute alias failed");
    }
    return ret;
}

static int32_t ComputeAndSavePskInner(int32_t osAccountId, uint8_t credAlgo, const Uint8Buff *selfKeyAlias,
    const Uint8Buff *peerKeyAlias, Uint8Buff *sharedKeyAlias)
{
    KeyParams selfKeyParams = { { selfKeyAlias->val, selfKeyAlias->length, true }, false, osAccountId };
    uint8_t peerPubKeyVal[KEY_VALUE_MAX_LENGTH] = { 0 };
    Uint8Buff peerPubKeyBuff = { peerPubKeyVal, KEY_VALUE_MAX_LENGTH };
    KeyParams keyParams = { { peerKeyAlias->val, peerKeyAlias->length, true }, false, osAccountId };
    int32_t res = GetLoaderInstance()->exportPublicKey(&keyParams, &peerPubKeyBuff);
    if (res != IS_SUCCESS) {
        LOGE("Failed to export peer public key!");
        return res;
    }
    KeyBuff peerKeyBuff = { peerPubKeyBuff.val, peerPubKeyBuff.length, false };
    Algorithm algo = GetAlgoFromCred(credAlgo);
    res = GetLoaderInstance()->agreeSharedSecretWithStorage(&selfKeyParams, &peerKeyBuff, algo,
        PSK_LEN, sharedKeyAlias);
    if (res != IS_SUCCESS) {
        LOGE("Agree psk failed.");
    }
    return res;
}

int32_t SetAgreeCredInfo(int32_t osAccountId, CJson *reqJson,
    Credential *agreeCredential, Uint8Buff *keyValue, Uint8Buff *agreeCredIdByte)
{
    if (AddIntToJson(reqJson, FIELD_METHOD, METHOD_IMPORT) != IS_SUCCESS) {
        LOGE("Failed to add method to json!");
        return IS_ERR_JSON_ADD;
    }
    uint8_t method = DEFAULT_VAL;
    int32_t ret = CheckAndSetCredInfo(osAccountId, agreeCredential, reqJson, &method, keyValue);
    if (ret != IS_SUCCESS) {
        return ret;
    }
    if ((ret = GenerateCredId(osAccountId, agreeCredential, agreeCredIdByte)) != IS_SUCCESS) {
        HcFree(keyValue->val);
        return ret;
    }
    return IS_SUCCESS;
}

int32_t ImportAgreeKeyValue(int32_t osAccountId, Credential *agreeCredential, Uint8Buff *keyValue,
    Uint8Buff *peerKeyAlias)
{
    int32_t ret = GenerateCredKeyAlias(
        StringGet(&agreeCredential->credId), StringGet(&agreeCredential->deviceId), peerKeyAlias);
    if (ret != IS_SUCCESS) {
        LOGE("Failed to generate peer key alias!");
        return ret;
    }
    ret = AddKeyValueToHuks(osAccountId, peerKeyAlias, agreeCredential, METHOD_IMPORT, keyValue);
    if (ret != IS_SUCCESS) {
        LOGE("Failed to add peer key value to huks!");
        return ret;
    }
    return IS_SUCCESS;
}

int32_t CheckAndDelInvalidCred(int32_t osAccountId, const char *selfCredId, Uint8Buff *selfCredIdByte)
{
    int32_t ret = GetValidKeyAlias(osAccountId, selfCredId, selfCredIdByte);
    if (ret == HAL_ERR_KEY_NOT_EXIST) {
        LOGE("Huks key not exist!");
        DelCredById(osAccountId, selfCredId);
        return IS_ERR_HUKS_KEY_NOT_EXIST;
    }
    if (ret == HAL_ERR_HUKS) {
        LOGE("Huks check key exist failed");
        return IS_ERR_HUKS_CHECK_KEY_EXIST_FAILED;
    }
    if (ret != IS_SUCCESS) {
        LOGE("Failed to check key exist in HUKS");
        return ret;
    }
    return IS_SUCCESS;
}

int32_t ComputePskAndDelInvalidKey(int32_t osAccountId, uint8_t credAlgo, Uint8Buff *selfCredIdByte,
    Uint8Buff *peerKeyAlias, Uint8Buff *agreeCredIdByte)
{
    int32_t ret = ComputeAndSavePskInner(osAccountId, credAlgo, selfCredIdByte, peerKeyAlias, agreeCredIdByte);
    if (ret != IS_SUCCESS) {
        LOGE("Failed to compute and save psk!");
        return ret;
    }
    ret = GetLoaderInstance()->deleteKey(peerKeyAlias, false, osAccountId);
    if (ret != IS_SUCCESS) {
        LOGE("Failed to delete key from HUKS");
        return ret;
    }
    return IS_SUCCESS;
}

int32_t SetRequiredParamsFromJson(QueryCredentialParams *queryParams, CJson *baseInfoJson)
{
    if (GetUint8FromJson(baseInfoJson, FIELD_CRED_TYPE, &(queryParams->credType)) != IS_SUCCESS) {
        LOGE("Failed to set query params: credType");
        return IS_ERR_JSON_GET;
    }
    if (queryParams->credType != ACCOUNT_SHARED) {
        LOGE("Not support for credType %" LOG_PUB "d, only support for ACCOUNT_SHARED", queryParams->credType);
        return IS_ERR_NOT_SUPPORT;
    }
    const char *credOwner = GetStringFromJson(baseInfoJson, FIELD_CRED_OWNER);
    if (credOwner == NULL || strcmp(credOwner, "") == 0) {
        LOGE("Failed to set query params: credOwner");
        return IS_ERR_JSON_GET;
    }
    queryParams->credOwner = credOwner;
    return IS_SUCCESS;
}

int32_t SetUpdateToQueryParams(CJson *json, QueryCredentialParams *queryParams)
{
    const char *userId = GetStringFromJson(json, FIELD_USER_ID);
    if (userId == NULL || strcmp(userId, "") == 0) {
        LOGE("Failed to set query params: userId");
        return IS_ERR_JSON_GET;
    }
    queryParams->userId = userId;
    const char *deviceId = GetStringFromJson(json, FIELD_DEVICE_ID);
    if (deviceId == NULL || strcmp(deviceId, "") == 0) {
        LOGE("Failed to set query params: deviceId");
        return IS_ERR_JSON_GET;
    }
    queryParams->deviceId = deviceId;
    return IS_SUCCESS;
}

static int32_t EraseCredIdInVec(const char *credId, CredentialVec *credVec)
{
    uint32_t index = 0;
    Credential **item;
    while (index < credVec->size(credVec)) {
        item = credVec->getp(credVec, index);
        if (item == NULL || *item == NULL) {
            index++;
            continue;
        }
        const char *itemCredId = StringGet(&(*item)->credId);
        if (itemCredId != NULL && strcmp(credId, itemCredId) == 0) {
            credVec->eraseElement(credVec, item, index);
            return IS_SUCCESS;
        }
        index++;
    }
    return IS_ERROR;
}

int32_t AddUpdateInfoToJson(QueryCredentialParams *queryParams, CJson *baseInfoJson)
{
    if (AddStringToJson(baseInfoJson, FIELD_USER_ID, queryParams->userId) != IS_SUCCESS) {
        LOGE("add userId to baseInfoJson fail.");
        return IS_ERR_JSON_ADD;
    }
    if (AddStringToJson(baseInfoJson, FIELD_DEVICE_ID, queryParams->deviceId) != IS_SUCCESS) {
        LOGE("add deviceId to baseInfoJson fail.");
        return IS_ERR_JSON_ADD;
    }
    if (AddIntToJson(baseInfoJson, FIELD_METHOD, METHOD_IMPORT) != IS_SUCCESS) {
        LOGE("Failed to add method to baseInfoJson!");
        return IS_ERR_JSON_ADD;
    }
    return IS_SUCCESS;
}

int32_t EraseUpdateCredIdInSelfVec(CredentialVec *updateCredVec, CredentialVec *selfCredVec)
{
    Credential **cred = updateCredVec->getp(updateCredVec, 0);
    if (cred == NULL || *cred == NULL) {
        LOGE("Failed to get first cred");
        return IS_ERR_NULL_PTR;
    }
    const char *updateCredId = StringGet(&(*cred)->credId);
    if (updateCredId == NULL) {
        LOGE("Failed to get updateCredId");
        return IS_ERR_NULL_PTR;
    }
    return EraseCredIdInVec(updateCredId, selfCredVec);
}

int32_t GetQueryJsonStr(CJson *baseInfoJson, char **queryJsonStr)
{
    const char *credOwner = GetStringFromJson(baseInfoJson, FIELD_CRED_OWNER);
    if (credOwner == NULL) {
        LOGE("Failed to get credOwner");
        return IS_ERR_INVALID_PARAMS;
    }
    CJson *queryJson = CreateJson();
    if (queryJson == NULL) {
        LOGE("Failed to create queryJson");
        return IS_ERR_JSON_CREATE;
    }
    if (AddStringToJson(queryJson, FIELD_CRED_OWNER, credOwner)) {
        FreeJson(queryJson);
        return IS_ERR_JSON_ADD;
    }
    *queryJsonStr = PackJsonToString(queryJson);
    FreeJson(queryJson);
    if (*queryJsonStr == NULL) {
        LOGE("Failed to pack queryJson to string");
        return IS_ERR_PACKAGE_JSON_TO_STRING_FAIL;
    }
    return IS_SUCCESS;
}

int32_t GetUpdateCredVec(int32_t osAccountId, CJson *updateInfo,
    QueryCredentialParams *queryParams, CredentialVec *updateCredVec)
{
    int32_t ret = SetUpdateToQueryParams(updateInfo, queryParams);
    if (ret != IS_SUCCESS) {
        LOGE("Failed to set updateLists to query params");
        return ret;
    }
    return QueryCredentials(osAccountId, queryParams, updateCredVec);
}
