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

#ifdef DEV_AUTH_PERMISSION_ENABLE
#include "permission_adapter.h"
#endif

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

static int32_t int64ToString(int64_t num, char **result)
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
    int32_t ret = int64ToString(HcGetCurTimeInMillis(), &timeStr);
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
        LOGE("Failed to sha256 credId, ret = %d", ret);
        HcFree(returnCredIdByte.val);
        return ret;
    }

    char *returnCredIdStr = NULL;
    ret = Uint8BuffToString(&returnCredIdByte, &returnCredIdStr);
    if (ret != IS_SUCCESS) {
        LOGE("Failed to convert credIdByte to credIdStr, ret = %d", ret);
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

static bool isCredIdExist(int32_t osAccountId, const char *credIdStr)
{
    Credential *existedCredential = NULL;
    int32_t ret = GetCredentialById(osAccountId, credIdStr, &existedCredential);
    DestroyCredential(existedCredential);

    return ret == IS_SUCCESS;
}

static int32_t UseImportedCredId(int32_t osAccountId, Credential *credential, Uint8Buff *credIdByte)
{
    if (isCredIdExist(osAccountId, StringGet(&credential->credId))) {
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
        LOGE("Failed to convert credId to byte, ret = %d", ret);
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
    if (isCredIdExist(osAccountId, returnCredId)) {
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
    LOGI("The number of credentials for this credOwner is within the limit");
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
    uint32_t keyLen = (credential->algorithmType == ALGO_TYPE_AES_128) ? AES_128_KEY_LEN : SELE_ECC_KEY_LEN;
    KeyPurpose purpose = (credential->algorithmType == ALGO_TYPE_ED25519) ?
        KEY_PURPOSE_SIGN_VERIFY : KEY_PURPOSE_KEY_AGREE;
    int32_t ret = GetLoaderInstance()->generateKeyPairWithStorage(&keyParams, keyLen, algo, purpose, &exInfo);
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

static int32_t ImportKeyValue(KeyParams keyParams, Uint8Buff keyValue, Algorithm algo, ExtraInfo exInfo)
{
    int32_t ret = GetLoaderInstance()->importPublicKey(&keyParams, &keyValue, algo, &exInfo);
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

int32_t AddKeyValueToHuks(int32_t osAccountId, Uint8Buff credIdByte, Credential *credential, uint8_t method,
    Uint8Buff keyValue)
{
    int32_t ret;
    KeyParams keyParams = { { credIdByte.val, credIdByte.length, true }, false, osAccountId };
    int32_t authId = 0;
    Uint8Buff authIdBuff = { (uint8_t *)&authId, sizeof(int32_t) };
    ExtraInfo exInfo = { authIdBuff, DEFAULT_EX_INFO_VAL, DEFAULT_EX_INFO_VAL };
    Algorithm algo = GetAlgoFromCred(credential->algorithmType);
    
    if (method == METHOD_GENERATE) {
        ret = GenerateKeyValue(osAccountId, credential, keyParams, algo, exInfo);
        if (ret != IS_SUCCESS) {
            return ret;
        }
    }
    if (method == METHOD_IMPORT) {
        ret = ImportKeyValue(keyParams, keyValue, algo, exInfo);
        if (ret != IS_SUCCESS) {
            return ret;
        }
    }
    return IS_SUCCESS;
}

int32_t CheckCredIdExistInHuks(int32_t osAccountId, const char *credId, Uint8Buff *credIdHashBuff)
{
    int32_t ret = HexStringToByte(credId, credIdHashBuff->val, credIdHashBuff->length);
    if (ret != IS_SUCCESS) {
        LOGE("Failed to convert credId to byte, invalid credId, ret = %d", ret);
        return IS_ERR_INVALID_HEX_STRING;
    }

    return GetLoaderInstance()->checkKeyExist(credIdHashBuff, false, osAccountId);
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
        LOGE("Failed to save CredDb, ret: %d", ret);
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

static int32_t SetAccListFromArray(Credential *credential, CJson *accountList)
{
    int32_t accountListNum = GetItemNum(accountList);
    for (int32_t i = 0; i < accountListNum; i++) {
        CJson *item = GetItemFromArray(accountList, i);
        if (item == NULL) {
            LOGE("item is null.");
            return IS_ERR_JSON_GET;
        }
        const char *account = GetStringValue(item);
        if (account == NULL) {
            LOGE("account is null.");
            return IS_ERR_JSON_GET;
        }
        HcString strAcc = CreateString();
        if (!StringSetPointer(&strAcc, account)) {
            LOGE("Failed to set strAcc!");
            DeleteString(&strAcc);
            return IS_ERR_MEMORY_COPY;
        }
        if (credential->authorizedAccountList.pushBackT(&credential->authorizedAccountList, strAcc) == NULL) {
            LOGE("Failed to push strAcc!");
            DeleteString(&strAcc);
            return IS_ERR_MEMORY_COPY;
        }
    }
    return IS_SUCCESS;
}

static int32_t SetMethodFromJson(CJson *json, uint8_t *method)
{
    if (GetUint8FromJson(json, FIELD_METHOD, method) != IS_SUCCESS) {
        LOGE("Failed to get method from credReqParam");
        return IS_ERR_JSON_GET;
    }

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

    uint8_t credTypeRange[] = { ACCOUNTT_RELATED, ACCOUNTT_UNRELATED };
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
    uint8_t algorithmTypeRange[] = { ALGO_TYPE_P256, ALGO_TYPE_ED25519 };
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
    uint8_t subjectRange[] = { SELF_DEVICE, OTHER_DEVICE };
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
    if (credential->credType == ACCOUNTT_UNRELATED) {
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
    if (credential->credType == ACCOUNTT_RELATED && (userId == NULL || strcmp(userId, "") == 0)) {
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

static int32_t SetKeyValueFromJson(CJson *json, uint8_t method, Uint8Buff *keyValue)
{
    if (method == METHOD_GENERATE) {
        return IS_SUCCESS;
    }
    const char *keyValueStr = GetStringFromJson(json, FIELD_KEY_VALUE);
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
    if (credential->credType == ACCOUNTT_UNRELATED && method == METHOD_IMPORT &&
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

static int32_t SetAccList(Credential *credential, CJson *json)
{
    CJson *accountList = GetObjFromJson(json, FIELD_AUTHORIZED_ACCOUNT_LIST);

    if (accountList == NULL) {
        LOGW("Failed to get authorized account list from credReqParam");
        return IS_SUCCESS;
    }

    int32_t ret = SetAccListFromArray(credential, accountList);
    if (ret != IS_SUCCESS) {
        LOGE("Failed to set authorized account list from credReqParam");
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
    if (ret != HC_SUCCESS) {
        return ret;
    }

    ret = SetProofType(credential, json);
    if (ret != IS_SUCCESS) {
        return ret;
    }
#ifdef DEV_AUTH_PERMISSION_ENABLE
    credential->ownerUid = GetCallingUid();
    LOGI("UID: %d", credential->ownerUid);
#endif
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

    ret = SetKeyValueFromJson(json, *method, keyValue);
    if (ret != IS_SUCCESS) {
        return ret;
    }

    ret = SetPeerUserSpaceId(credential, json, *method);
    if (ret != IS_SUCCESS) {
        return ret;
    }
    return IS_SUCCESS;
}

static int32_t SetOptionalField(Credential *credential, CJson *json)
{
    int32_t ret = SetAccList(credential, json);
    if (ret != IS_SUCCESS) {
        return ret;
    }

    ret = SetExtendInfo(credential, json);
    if (ret != IS_SUCCESS) {
        return ret;
    }

    ret = SetCredIdFromJson(credential, json);
    if (ret != IS_SUCCESS) {
        return ret;
    }

    return IS_SUCCESS;
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
        return ret;
    }

    ret = CheckOutMaxCredSize(osAccountId, StringGet(&credential->credOwner));

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

int32_t GetCredIdsFromCredVec(CredentialVec credentialVec, CJson *credIdJson, int32_t osAccountId)
{
    uint32_t index;
    int32_t ret;
    Credential **ptr;
    FOR_EACH_HC_VECTOR(credentialVec, index, ptr) {
        if (*ptr == NULL) {
            continue;
        }
        Credential *credential = (Credential *)(*ptr);
        const char *credId = StringGet(&credential->credId);
        uint32_t credIdByteLen = HcStrlen(credId) / BYTE_TO_HEX_OPER_LENGTH;
        Uint8Buff credIdByte = { NULL, credIdByteLen };
        credIdByte.val = (uint8_t *)HcMalloc(credIdByteLen, 0);
        if (credIdByte.val == NULL) {
            LOGE("Failed to malloc credIdByte");
            return IS_ERR_ALLOC_MEMORY;
        }

        ret = CheckCredIdExistInHuks(osAccountId, credId, &credIdByte);
        HcFree(credIdByte.val);
        if (ret == HAL_ERR_KEY_NOT_EXIST) {
            LOGE("Huks key not exist!");
            DelCredById(osAccountId, credId);
            continue;
        }
        if (ret == HAL_ERR_HUKS) {
            LOGE("Failed to check key exist in huks");
            continue;
        }
        if (ret != IS_SUCCESS) {
            LOGW("CheckKeyExist failed");
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

static int32_t UpdateAccountList(Credential *credential, CJson *accountList)
{
    DestroyStrVector(&credential->authorizedAccountList);
    credential->authorizedAccountList = CreateStrVector();
    int32_t ret = SetAccListFromArray(credential, accountList);
    if (ret != IS_SUCCESS) {
        LOGE("Failed to update authorizedAccountList");
        return ret;
    }
    return IS_SUCCESS;
}

int32_t UpdateInfoFromJson(Credential *credential, CJson *json)
{
    const char *extendInfo = GetStringFromJson(json, FIELD_EXTEND_INFO);
    CJson *accountList = GetObjFromJson(json, FIELD_AUTHORIZED_ACCOUNT_LIST);

    if (extendInfo == NULL && accountList == NULL) {
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

    if (accountList != NULL) {
        ret = UpdateAccountList(credential, accountList);
        if (ret != IS_SUCCESS) {
            return ret;
        }
    }

    return IS_SUCCESS;
}

int32_t DelCredById(int32_t osAccountId, const char *credId)
{
    QueryCredentialParams delParams = InitQueryCredentialParams();
    delParams.credId = credId;
    int32_t ret = DelCredential(osAccountId, &delParams);
    if (ret != IS_SUCCESS) {
        LOGE("Failed to delete credential, ret: %d", ret);
        return ret;
    }
    ret = SaveOsAccountCredDb(osAccountId);
    if (ret != IS_SUCCESS) {
        LOGE("Failed to save CredDb, ret: %d", ret);
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
