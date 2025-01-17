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

#include "identity_manager.h"

/* in order to expand to uint16_t */
static const uint8_t KEY_TYPE_PAIRS[KEY_ALIAS_TYPE_END][KEY_TYPE_PAIR_LEN] = {
    { 0x00, 0x00 }, /* ACCESSOR_PK */
    { 0x00, 0x01 }, /* CONTROLLER_PK */
    { 0x00, 0x02 }, /* ed25519 KEYPAIR */
    { 0x00, 0x03 }, /* KEK, key encryption key, used only by DeviceAuthService */
    { 0x00, 0x04 }, /* DEK, data encryption key, used only by upper apps */
    { 0x00, 0x05 }, /* key tmp */
    { 0x00, 0x06 }, /* PSK, preshared key index */
    { 0x00, 0x07 }, /* AUTHTOKEN */
    { 0x00, 0x08 }  /* P2P_AUTH */
};

uint8_t *GetKeyTypePair(KeyAliasType keyAliasType)
{
    return (uint8_t *)KEY_TYPE_PAIRS[keyAliasType];
}

const AuthIdentity *GetAuthIdentityByType(AuthIdentityType type)
{
    (void)type;
    return NULL;
}

const AuthIdentityManager *GetAuthIdentityManager(void)
{
    return NULL;
}

const AuthIdentity *GetGroupAuthIdentity(void)
{
    return NULL;
}

const AuthIdentity *GetPinAuthIdentity(void)
{
    return NULL;
}

const AuthIdentity *GetP2pAuthIdentity(void)
{
    return NULL;
}

const CredentialOperator *GetCredentialOperator(void)
{
    return NULL;
}
