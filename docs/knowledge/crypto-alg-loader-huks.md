# 密码学适配层知识（AlgLoader / HUKS）

本文记录加解密/签名/密钥操作 HUKS 化的架构约束与已知风险点（自原 AGENTS.md「专项排查 1」下沉）。

## 架构结论

services 层**不直接调 HUKS**，全部经 `AlgLoader` v-table（`deps_adapter/key_management_adapter/interfaces/alg_defs.h:151-179`）。入口 `GetLoaderInstance()`（`impl/src/alg_loader.c:19`）→ `GetRealLoaderInstance()`（`impl/src/huks_adapter.c:1102`）返回静态表 `g_huksLoader`（`:1072`）。mini 另有独立实现 `frameworks/deviceauth_lite/source/huks_adapter/huks_adapter.c`（HKS TEE）。

- `AlgLoader` 关键条目：`sha256/computeHmac(:155)/computeHkdf(:157)/computePseudonymPsk/importSymmetricKey(:160)/aesGcmEncrypt/aesGcmDecrypt(:163-164)/hashToPoint/agreeSharedSecretWithStorage(:166)/agreeSharedSecret(:167)/generateKeyPairWithStorage(:169)/exportPublicKey(:170)/sign/verify(:171-172)/importPublicKey(:173)/checkDl/EcPublicKey/bigNumExpMod/base64*`。注意**没有**名为 Encrypt/Decrypt/GenerateKey/AgreePsk 的条目。
- 公共入参 `KeyParams{KeyBuff(isAlias), isDeStorage, osAccountId}`（`alg_defs.h:69-79`）；算法枚举 `Algorithm{ED25519,X25519,P256,AES}`（`:41-46`）。
- 底层统一 legacy 风格 `Hks*` API（经 `impl/inc/huks_adapter_utils.h:20`），**无运行时新/旧 HUKS 接口切换**；平台差异靠编译期 `impl/src/{mini,small,standard}/huks_adapter_diff_impl.c`。
- 存储位置分发：按 `isDeStorage` 构造 DE/CE 两套 ParamSet 互为 fallback（`HksKeyExist:104-113`、`HksGenerateKey:679-690` 且 DE 成功后 `MoveSharedKeyToCe`）。
- 持久密钥全部走别名索引（isAlias=true）：authId 密钥对、`MK_`/`PSEUDONYM_` 前缀（`key_manager.c:32-34`）、credId 哈希别名（`identity_operation.c:354-375`）。仅 `exportPublicKey`/公钥验签传明文 blob（正常）。
- `sha256/base64/hashToPoint/公钥合法性校验` 不涉密，可本地执行（`huks_adapter.c:578/1035/1038/1098`）。

## 已知风险点（代码评审必查项）

1. **临时会话密钥明文入参**：PAKE/ISO/DAS 会话密钥以 raw blob 每次传 HUKS（`HKS_TAG_IS_KEY_ALIAS=false`，`huks_adapter_utils.c:302-320`），明文驻留 SA 进程并跨 IPC。属协议设计；使用完必须配对 `FreeAndCleanKey()` + `ClearSensitiveStringInJson(FIELD_SESSION_KEY)`。
2. **P256 协商旁路 HUKS**：`huks_adapter.c:702-715 AgreeSharedSecret` 对 ECC 走进程内 `MbedtlsAgreeSharedSecret`，临时私钥在进程内明文计算（ec_speke/pake 登录流程）；X25519 存储协商仍走 HUKS。**不得新增同类旁路。**
3. **PIN 明文残留**：`identity_pin.c:332-356` 原样 memcpy PIN；`pake_task_common.c:113-138 FillPskWithPin` 留存副本；cJSON 删除不擦除（`json_utils.c:104`），`FIELD_PIN_CODE` 链路（`device_auth.c:318`、`compatible_bind_sub_session*.c`、`creds_manager.c:41/100`）无 `ClearSensitiveStringInJson`；`identity_pin.c:262` 栈缓冲未清零。修复方向：全链路 `memset_s` 清零。
4. **硬编码派生盐/因子**：`g_factor "hichain_key_enc_key"`（lite `huks_adapter.c:36`）、`PSEUDONYM_KEY_FACTOR/_LABEL`（`huks_adapter_utils.c:40-41`）为全网固定盐参与 HKDF（`huks_adapter_utils.c:465-482`）；`RANDOM_SEED_CUSTOM`（`mbedtls_ec_adapter.c:107`）现仅作 CTR-DRBG personalization，旧"X25519 校验 DRBG 未种子化"已由 `InitRngContext(692-712)` 修复。
5. `hcgroup.dat` 等静态数据未做 HUKS 加密，仅靠 DAC+安全标签保护（见 `data-storage-files.md`），属残留明文风险面。历史清单见仓库根 `AI_warnning.md`。
