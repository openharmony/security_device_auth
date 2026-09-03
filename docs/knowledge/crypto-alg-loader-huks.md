# 密码学适配层知识（AlgLoader / HUKS）

本文记录加解密/签名/密钥操作 HUKS 化的架构约束与评审要点。

## 架构结论

services 层**不直接调 HUKS**，全部经 `AlgLoader` v-table（`deps_adapter/key_management_adapter/interfaces/alg_defs.h:151-179`）。入口 `GetLoaderInstance()`（`impl/src/alg_loader.c:19`）→ `GetRealLoaderInstance()`（`impl/src/huks_adapter.c:1102`）返回静态表 `g_huksLoader`（`:1072`）。mini 另有独立实现 `frameworks/deviceauth_lite/source/huks_adapter/huks_adapter.c`（HKS TEE）。

- `AlgLoader` 关键条目：`sha256/computeHmac(:155)/computeHkdf(:157)/computePseudonymPsk/importSymmetricKey(:160)/aesGcmEncrypt/aesGcmDecrypt(:163-164)/hashToPoint/agreeSharedSecretWithStorage(:166)/agreeSharedSecret(:167)/generateKeyPairWithStorage(:169)/exportPublicKey(:170)/sign/verify(:171-172)/importPublicKey(:173)/checkDl/EcPublicKey/bigNumExpMod/base64*`。注意**没有**名为 Encrypt/Decrypt/GenerateKey/AgreePsk 的条目。
- 公共入参 `KeyParams{KeyBuff(isAlias), isDeStorage, osAccountId}`（`alg_defs.h:69-79`）；算法枚举 `Algorithm{ED25519,X25519,P256,AES}`（`:41-46`）。
- 底层统一 legacy 风格 `Hks*` API（经 `impl/inc/huks_adapter_utils.h:20`），**无运行时新/旧 HUKS 接口切换**；平台差异靠编译期 `impl/src/{mini,small,standard}/huks_adapter_diff_impl.c`。
- 存储位置分发：按 `isDeStorage` 构造 DE/CE 两套 ParamSet 互为 fallback（`HksKeyExist:104-113`、`HksGenerateKey:679-690` 且 DE 成功后 `MoveSharedKeyToCe`）。
- 持久密钥全部走别名索引（isAlias=true）：authId 密钥对、`MK_`/`PSEUDONYM_` 前缀（`key_manager.c:32-34`）、credId 哈希别名（`identity_operation.c:354-375`）。仅 `exportPublicKey`/公钥验签传明文 blob（正常）。
- `sha256/base64/hashToPoint/公钥合法性校验` 不涉密，可本地执行（`huks_adapter.c:578/1035/1038/1098`）。

## 评审要点（触碰密钥链路时逐条核对）

1. **临时会话密钥 blob**（协议设计如此，每次以非别名入参传 HUKS）：使用完必须配对 `FreeAndCleanKey()`，出会话链路前 `ClearSensitiveStringInJson(FIELD_SESSION_KEY)`；新增使用点时逐退出路径核对。
2. **协商实现约束**：密钥协商一律经 `AlgLoader` 现有条目（`agreeSharedSecret/agreeSharedSecretWithStorage`）；**禁止新增任何进程内本地计算的协商/算钥实现**。
3. **PIN/口令类输入**：任何持有明文的缓冲区（含栈上、cJSON 内、跨任务指针）在用毕必须 `memset_s` 清零；cJSON `DeleteItem*` 不擦除内存，敏感字段必须先清再删；严禁日志输出。
4. **派生盐/因子**：禁止新增硬编码盐/因子/种子；确需固定值时注释指向 Hichain 协议规范章节。
5. **静态存储边界**：持久密钥一律 HUKS 别名；文件（`hcgroup.dat` 等）只存标识/别名/元数据，写后设安全标签（见 `data-storage-files.md`）。
