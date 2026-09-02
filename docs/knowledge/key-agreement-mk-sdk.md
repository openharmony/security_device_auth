# 主密钥协商与密钥协商 SDK 知识

覆盖 `services/mk_agree`、`services/key_agree_sdk`、`services/privacy_enhancement`。会话装配见 `auth-session-pipeline.md`。

## mk_agree（V2 扩展通道内的 MK 协商）

目的：在已认证的 expand 通道上协商主密钥 MK，衍生 pseudonym PSK，别名持久化 HUKS（`MK_`/`PSEUDONYM_` 前缀 `key_manager.c:32-34`，isAlias=true，私钥不出 HUKS）。

- 入口**不是**某个 GetInstance 单例：`services/mk_agree/src/mk_agree_task.c:655 CreateMkAgreeTask(protocolType, isClient,...)` → Iso/Pake 两种 `MkAgreeTaskBase v-table{destroy, process}`（`inc/mk_agree_task.h:43-53`）；PAKE 消息处理 `StartPakeMkAgreeRequest:274/ProcessPakeMkAgreeTask:542`。
- 密钥管理 `key_manager.c`：`GenerateDeviceKeyPair/GenerateMk/DeleteMk/GeneratePseudonymPsk/DeletePseudonymPsk/GetDevicePubKey`（声明 `inc/key_manager.h:30-37`）。
- 调用链：`expand_process_lib/mk_agree.c:194 StartMkAgreeCmd/:104 ProcessMkAgreeTask` ← `dev_session_v2.c:209 addCmd(MK_AGREE_CMD_TYPE)`。整个子系统受 `ENABLE_PSEUDONYM` 编译开关控制，关闭时编入 mock 空实现。
- 伪名数据管理：`services/privacy_enhancement/src/pseudonym_manager.c:855 GetPseudonymInstance`（v-table {getPseudonymId, getRealInfo, loadPseudonymData…}），供 `device_auth.c:674/688`（GetRealInfo/GetPseudonymId API）与 mk_agree 使用；落盘 `pseudonym_data.dat` 见 `data-storage-files.md`。

## key_agree_sdk（独立协商 SDK）

面向**外部组件**的独立 SPAKE 协商库，不经 deviceauth 会话/组体系：

- 公开接口 `services/key_agree_sdk/inc/key_agree_sdk.h:96-104`：`KeyAgreeInitSession/StartSession/GenerateNextMessage/IsFinish/GetResult/FreeSession`。
- 实现 `src/key_agree_session.c` 复用 `services/protocol` 的 `pake_v2_protocol_common.h`（`:20` include、`:737 InitSpekeSession`）——**改 pake_v2 公共算法层时同时评估本 SDK 的兼容性**。
- 会话表 `key_agree_session_manager.c` v-table `GetManagerInstance()`（`inc/key_agree_session_manager.h:32 {addSession/deleteSession/getSession}`）。

## 边界提醒

- mk_agree 消息只在 expand 加密通道内传输（sessionKey 已协商），不要假设其独立可达；临时 PSK 用毕仍要 `FreeAndCleanKey()` 配对。
- PSK 派生一律经 `AlgLoader`（`computePseudonymPsk/computeHkdf`，见 `crypto-alg-loader-huks.md`）；禁止新增硬编码盐/因子。
