# 身份与凭据知识（legacy identity/group + identity_service）

本文记录"身份→凭据→PSK"解析链与两套凭据接口边界。文件落盘格式见 `data-storage-files.md`。

## 两套凭据体系（勿混淆）

| 体系 | 入口 | 实现 |
| --- | --- | --- |
| 老凭据库（identity_service） | `GetCredMgrInstance` (`device_auth.c:2001`) | `services/identity_service/src/identity_service.c`（facade，`AddCredential:26/ExportCredential:48/AgreeCredential:212...`）→ `identity_service_impl.c` → `identity_operation.c` |
| 凭据本地 CRUD（ProcessCredential） | `device_auth.c:774` | `services/legacy/identity_manager/src/credential_operator.c:711`，按 CRED_OP_QUERY/CREATE/IMPORT/DELETE 分发 |

identity_service 凭据库安全红线在 `identity_operation.c`：`GenerateCredId:251`、`GenerateCredKeyAlias:1173`、`AddKeyValueToHuks:354`、`GetValidKeyAlias:378`——**credId 哈希别名 + isAlias=true 是私钥不落盘的落点，改错即密钥泄盘**；`SetAgreeCredInfo:1232`+`ComputeAndSavePskInner:1210` 为 Agree→PSK 入 HUKS。

## 身份类型仲裁门面

`services/legacy/creds_manager/src/creds_manager.c:92/117`：按 IsPinAuth/IsDirectAuth/IsDeviceLevel/IsCredAuth 选择 **PIN→P2P→CRED→GROUP** 解析顺序；`GetCredInfosByPeerIdentity` 唯一消费者是 session v2（调用点 `dev_session_v2.c:335`）。

- **边界**：device-level GROUP 会追加一次 P2P 解析并回写 `FIELD_ACQURIED_TYPE=P2P_BIND` 到 context（`creds_manager.c:127-141`），该字段决定后续握手参数选型，乱改即协议走错分支。

## AuthIdentity 四型（identity_manager）

`services/legacy/identity_manager/src/identity_manager.c:60 GetAuthIdentityManager/:38 GetAuthIdentityByType`，把"对方身份"解析成凭据清单/PSK：

- `identity_group.c:966`（组）、`identity_p2p.c:433`（P2P）、`identity_cred.c:844`（凭据，含 `ISSetEcSpekeEntityForAccountUnrelated:141` 等协议实体填充——**决定 V2 握手用哪类 PSK/公钥的核心映射**）。
- `identity_pin.c`：`AuthGeneratePskUsePin:253`（HKDF(PIN,seed)）、`GetSharedSecretForPinInIso:286`、`GetSharedSecretForPinInPake:332`、v-table `GetPinAuthIdentity:404`。
- **PIN 明文残留是已知风险点**：`GetSharedSecretForPinInPake` 原样 memcpy PIN；`legacy/authenticators/.../pake_task_common.c:113-138 FillPskWithPin` 留存副本；`FIELD_PIN_CODE` 链路无 `ClearSensitiveStringInJson` 覆盖（详见 `crypto-alg-loader-huks.md` 风险清单）。触碰 PIN 代码必须整链路 `memset_s` 清零，且严禁日志输出。

## legacy 组认证/任务机（group_auth + authenticators）

- 组管理：`services/legacy/group_manager/src/group_manager.c:24/32/48/102`（GetGmInstance 后端）；`group_operation.c` 组 CRUD 总入口，按组类型分 `identical_account_group/`、`across_account_group/`、`peer_to_peer_group/`；**所有服务端 OnRequest 用户确认都过** `callback_manager.c:148 ProcessRequestCallback`。
- 组认证注册表：`group_auth_manager.c:41 InitGroupAuthManager→RegisterGroupAuth`；注册口在 compatible_auth_sub_session_util、取用口 `GetGroupAuth:117`；两族 v-table `BaseGroupAuth`（`inc/base_group_auth.h:32-35`），实现 `account_unrelated_group_auth.c:37`（`OnDasFinish:223` 回传 sessionKey，**finish 前 ClearSensitiveStringInJson(FIELD_SESSION_KEY) 模式勿删**）与 `account_related_group_auth.c:48`。仅被 **V1 兼容认证子会话**调用。
- 任务状态机真身：`authenticators/account_unrelated/`（`das_task_main.c:433/579`、`das_module.c:160 GetDasModule`、`iso_task|pake_task|pake_v1_task/`）与 `authenticators/account_related/`（`auth/iso_auth_task`、`auth/pake_v2_auth_task`、`creds_manager/sym|asy_token_manager.c` 落 `account_data_*.dat`）。调用方统一为 `services/frameworks/src/module/dev_auth_module_manager.c:184 CreateTask/:206 ProcessTask`（按 DAS_MODULE/ACCOUNT_MODULE 路由）。

## 外部插件

`services/ext_plugin_manager/src/ext_plugin_manager.c`：`:42 InitCredMgr/:72 AddCredPlugin/:29 ProcCred(pluginName, cmdId,...)` 把 IMPORT/DELETE 凭据、REQUEST_SIGNATURE 转发给账号侧插件；调用方 `group_operation.c:1553`、`identical/across_account_group.c`、`compatible_auth_sub_session.c:148`。账号认证会话桥接在 `services/frameworks/src/plugin_adapter/ext_part/account_auth_plugin/account_auth_plugin_proxy.c:72 ProcessAuthSession`。
