# API 入口与模块路由知识

本文只记录对外 API 到内部模块的路由边界，容易改错的是"同名接口两套实现"和"初始化/销毁顺序"。会话内部状态机见 `auth-session-pipeline.md`。

## 公开 API 面（standard/small）

本仓库 v4.0.2 的实际 API 声明在 `interfaces/inner_api/device_auth.h`。**旧版 API 名（DoPublishDeviceCapability/DoBindTargetDevice/DoAuthConnection/DoVerifyAuth/DoGenAuthCodeForPair/DoGenerateGroupOwnerId/ExportDeviceCredential 等）已不存在，勿臆造。**

取实例接口返回 v-table（v4.0.2 的伪 OOP 入口，全部定义于 `services/device_auth.c`）：

| 入口 | 定义 | 实现落点 |
| --- | --- | --- |
| `GetGaInstance()` | `device_auth.c:1184` | 组认证/伪名，processData→OpenServerAuthSession，路由 session_manager |
| `GetGmInstance()` | `device_auth.c:1151` | 组管理 CRUD，指向 `services/legacy/group_manager/` |
| `GetCredMgrInstance()` | `device_auth.c:2001` | 凭据库，指向 `services/identity_service/` |
| `GetCredAuthInstance()` | `device_auth.c:2024` | 凭据认证，authCredential/processCredData 路由 session_manager |
| `GetAccountVerifierInstance()` | `device_auth.c:1978` | 账号共享密钥（无会话，HKDF 算钥） |
| 自由函数 `StartAuthDevice` / `ProcessAuthDevice` / `ProcessCredential` | `device_auth.c:853/810/774` | 对应 client P2P / server P2P 首包 / 本地凭据 CRUD |

## 三组易混边界

1. **ProcessCredential ≠ GetCredMgrInstance**：前者（`device_auth.c:774`）后端是 `services/legacy/identity_manager/src/credential_operator.c:711`，无会话的本地凭据 CRUD；后者是 identity_service 的 v-table。改凭据逻辑前先确认哪一套。
2. **GetGaInstance 已不直接执行组认证**：processData/authDevice 全部经 `OpenDevSession` 路由 session_manager（`device_auth.c:357/395`）；真正的 legacy 组认证仅在 V1 兼容子会话中触发。
3. **前台/锁屏门禁**：`AuthDeviceInner`（`device_auth.c:177`）与 `AuthCredentialInner`（`:569`）有 `CheckIsForegroundOsAccountId`/`IsOsAccountUnlocked` 双重校验；`ProcessAuthDevice`/`DeviceAuthCallback` 路径**没有**该校验（由 P2P channel 上下文保证），不要擅自补齐或移除。

## 初始化/销毁顺序（高危）

`InitDeviceAuthService`（`device_auth.c:1084`）内部严格按固定顺序初始化：
`AlgLoader → CredMgr(ext_plugin) → Modules(frameworks) → CallbackMgr → OperationDataManager → GroupManager → IdentityService → DevSessionManager → GroupAuthManager → TaskManager → LightSessionMgr`。

- `CleanAllModules`（`:1021`）按 type 从此表中段级联回滚。
- `DestroyDeviceAuthService`（`:1123`）为逆序销毁。
- **改任一模块的初始化时机必须同步修改 `CleanOperation` 表，否则回滚级联错位导致 UAF/双重释放。**

## 匿名客户端/服务 API 差异

- mini：`interfaces/inner_api/deviceauth_lite/hichain.h`（句柄式 `get_instance/receive_data/start_pake/authenticate_peer`），纯 in-process 库，网络报文交用户 `hichain->cb.transmit`，无 IPC。
- small/standard：经 IPC/SA。客户端封装见 `ipc-client-sdk-sa.md`。
