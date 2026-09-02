# 认证会话流水线知识（session_manager）

本文记录 V1/V2 双轨会话模型与子会话装配边界。协议握手算法见 `protocol-handshake.md`，凭据/身份解析见 `identity-credentials.md`。

## 会话容器与锁（高危）

`services/session_manager/src/dev_session_mgr.c`：`OpenDevSession:148` → `StartDevSession:180` / `ProcessDevSession:200` / `CancelDevSession:239`（sessionId+appId 双匹配才取消）。**没有 GetSessionManagerInstance 单例**，DevSession 即 v-table {start/process/destroy}。

- 所有 v-table 调用持全局 `g_sessionMutex`；`ProcessDevSession` **持锁执行整条 process 链**。在子会话/协议里引入长阻塞操作（等待、同步 IPC）即全局死锁。
- 异步入口 `PushStartSessionTask:331` / `PushProcSessionTask:349` 经任务队列投递。

## V1/V2 双轨路由（最易改错）

装配与分轨在 `src/session/dev_session_fwk.c`：

- `BuildDevSession:849` 装配会话。
- `StartSession:387`：先尝试 V1（directAuth/credAuth 跳过，`:400`）；`IsSupportSessionV2() && !IsMetaNode` 才 `StartV2Session:206`。
- `HC_ERR_NO_CANDIDATE_GROUP + deviceLevel` 的 V2→V1 降级兜底在 `:403-407`，**改错误码逻辑勿破坏**。
- `ProcessSession:803` 按 `IsV1SessionMsg:475` 分流 `ProcV1Session:657` / `ProcV2Session:774`。
- 三判据 `IsSupportSessionV2()/IsMetaNode/IsV1SessionMsg` 散在 `:395-421/:803-813`，任何一处理解偏差都会让报文走错轨道。

## V1 兼容子会话

`src/session/v1/compatible_sub_session.c:24` 按 4 型（client/server × bind/auth）分发：

- bind → `compatible_bind_sub_session.c:286`（PROCESS_BIND_V1 事件进 GroupDataOperation）。
- auth → `compatible_auth_sub_session.c:88`（向 legacy `GetGroupAuth()->getAuthParamsVecForServer` 取参数）+ `compatible_auth_sub_session_common.c:594 CreateAndProcessAuthTask`（进 legacy 任务机）。
- 此路径是 `services/legacy/group_auth` 的**唯一现代入口**。

## V2 会话核心

`src/session/v2/dev_session_v2.c`，事件状态机 `SessionSwitchState:1956`：

- client 起握手：`ClientCreateAuthSubSessionByCred:1211` → 按凭据算法 `CreateAuthSubSession(PROTOCOL_TYPE_ISO:835 / DL_SPEKE:886 / EC_SPEKE:912)`；server 对偶 `ServerCreateAuthSubSessionByCred:1349`。
- 会话密钥到手后 `CreateExpandSubSessionByCred:1714`（salt+sessionKey→nonce/encKey），握手后经 `:1727/:1834` 走扩展通道。
- **sessionKey 生命周期红线**：唯一读出点 `auth_sub_session.c:123 getSessionKey` → `dev_session_v2.c:1716` → expand 加密通道；任一退出路径漏 `FreeAndCleanKey()`/`ClearSensitiveStringInJson(FIELD_SESSION_KEY)` 即密钥残留。

### auth_sub_session（协议壳）

`src/session/v2/auth_sub_session/auth_sub_session.c:144 CreateAuthSubSession`；协议候选表 `PROTOCOL_COMPONENT_LIB:39` 受 `ENABLE_EC_SPEKE/ENABLE_P2P_BIND_DL_SPEKE/ENABLE_ISO` 编译宏控制。v-table {start, process, setPsk, setSelf/PeerProtectedMsg, getSessionKey}——**PSK 由 dev_session_v2 注入（setPsk），协议库内部不读凭据**，改协议时不要在其中加取凭据逻辑。

### expand_sub_session（认证后扩展通道）

`src/session/v2/expand_sub_session/expand_sub_session.c:508 CreateExpandSubSession`；`EncryptMsg:96/DecryptMsg:119` 用协商 sessionKey 加密封装；命令注册表 `CMD_COMPONENT_LIB:59 addCmd`，四类命令 auth_code_import / pub_key_exchange / save_trusted_info / mk_agree 在 `dev_session_v2.c:125/153/187/209` 注册。**新增握手后指令 = 实现 BaseCmd + addCmd 注册，不改状态机本体。**

mini OS 等级用简化会话：`src/session/mini_session/mini_session_manager.c`。
