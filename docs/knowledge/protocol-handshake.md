# 握手协议层知识（protocol）

本文记录协议实现的**两套同名家族**边界——这是本项目最容易改错文件的地方。会话如何调用协议见 `auth-session-pipeline.md`。

## 两套协议代码，先确认调用方集合再改

| 家族 | 位置 | 消费方 |
| --- | --- | --- |
| V2 会话握手协议 | `services/session_manager/src/session/v2/auth_sub_session/protocol_lib/` | 仅 auth_sub_session 状态机 |
| 共享握手算法/参数层 | `services/protocol/src/` | legacy authenticator 任务机 + `services/key_agree_sdk` |

`services/protocol/` **不是** V2 的 ISO/EC-SPAKE/DL-SPAKE 所在处；V2 实现叫 `iso_protocol.c` 等但位于 session_manager 树内。两侧存在 iso/pake 同名文件，grep 时注意区分。

## V2 protocol_lib（会话直连）

- ISO：`iso_protocol.c` — `CreateIsoProtocol:845`（v-table 装配 `:868-870`），入口 `StartIsoProtocol:744` / `ProcessIsoProtocol:757` → `IsoProtocolSwitchState:722` 事件表。
- EC-SPAKE：`ec_speke_protocol.c` — `CreateEcSpekeProtocol:1140`，Start `:1006`/Process `:1019`；算钥核心 `CalSalt:190`、`EcSpekeCalEskSelf:247`、`CalSharedSecret:487`。
- DL-SPAKE：`dl_speke_protocol.c` — `CreateDlSpekeProtocol:1133`，Start `:1006`/Process `:1019`。
- 与外部的**全部衔接面**只有 `BaseProtocol{start, process, setPsk, getSessionKey}` 四个口；`ProtocolInit/HandshakeInit/ExchangeData/GetHandshakeInfo` 这类接口在本仓库不存在。

## services/protocol（共享算法层）

- `protocol_common.c:22 FreeAndCleanKey` — 敏感 buffer 统一清零释放。
- `iso_protocol/iso_protocol_common.c:24 InitIsoBaseParams`。
- PAKE 家族：`pake_protocol/pake_common.c:20 CleanPakeSensitiveKeys`；`pake_v1_protocol/` 与 `pake_v2_protocol/pake_v2_protocol_common.c`（`InitPakeV2BaseParams:143`、`ClientConfirm:587`、`ClientVerifyConfirm:614`、`ServerResponse:637`、`ServerConfirm:651`；v1 同构 `:150/:391/:420/:434/:448`）。
- EC/DL PAKE 参数协商原语：`pake_protocol_ec_common.c:77 GenerateEcPakeParams/:113 AgreeEcSharedSecret`；`pake_protocol_dl_common.c:126/:173`。

## 约束

- 协议消息字段编解码一律经 `common_lib` 的 `CJson`/`hc_parcel`，不得私加二进制打包。
- 修改握手报文 = 修改跨设备兼容性，先对照 Hichain 协议规范并在 PR 中注明影响版本。
- 协议内派生/协商密钥必须经 `GetLoaderInstance()` 现有条目（见 `crypto-alg-loader-huks.md`），禁止新增任何进程内本地计算的协商/算钥实现。
