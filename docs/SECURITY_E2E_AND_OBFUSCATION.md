# Server：端到端加密与网络混淆设计

> 状态：**全量切片已落地（DM+频道+文件 Web；Flutter DM/频道文本；Bot runner / REALITY 仍外置）**  
> 仓：`vocechat-server-rust-uu`（**本仓为 E2E 服务端实现落点**）  
> 跨端契约副本：`vocechat-web-uu/docs/E2E_ENCRYPTION_DESIGN.md`  
> 强制规则：[`../AGENTS.md`](../AGENTS.md) · 总览：[`../design.md`](../design.md)  
> 实现计划：[`superpowers/plans/2026-07-13-e2e-mvp.md`](superpowers/plans/2026-07-13-e2e-mvp.md) · [`superpowers/plans/2026-07-14-e2e-full-docker-win.md`](superpowers/plans/2026-07-14-e2e-full-docker-win.md)  
> Docker：[`../build/docker/README.E2E.md`](../build/docker/README.E2E.md)

本文把**内容加密（E2E）**与**网络混淆（抗 DPI / 伪装）**写进 Server 视角，避免只存在于 Web 仓文档。

---

## 1. 威胁模型与控制分工

用户已确认威胁 **D（全部）**：

| 威胁 | 主要控制 | Server 仓职责 |
| --- | --- | --- |
| HTTPS MITM（假 CA）读内容 | 应用层 E2E | 存转发**不透明信封**；不持有用户/Bot 私钥 |
| Server 管理员 / 库泄露读内容 | 同上 | MsgDb/SQLite 仅密文；日志无明文 |
| DPI / SNI / 指纹识别封锁 | **网络混淆（应用外）** | **不在 Rust 进程内做 REALITY**；文档给出部署侧配合方式 |
| 元数据（谁与谁、时序、长度） | 混淆可部分缓解；E2E 不解决 | MUST NOT 声称 Server 已隐藏元数据 |

**原则：混淆保护「连谁」；E2E 保护「说什么」。二者互补，不得互相替代。**

---

## 2. 网络混淆（应用外）— Server 视角

### 2.1 明确非目标（本进程不做）

`vocechat-server-rust-uu` **MUST NOT** 实现：

- 类 Xray **REALITY** 入站（伪造大厂证书握手、自定义 TLS 指纹）
- 在业务代码里伪造 SNI / 伪装成 `google.com`
- 把「混淆」写进 `/api` 业务语义
- **Minewire**（Minecraft 伪装隧道）协议栈

原因：REALITY/伪装是**传输层/代理栈**能力；本进程是标准 HTTPS（或 HTTP）上的聊天 API。把 REALITY 塞进 Poem 会破坏证书、ACME、浏览器直连与 OpenAPI 客户端兼容。

**可选旁路（应用外）：**
- [sing-box REALITY](../deploy/sing-box-reality/) — TLS 指纹伪装边缘（推荐与 E2E compose 叠加：`build/docker/docker-compose.reality.yml`）
- [Minewire](https://github.com/dmitrymodder/minewire) — Minecraft 伪装隧道 sidecar。运维模板见 [`MINEWIRE_TUNNEL.md`](MINEWIRE_TUNNEL.md) 与 [`../deploy/minewire/`](../deploy/minewire/)

### 2.2 推荐部署拓扑（运维，非本仓代码交付）

```text
[客户端] --REALITY/VPN--> [边缘代理 (Xray/sing-box 等)] --内网/本机--> [vocechat-server :3000]
                              或
[客户端] --HTTPS--> [CDN / 反代 / 无害域名] --> [vocechat-server]
```

| 层级 | 建议 | 说明 |
| --- | --- | --- |
| 用户侧 | 本机 REALITY/VPN 出站 | 客户端（Web 浏览器 / Flutter）流量先入代理；**应用无感** |
| 边缘 | 可选 REALITY 入站或普通 TLS 反代 | 终结伪装 TLS 后，用明文或内网 TLS 转到 `network.bind` |
| Server | 继续标准 `config.toml` 监听 | `bind` 可只听 `127.0.0.1:3000`，不直接暴露公网 |
| 弱伪装 | CDN + 普通域名 | 非 REALITY；降低「裸 IP 跑聊天」指纹，**不能**防假 CA MITM 读内容 |

### 2.3 与现有 TLS 配置的关系

本仓已支持：`none` / `self_signed` / `certificate` / ACME（见 `config.rs`、`config/config.toml`）。

| 场景 | 建议 |
| --- | --- |
| 公网直连 + 合法证书 | 继续用 certificate / ACME；**不提供**抗 DPI 伪装 |
| 前置 REALITY/反代 | Server 可用 `tls.type = none` 仅本机 HTTP，或内网证书；对外 TLS 由边缘负责 |
| 自签直连 | 仅开发；对抗 MITM 弱，必须靠 E2E 护内容 |

### 2.4 Server 仓文档义务（可做）

- 在 README/本文件说明「抗封锁靠边缘代理，不靠本进程」。  
- 已交付：[`../deploy/sing-box-reality/`](../deploy/sing-box-reality/) + [`../build/docker/docker-compose.reality.yml`](../build/docker/docker-compose.reality.yml)（占位密钥，勿提交真实密钥）。  
- MUST NOT 在发行说明中宣称「已内置 REALITY / 已伪装成 Google」。

### 2.5 与 E2E 的组合

即使用户走 REALITY，边缘代理或公司 MITM 仍可能看到**到达 VoceChat 源站之后**的 TLS；若再拆源站 TLS，**只有 E2E 保护正文**。部署上两者都应启用才覆盖威胁 D。

### 2.6 应用层元数据硬化（客户端，非 Server 解密）

设计：[`superpowers/specs/2026-07-17-metadata-and-anti-blocking-design.md`](superpowers/specs/2026-07-17-metadata-and-anti-blocking-design.md)

| 控制 | 说明 |
| --- | --- |
| 长度分桶填充 | 明文先 `pad_message`（`u32_be \|\| {"m","c"} \|\| random` → 2^n 桶），再 AEAD；削弱「按密文长度猜消息长度」 |
| 属性最小化 | 线属性仅保留 `e2e` / `e2e_ver` / `sender_device_id` / `local_id`（及必要 `gid`/`cid`）；MIME 进填充载荷，不再发 `inner_content_type` / `peer_device_ids` |

Server 仍可见会话图与时序；上述只降低**消息属性与长度泄漏**，不隐藏社交图。

---

## 3. 端到端加密（E2E）— Server 职责

### 3.1 当前基线（事实）

- 消息经 `api/message.rs` 写入 **MsgDb**，应用层对 Server **明文可读**。  
- Webhook（`forward_chat_messages_to_webhook`）可 POST **含内容**的载荷。  
- FCM/邮件等可能依赖明文预览（待产品 §0.1 最终确认）。

### 3.2 目标态（已对齐的产品决策）

| 项 | 决策 |
| --- | --- |
| 范围 | DM + 频道 + 文件（文本/Markdown/附件）；**语音消息与 Agora 先不动** |
| 协议 | Signal 风格；群 Sender Keys；MLS 后置 |
| 密钥 | 账号自动协商；TOFU + 可选安全码（客户端） |
| 多设备 | 口令加密的身份备份 blob（Server 存不透明） |
| 迁移 | 会话级 `e2e_enabled`；仅新消息加密 |
| Bot | **支持通信加密**；外置 runner 持私钥；主 Server **禁止代解密** |

### 3.3 Server MUST 做

1. **公钥目录**：存储/分发用户与 Bot 的 identity 公钥、预钥（X3DH 若采用）。  
2. **不透明消息**：E2E 会话的 `content`（及加密文件字节）原样存 MsgDb、原样 SSE 下发；**不解析正文**。  
3. **会话策略**：持久化 `e2e_enabled`（DM/频道）；暴露 `e2e_available`。  
4. **备份 blob**：`PUT/GET` 口令加密的身份备份；Server 永不明文解密。  
5. **Webhook**：E2E 会话回调 **仅密文或 mid/元数据**，禁止明文 body。  
6. **Bot API**：接受与人类相同的 `vocechat/e2e` 信封；bot key 鉴权不变。  
7. **能力协商**：旧客户端忽略未知字段；过旧客户端进加密会话时由客户端提示升级（Server 可返回明确错误码）。

### 3.4 Server MUST NOT 做

1. 持有或托管用户/Bot **身份私钥**或会话密钥。  
2. 为「方便搜索/推送/审计」解密 E2E 内容。  
3. 在日志、metrics、FCM 数据中输出 E2E 明文。  
4. 把内置「私钥也在主进程」的 Bot 标称为满足威胁模型 D 的 E2E Bot。

### 3.5 建议 API 落点（实现时挂 OpenAPI）

路径名为草案，实现时可微调，但语义须稳定：

| 方法 | 路径（示意） | 作用 |
| --- | --- | --- |
| PUT | `/api/user/e2e/identity` | 上传/轮换 identity 公钥 + device id |
| GET | `/api/user/e2e/identity/:uid` | 取对端（含 Bot）公钥 |
| PUT/GET | `/api/user/e2e/prekeys` | 一次性预钥 |
| PUT/GET | `/api/user/e2e/backup` | 口令加密备份 blob |
| PATCH | 既有 group/user settings | `e2e_enabled` |
| GET | admin/system 或 login config | `e2e_available` |
| 既有 | `/api/user|group/.../send`、`/api/bot/send_to_*` | 接受 `vocechat/e2e` 或不透明 content |

信封概念：

```text
content_type: "vocechat/e2e"   # 或 properties.e2e=true
content: <opaque>
properties: { e2e, e2e_ver, sender_device_id, ratchet_header, local_id, ... }
```

`mid` / SSE `chat` / `local_id` 客户端对齐语义 **保持不变**。

### 3.6 存储与迁移影响

- SQLite：新表或列存 identity、prekeys、backup blob、会话 `e2e_enabled` — **前向 migration**。  
- MsgDb：密文字节按现有消息记录存储；勿对 E2E content 做全文索引类假设。  
- 文件：`resource` 上传密文 blob；元数据策略按跨端文档（MVP 加密文件名）。

### 3.7 Bot（Server 侧要点）

- Bot 与人类共用 identity API 语义；私钥只在 **外置 runner**。  
- 加/踢 Bot 不负责密钥轮换算法（客户端 Sender Keys），但 MUST 正确维护成员列表事件，以便客户端轮换。  
- `forward_chat_messages_to_webhook`：分支判断会话是否 E2E，剥离明文。

### 3.8 推送 / 搜索（待跨端 §0.1 最终确认）

推荐默认（未全部锁定）：推送占位无正文；Server 全文搜索对密文失效。实现前再核对产品确认项。

### 3.9 实现阶段（Server）

| 阶段 | Server 工作 |
| --- | --- |
| P0 | 本文 + 跨端文档 Accepted |
| P1 | identity/prekeys/backup API + migration spike |
| P2 | 接受/存储/转发 `vocechat/e2e`；会话开关 |
| P2b | webhook 无明文；Bot 发信封 |
| P3 | 加密文件上传兼容 |
| P4 | 频道成员变更事件与策略位完善 |
| 另案 | 语音/Agora；REALITY 仅文档/compose 示例 |

E2E PR **不得**与 REALITY 客户端、无关依赖大升级混在同一变更。

---

## 4. 安全红线（Server）

1. MUST NOT 上传路径接收或持久化身份私钥明文。  
2. MUST NOT 在 E2E 会话 webhook/FCM/邮件中附带明文正文。  
3. MUST NOT 声称本进程提供 REALITY 或「伪装成 google.com」。  
4. MUST NOT 为 E2E「临时」关闭鉴权或 license 校验。  
5. key.json / FCM / SMTP 秘密与 E2E 备份 blob 同等敏感对待（备份 blob 虽已口令加密，仍限制访问为本人）。

---

## 5. 修订记录

| 日期 | 变更 |
| --- | --- |
| 2026-07-13 | 初稿：Server 视角 E2E + 网络混淆职责与非目标 |
| 2026-07-13 | MVP：migration + `/api/user/e2e/*` + `vocechat/e2e` 发送 + webhook 脱敏 + LoginConfig.e2e_available；Web DM P-256 ECDH |
| 2026-07-13 | 验证：`cargo build --release` PASS；Android debug/release APK PASS；Windows Flutter 因缺 VS C++ CMake 工具链 BLOCKED；频道/Flutter E2E 仍未实现 |
| 2026-07-14 | 验证：安装 VS NativeDesktop 后 Windows release PASS（`vocechat_client.exe`）；E2E identity 单测 PASS |
| 2026-07-14 | 全量切片：Web 频道 Sender Keys + 文件信封；Flutter DM/频道文本 e2e_ver=1；Docker Compose+nginx 部署文档（`build/docker/docker-compose.e2e.yml`）。混淆仍为边缘可选，非本镜像 |
| 2026-07-17 | 元数据应用层（pad + 属性最小化）+ `deploy/sing-box-reality` / `docker-compose.reality.yml` |
