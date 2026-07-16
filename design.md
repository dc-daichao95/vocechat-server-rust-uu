# VoceChat Server (Rust uu) 设计文档 / Design

> 本文件描述 `vocechat-server-rust-uu` 的**实际架构与设计约定**。
> 事实基线以**源码与真实运行结果**为准；与代码冲突时以代码为准并更新本文。
> 强制规则见 [`AGENTS.md`](AGENTS.md)。
> **E2E 加密与网络混淆（Server 视角）**：[`docs/SECURITY_E2E_AND_OBFUSCATION.md`](docs/SECURITY_E2E_AND_OBFUSCATION.md)  
> 跨端 E2E 契约：`vocechat-web-uu/docs/E2E_ENCRYPTION_DESIGN.md`（实现落点含本仓）。

## 1. 项目定位 — 这就是 Server 端

| 仓库 | 角色 | 说明 |
| --- | --- | --- |
| **`vocechat-server-rust-uu`** | **VoceChat 后端 Server（本仓）** | Rust 进程：HTTP API、SSE、SQLite、消息库、文件、Bot/Webhook、License、可选静态托管 Web 前端 |
| `vocechat-web-uu` | Web 前端客户端 | React SPA；可被本 Server 的 `wwwroot` 托管；**不是**后端进程 |
| `vocechat-client-uu` | Flutter 客户端 | Android / iOS / Windows |

上游对应：`privoce/vocechat-server-rust`。本仓为独立 fork（`-uu`），不假定与上游自动同步。

`Cargo.toml`：`name = "vocechat-server"`，当前版本 **`0.3.3`**，edition **2021**。

官方 README 明确：Server（Rust）+ Docker image；Web Client 与 App Client 为独立项目。Docker 示例将容器 **3000** 映射到宿主机（如 3009），浏览器访问的是 **本 Server 提供的 API +（若有）静态 Web**。

## 2. 技术栈事实

| 领域 | 选型 |
| --- | --- |
| 语言 / 运行时 | Rust 2021，Tokio |
| HTTP / OpenAPI | Poem 1.3 + poem-openapi 2（Swagger/RapiDoc/Redoc） |
| 元数据 DB | SQLite via **sqlx 0.5** + `migrations/` |
| 消息存储 | 自研 crate `rc-msgdb`（目录型消息库，非 SQLite 存全量聊天） |
| 认证 | Token / refresh（`rc-token`），请求头 **`X-API-Key`**；SSE 用 query `api-key` |
| 推送 | FCM（`rc-fcm`） |
| 邮件 | lettre + liquid 模板 |
| 实时 | Poem SSE + 进程内 `broadcast` 事件总线 |
| TLS | 可选 none / self_signed / certificate / ACME |
| 配置 | TOML（`config/config.toml`）+ clap CLI + 部分 env（`envy`） |
| 许可证 | `vc-license` crate；商业 license 逻辑 |

## 3. 目录地图

```
vocechat-server-rust-uu/
├─ src/
│  ├─ main.rs           # CLI、配置合并、运行时、监听启动
│  ├─ server.rs         # create_state / create_endpoint；挂载 /api 与静态 wwwroot
│  ├─ state.rs          # State、Cache、BroadcastEvent、webhook 转发
│  ├─ config.rs         # Config / Network / System / TLS
│  ├─ api/              # OpenAPI 路由实现（token/user/group/message/bot/admin_* …）
│  ├─ create_user.rs    # 用户创建统一入口
│  ├─ api_key.rs        # API key 解析
│  ├─ middleware.rs license.rs self_signed.rs
│  └─ test_harness.rs   # 集成测试客户端（含 SSE 订阅）
├─ migrations/          # sqlx 迁移（用户、群、已读、bot、webhook…）
├─ crates/
│  ├─ msgdb/            # 消息持久化与序列
│  ├─ token/            # token 编解码
│  ├─ fcm/ magic-link/ open-graph/ vc-license/ agora-token/ github-oauth/
├─ config/              # 示例配置
├─ build/docker/        # compose 等
└─ .github/workflows/release.yml  # tag 触发多架构 release
```

## 4. 运行时架构

### 4.1 进程模型

1. 读 TOML + CLI + env → `Config`。  
2. `create_state`：确保 `data_dir`、打开/迁移 SQLite、打开 MsgDb、加载 users/groups 缓存、启动后台任务（含 **webhook 转发**）。  
3. `create_endpoint`：路由组装后 `Server` 监听 `network.bind`（默认 `0.0.0.0:3000`）。  
4. 可选 daemon（非 Windows）。

### 4.2 路由分层

- `/` → `wwwroot` 静态文件（可放 web-uu 构建产物 `index.html`）。  
- `/api` → OpenAPI 服务（业务 API）。  
- `/api/doc`、`/api/swagger`、`/api/spec` 等 → API 文档。  
- `/health`、`/metrics` → 健康与 Tokio metrics。

客户端（web-uu / Flutter）的 `BASE_URL` 指向 **`{origin}/api`**，与本文一致。

### 4.3 双存储

| 存储 | 用途 |
| --- | --- |
| **SQLite** | 用户、群元数据、设备、配置、已读/静音/收藏索引、bot_keys、webhook_url、license 相关等 |
| **MsgDb** | 聊天消息体与 mid 序列；按目录落盘 |

改消息语义 MUST 同时考虑 MsgDb 与可能的 SQLite 索引/设置表；迁移 SQLite 用 `migrations/` 前向追加。

### 4.4 实时：BroadcastEvent → SSE

- 进程内 `broadcast::Sender<BroadcastEvent>`（chat、用户状态、群变更、kick、settings…）。  
- 客户端：`GET /api/user/events?api-key=...&after_mid=...&users_version=...`（SSE）。  
- 与 web-uu `useStreaming` / Flutter `VoceSse` 对齐的是**本服务端事件流**。

### 4.5 鉴权

- 登录：`/api/token/login` 等 → token + refresh_token。  
- 业务请求：`X-API-Key: <token>`。  
- Bot：Bot API key（`bot_keys`）+ `/api/bot/*`；可与用户 token 体系并存。  
- `key.json`（`server_id` / `server_key` / `third_party_secret`）在 `data_dir`，首次启动生成。

### 4.6 消息发送

- `src/api/message.rs`：`SendMessageRequest` 支持 text/markdown/file/archive 等 content-type。  
- 写入 MsgDb → 广播 `BroadcastEvent::Chat` → SSE 订阅者与 webhook 转发任务消费。  
- **当前应用层对 Server 为明文可读**（E2E 落地前）；E2E 后 body 应变不透明信封（见跨端 E2E 文档）。

### 4.7 Bot / Webhook

- Bot 用户：`is_bot`、`webhook_url`、`bot_keys`。  
- `forward_chat_messages_to_webhook`：对目标用户带 webhook 的 chat 事件 HTTP POST（**当前可含消息内容**）。  
- E2E 设计要求：加密会话 webhook **不得**再 POST 明文；Bot 私钥外置 — 实现时改本仓此处与 bot API。

## 5. 与客户端的边界

- **协议真相**：HTTP 路径与 SSE 事件类型以本仓 `src/api/*` + OpenAPI 为准；web-uu / client-uu 是消费者。  
- **E2E 契约文档**可写在 `vocechat-web-uu/docs`，但 **Server 行为变更必须改本仓**。  
- 静态 Web：可选下载/放置 web client 到 `wwwroot`（配置 `webclient_url`）；不替代本进程作为 API Server。

## 6. 配置要点

- `config/config.toml`：`system.data_dir`、`network.bind`、`frontend_url`、TLS、邮件模板。  
- Token 默认过期：access ~300s，refresh ~7d（可配）。  
- 敏感：`data_dir/key.json`、FCM 私钥、SMTP、license — MUST NOT 提交仓库。

## 7. 构建与发布

- 本地：`cargo build --release`；测试：`cargo test`（含 `test_harness` 与各 api 模块内测试）。  
- CI：`.github/workflows/release.yml` 在版本 tag 上打多目标（linux musl、macos、armv7、aarch64 等）。  
- Docker：官方镜像 `privoce/vocechat-server`；本 fork 的镜像发布策略以本仓/运维约定为准。

## 8. 已知边界

- sqlx 0.5 / 部分依赖较旧；大升级须独立 PR 与迁移验证。  
- 消息在 E2E 前 Server 侧明文；搜索/推送/webhook 依赖明文 — 与 E2E 冲突处按安全设计文档改。  
- Windows 可编译运行；daemonize 仅非 Windows。  
- License 限制非个人大规模使用（见 README 商业条款）。  
- **本进程不提供 REALITY/流量伪装**；抗 DPI 靠边缘代理（见 §10）。

## 9. 应用层端到端加密（E2E）摘要

> 完整设计见 [`docs/SECURITY_E2E_AND_OBFUSCATION.md`](docs/SECURITY_E2E_AND_OBFUSCATION.md)。未 Accepted 前 MUST NOT 写生产加密代码。

- **威胁**：假 CA MITM、Server 读库 → 靠 E2E；**不是**靠本进程 TLS 伪装。  
- **范围**：DM + 频道 + 文件；语音/Agora 冻结。  
- **Server 角色**：公钥/预钥/口令备份 blob 存储与分发；MsgDb **不透明**存转发；会话 `e2e_enabled`；SSE 原样下发。  
- **Server 禁止**：持有用户/Bot 私钥；为 webhook/搜索/推送解密 E2E 正文。  
- **Bot**：支持加密通信；私钥在**外置 runner**；webhook 对 E2E 会话禁止明文 POST。  
- **协议**：Signal 风格 + Sender Keys；与 web-uu / client-uu 一致。  
- **迁移**：会话级开关，仅新消息加密。  
- **落点**：新 OpenAPI（`/api/user/e2e/*` 等）+ `migrations/` + 改造 `message.rs` / webhook 转发。

## 10. 网络混淆（抗封锁）摘要

> 完整设计见 [`docs/SECURITY_E2E_AND_OBFUSCATION.md`](docs/SECURITY_E2E_AND_OBFUSCATION.md) §2。

- **职责在应用外**：用户本机 REALITY/VPN，和/或边缘 Xray/反代/CDN。  
- **本仓 MUST NOT**：在 Rust 服务内实现 REALITY、伪造 SNI、宣称伪装成大厂域名。  
- **推荐**：公网只暴露边缘；`vocechat-server` 听 `127.0.0.1:3000`（或内网），继续用现有 `network.tls` 仅处理「源站」TLS（或本机明文）。  
- **与 E2E**：混淆 ≠ 加密；威胁 D 需要**两者都做**。  
- **弱选项**：无害域名 + CDN 反代（非 REALITY），不能替代 E2E。

## 11. 参考

- 上游：https://github.com/Privoce/vocechat-server-rust  
- 文档站：https://doc.voce.chat  
- 本地 API 文档：运行后 `/api/swagger` 或 `/api/doc`  
- Agent 规则：[`AGENTS.md`](AGENTS.md)  
- E2E + 混淆（本仓）：[`docs/SECURITY_E2E_AND_OBFUSCATION.md`](docs/SECURITY_E2E_AND_OBFUSCATION.md)  
- 跨端 E2E：`vocechat-web-uu/docs/E2E_ENCRYPTION_DESIGN.md`
