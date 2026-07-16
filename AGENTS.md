# VoceChat Server (Rust uu) Agent 指南

## 1. Scope / Purpose

- 本文件适用于 `vocechat-server-rust-uu` 全仓库，始终生效。
- Agent / 开发者 MUST 按序建立上下文：
  1. [`README.md`](README.md)
  2. 本 `AGENTS.md`
  3. [`design.md`](design.md)
  4. 涉及加密/抗封锁时：[`docs/SECURITY_E2E_AND_OBFUSCATION.md`](docs/SECURITY_E2E_AND_OBFUSCATION.md)
  5. 任务相关 `src/`、`crates/`、`migrations/`、测试
- **源码、配置与可复现命令结果是 source of truth。**
- 文档与代码冲突时以代码为准，并记录/更新文档偏差。
- MUST NOT 把推断写成未验证事实；MUST NOT 把 `BLOCKED`/未执行报成 `PASS`。
- 与用户明确要求冲突时用户优先；仍须遵守安全与证据真实性底线。

## 2. 身份确认（Server 端）

- **本仓库就是 VoceChat 的 Server 端**（Rust 后端进程）。
- **不是** Web 前端：Web 前端是 `vocechat-web-uu`；本进程可**静态托管**其构建产物（`wwwroot`），但 API/SSE/SQLite/MsgDb/Bot 均在本仓。
- **不是** Flutter 客户端：`vocechat-client-uu` 是 API 消费者。
- 包名 `vocechat-server`，版本以 `Cargo.toml` 为准（当前文档基线 **0.3.3**）。
- 独立 fork（`-uu`）；MUST NOT 假定与上游自动同步。
- 默认监听 **`0.0.0.0:3000`**；API 前缀 **`/api`**；SSE **`GET /api/user/events`**；鉴权头 **`X-API-Key`**。

## 3. Project Map（简版）

- `src/main.rs`：入口、配置、监听。
- `src/server.rs`：`create_state` / `create_endpoint`。
- `src/state.rs`：缓存、广播、webhook 转发。
- `src/api/*`：OpenAPI 业务（token、user、group、message、resource、bot、admin_*、license…）。
- `migrations/`：SQLite 前向迁移。
- `crates/msgdb`：消息持久化；`crates/token`、`fcm`、`vc-license` 等。
- `config/`：示例 TOML；运行时数据在 `system.data_dir`（含 `key.json`）。
- 详见 [`design.md`](design.md)。

## 4. Architecture Invariants

### 4.1 API 与鉴权

- 新 HTTP API MUST 经 `poem-openapi` 挂到 `api/mod.rs` 的 `create_api_service`，保持 `/api` 前缀与 OpenAPI 可发现。
- 需登录的接口 MUST 校验 `X-API-Key`（或既有等价机制）；登录/公开配置类接口 MUST NOT 误要求用户 token。
- Bot 专用接口走 `/api/bot` + bot key 校验（`check_api_key` 模式）；MUST NOT 把 bot 私钥存进主 Server（E2E 落地后，见跨端 E2E 文档）。
- 改 token 过期、refresh、kick 语义 MUST 与 web-uu / client-uu 现有客户端行为兼容或提供版本协商。

### 4.2 SSE 与事件顺序

- 实时路径：业务写入 → `BroadcastEvent` → 用户 SSE 订阅。
- `heartbeat` / kick 类事件语义 MUST 保持客户端可解析的既有 JSON `type` 字段约定。
- 改 `after_mid` / `users_version` 增量语义 MUST 有测试或可复现证据；MUST NOT 只改一端客户端。
- MUST NOT 在日志中打印完整消息正文或 token。

### 4.3 双存储

- SQLite（元数据）与 MsgDb（消息）职责分离；新功能 MUST 明确写入哪一侧。
- SQLite schema 变更 MUST 新增 `migrations/` 文件，版本单调；MUST 验证空库迁移与至少一条升级路径。
- MsgDb 格式变更 MUST 评估旧数据目录兼容与回滚；destructive 清理 MUST 有用户明确批准。

### 4.4 消息内容

- 当前 Server **可读**消息正文（明文应用层）。引入 E2E 后：E2E 会话的 `content` MUST 作不透明字节存储与转发；MUST NOT 为 webhook/搜索/推送解密用户密文（Bot 外置持钥除外）。
- 发送路径集中在 `api/message.rs` 的 `send_message` 一类逻辑；改动 MUST 保持 mid 分配、目标枚举（DM/group）、广播与持久化一致。
- 新 `content_type` MUST 定义存储、SSE 下发、旧客户端兼容策略。

### 4.5 Bot / Webhook

- `forward_chat_messages_to_webhook` 当前可转发消息内容；E2E 会话 MUST 改为密文或仅元数据（见 [`docs/SECURITY_E2E_AND_OBFUSCATION.md`](docs/SECURITY_E2E_AND_OBFUSCATION.md)）。
- 改 webhook 载荷 MUST 同步文档与 bot runner 期望；MUST NOT 静默恢复明文 POST。
- Bot 支持 E2E：主 Server MUST NOT 持有 Bot 身份私钥；加密/解密在外置 runner。

### 4.6 E2E 与网络混淆（专题）

- E2E 与混淆的完整设计 MUST 遵循 [`docs/SECURITY_E2E_AND_OBFUSCATION.md`](docs/SECURITY_E2E_AND_OBFUSCATION.md) 与跨端 `vocechat-web-uu/docs/E2E_ENCRYPTION_DESIGN.md`。
- **E2E（本仓实现）**：公钥/预钥/备份 blob API、不透明消息、会话开关、webhook 无明文；未文档 Accepted 前 MUST NOT 合并生产加密代码。
- **网络混淆（本仓不实现 REALITY）**：MUST NOT 在本进程加入 REALITY/伪造 SNI/伪装大厂域名；抗 DPI 由边缘代理/用户 VPN 承担。本仓仅可文档化「反代后听本机端口」等部署建议。
- MUST NOT 将 E2E 与 REALITY/无关大升级塞进同一 PR。
- MUST NOT 声称本 Server「已防中间人识别流量」或「等同 REALITY」。

### 4.7 静态前端与配置

- `wwwroot` 仅静态托管；MUST NOT 在静态层实现业务鉴权替代 `/api`。
- `data_dir/key.json`、FCM、SMTP、license 密钥 MUST NOT 提交 git 或写入日志。

## 5. Change Workflow

### 5.1 开工前

- MUST `git status`（PowerShell 用 `;` 连接）。
- MUST 阅读 README、本文件、design、相关 api/migration。
- MUST 一句话定义目的、文件范围与明确不做之事。
- 若变更影响客户端协议，MUST 标明需同步的 web-uu / client-uu 项或兼容策略。
- 缺关键产品决策时 MUST 先问聚焦问题。

### 5.2 实施中

- 一次变更一个主要目的；MUST NOT 混合无关依赖大升级与业务。
- MUST NOT 顺手大范围 rustfmt 无关文件或重命名无关符号。
- MUST 保留用户已有改动。
- MUST NOT 擅自改版本号、打 tag、发布 Docker/release、force push。
- 新迁移 MUST 可重复执行于干净环境。

### 5.3 收尾

- MUST 检查 diff 仅含预期文件。
- MUST 运行与风险相称的 `cargo test` / `cargo build`；无法运行则记 `BLOCKED` 与原因。
- MUST 区分 pre-existing 失败与本次引入失败。

## 6. Recipes

### 6.1 新增 API

1. 在 `src/api/<module>.rs` 用 `#[OpenApi]` 定义。  
2. 在 `api/mod.rs` 注册。  
3. 需要鉴权则复用 `Token` / `CurrentUser` / bot key 模式。  
4. 补充或更新模块内 `#[cfg(test)]`；复杂流用 `test_harness`。  
5. 若客户端需调用，在 web-uu RTK Query / Flutter API 侧另 PR 对接。

### 6.2 SQLite 迁移

1. 新增 `migrations/YYYYMMDDHHMMSS_*.sql`。  
2. 本地空目录与旧 data 升级各验一次。  
3. 更新读写 SQL 与 cache 加载逻辑（`state.rs` / 相关 api）。

### 6.3 新 SSE 事件

1. 扩展 `BroadcastEvent` 与序列化到客户端的 JSON shape。  
2. 在发送点 `event_sender.send`。  
3. 同步 web-uu `useStreaming` 与 client-uu SSE handler（独立 PR 可接受，但协议须先对齐）。  
4. 用 `test_harness::subscribe_events*` 覆盖。

### 6.4 Bot

- 发消息走 `/api/bot/send_to_*` 既有路径或扩展时保持 api-key 校验。  
- Webhook URL 校验与明文/密文策略按 [`docs/SECURITY_E2E_AND_OBFUSCATION.md`](docs/SECURITY_E2E_AND_OBFUSCATION.md)。

### 6.5 E2E API / 迁移

- 按安全设计文档增加 identity/prekeys/backup 与 `e2e_enabled`；SQLite 前向 migration。  
- 发送与 SSE 路径对 `vocechat/e2e` 做不透明处理；补 `test_harness` 用例（存转发不解析正文）。  
- Webhook 分支：E2E 会话无明文。

### 6.6 网络混淆（仅文档/部署）

- 若补充 compose/反代示例，放 `docs/` 或 `build/`，MUST 标明「边缘代理非本进程」。  
- MUST NOT 向 `src/` 引入 REALITY 协议实现充当「安全修复」。

## 7. 验证与质量门

- 建议命令（环境需 Rust toolchain；未验证则 `BLOCKED`）：
  - `cargo fmt -- --check`（若项目采用 rustfmt）
  - `cargo clippy -- -D warnings`（若团队启用；当前代码有 clippy allow，勿擅自改成全仓 deny）
  - `cargo test`
  - `cargo build --release`
- Release CI 在版本 tag 触发多目标构建；日常 PR MUST NOT 假设 CI 已跑完所有矩阵 unless tag/workflow 证据。
- 协议变更 MUST 在至少一种客户端或 harness 上验证登录、SSE、发消息。

## 8. Security Red Lines

- MUST NOT 日志/Issue/CI artifact 输出 token、refresh、密码、server_key、FCM private key、消息明文（E2E 后含密钥材料）。
- MUST NOT 提交 `data/`、`key.json`、生产证书私钥、`.env` 秘密。
- TLS 与 ACME 配置变更 MUST 最小权限；MUST NOT 为图省事关闭校验作为“修复”。
- License 校验失败语义（如客户端所见 451）MUST fail closed，除非用户明确要求改产品策略。
- E2E：主 Server MUST NOT 持有 Bot/用户身份私钥代解密。
- MUST NOT 在本进程实现或宣传 REALITY/域名伪装作为产品能力。

## 9. GitHub Flow

- 短生命周期分支与小型 PR。
- commit / push / tag / release MUST 有用户明确要求。
- MUST NOT force push `master`/`main`。
- 依赖升级、协议破坏性变更、E2E、商业 license 逻辑 SHOULD 分 PR。

## 10. Definition of Done

每项 `PASS` / `FAIL` / `BLOCKED` / `N/A`：

- [ ] 范围单一；用户改动保留。  
- [ ] API 已挂 OpenAPI；鉴权正确。  
- [ ] 涉及 DB 时迁移前向且可验证。  
- [ ] SSE/消息/mid 语义未静默破坏；客户端兼容已说明。  
- [ ] `cargo test` / build 有证据或 `BLOCKED` 原因。  
- [ ] 涉及 E2E/webhook 时符合 `docs/SECURITY_E2E_AND_OBFUSCATION.md`；未混入 REALITY 实现。  
- [ ] 无秘密与明文消息泄露。  
- [ ] 未擅自 tag/发布/force push。

## 11. Links

- [`README.md`](README.md)  
- [`design.md`](design.md)  
- [`docs/SECURITY_E2E_AND_OBFUSCATION.md`](docs/SECURITY_E2E_AND_OBFUSCATION.md)（E2E + 网络混淆）  
- 上游 https://github.com/Privoce/vocechat-server-rust  
- 文档 https://doc.voce.chat  
- 跨端 E2E Draft：`vocechat-web-uu/docs/E2E_ENCRYPTION_DESIGN.md`
