# Minewire 隧道旁路（VoceChat 运维对接）

> 状态：运维旁路（方案 A）— **不改** VoceChat 进程  
> 上游：[dmitrymodder/minewire](https://github.com/dmitrymodder/minewire)  
> 模板：[`../deploy/minewire/`](../deploy/minewire/)  
> 设计：[`superpowers/specs/2026-07-14-minewire-ops-sidecar-design.md`](superpowers/specs/2026-07-14-minewire-ops-sidecar-design.md)

## 1. 定位

| 层 | 作用 |
|----|------|
| Minewire | 把 TCP 隧道伪装成 Minecraft Java 流量，便于穿越**特征型** DPI |
| VoceChat E2E | 保护消息内容；与隧道无关 |
| TLS / 域名 | 正常 HTTPS 仍可用；Minewire 是受限网络下的**可选旁路** |

上游明确：**爱好实验**，不声称对抗行为/流量分析 DPI。勿在高风险环境当作唯一通道。

## 2. 架构

```
用户设备
  Minewire Client  --MC伪装:25565-->  Minewire Server (本机 WSL/Linux)
         |                                    |
         | 本地代理出口                        | 按客户端请求 dial 目标
         v                                    v
   VoceChat Web/App  ------------------>  vocechat-server :3000
```

要点：

- Minewire **不**内嵌 VoceChat 地址；认证后由**客户端指定**要代理的目标（如 `WINDOWS_HOST:3000`）。
- 本仓库 Windows 主机上 VoceChat 默认 `network.bind = 0.0.0.0:3000`。
- Minewire 跑在 **WSL** 时，`127.0.0.1:3000` 是 Linux 自己，**不是** Windows 上的 VoceChat。客户端目标应使用：
  - Windows 主机局域网 IP，或
  - WSL 可见的 Windows host IP（常见为 `/etc/resolv.conf` 里的 `nameserver`）。

## 3. 本机部署（WSL）

```bash
# 在 WSL Ubuntu 中
cd /mnt/c/Users/Administrator/repo/vocechat/vocechat-server-rust-uu/deploy/minewire
bash install-wsl.sh
# 编辑 runtime/server.yaml 中的 passwords
bash start-wsl.sh   # 前台；另开终端跑 verify
bash verify-listen.sh
```

Windows 侧也可：

```powershell
wsl -d Ubuntu-22.04 -- bash -lc 'cd /mnt/c/Users/Administrator/repo/vocechat/vocechat-server-rust-uu/deploy/minewire && bash verify-listen.sh'
```

可选 Docker：见 `deploy/minewire/docker-compose.yml`（需自备二进制；**本机无 Docker**）。

## 4. 客户端怎么连 VoceChat

1. 使用与服务器密码匹配的 **Minewire 客户端**（官方 Release 目前以 **server** 为主；客户端以你采用的发行版/配套工具为准，链接形态多为 `mw://password@host:25565#name`）。
2. 客户端建立隧道后，将 HTTP/SOCKS 或本地端口指到 VoceChat：
   - 目标主机：Windows 上 VoceChat 可达地址  
   - 目标端口：`3000`（或你的 TLS 入口）
3. VoceChat exe / Web 的「服务器 URL」填**客户端本地出口**（例如 `http://127.0.0.1:<本地端口>`），而不是直接填被墙的公网地址。

订阅辅助（可选）：在 `server.yaml` 打开 `subs_listen_port`，访问 `http://server:port/subs/Nickname` 获取 `mw://` 链接。

## 5. 验证矩阵

| 级别 | 内容 | 结果约定 |
|------|------|----------|
| L1 | `minewire-server` 进程 + TCP `:25565` listen | 本机必须 PASS |
| L2 | Minecraft status/list ping 有响应 | Best-effort |
| L3 | Minewire 客户端经隧道访问 VoceChat `/api` | 依赖客户端二进制；无客户端则文档标 PARTIAL |

### 本机记录（2026-07-14）

- 环境：Windows Server + WSL Ubuntu 22.04；用户 `dc`；无 Docker
- 二进制：release `26.7.2` asset `minewire-server-linux-amd64`（运行自报 `v26.7.1`）
- **L1：PASS**（`verify-listen.sh` / TCP `127.0.0.1:25565`）
- **L2：PASS**（Minecraft status handshake 收到响应）
- **L3：PARTIAL**（GitHub Release 仅有 server；待配套客户端做端到端）
- 运行配置：`deploy/minewire/runtime/server.yaml`（gitignore，勿提交）
- 启动示例：`cd runtime && nohup ~/.local/bin/minewire-server >/tmp/minewire.log 2>&1 & disown`

## 6. 与安全文档的关系

见 [`SECURITY_E2E_AND_OBFUSCATION.md`](SECURITY_E2E_AND_OBFUSCATION.md)：混淆在应用外；Minewire 是可选 sidecar，与 REALITY 等并列，互不替代 E2E。

## 7. 运维注意

- `runtime/server.yaml` 含密钥，已 gitignore，勿提交。
- 防火墙放行 TCP `25565`（及可选订阅端口）。
- 升级：设 `MINEWIRE_VERSION` 后重跑 `install-wsl.sh`。
