# Cloudflare 部署指南（Tunnel 公网入口 + Relay 代理池）

本文把「用 Cloudflare 部署 Agent2API」的两件事一次讲全：

| 能力 | 解决什么问题 | 入口 |
| --- | --- | --- |
| **Cloudflare Tunnel**（cloudflared） | 让**别人访问你的网关**：不用公网 IP、不开端口映射，把面板 + API 暴露到你的域名 | 环境变量开关，随网关启动 |
| **Relay 代理池**（网络代理页） | 让**你的网关访问上游**：本机直连上游 AI 服务不通（网络受限 / IP 被风控）时，经 Cloudflare Worker 中转出站 | 面板「网络代理」页 |

两者互相独立，可只用一个，也可组合：公网用户 → Tunnel → 你的网关 → Relay → 上游 AI。

---

## 第一部分：Cloudflare Tunnel（公网访问网关）

### 1. 原理

网关启动时自动拉起 `cloudflared`（Cloudflare 官方隧道客户端）作为**子进程**：按平台自动下载（落 `{数据目录}/bin/`，重启复用），随网关停机一起退出；崩溃按指数退避（3 秒起、封顶 5 分钟）自动重启。桌面 / 服务端 / Docker 三种形态都支持。

### 2. 两种模式怎么选

| | Quick Tunnel | 具名隧道 |
| --- | --- | --- |
| 需要 Cloudflare 账号 | ❌ 不需要 | ✅ 需要（免费版即可） |
| 公网地址 | `https://xxx.trycloudflare.com`，**随机且重启会变** | `https://你自己的域名`，固定 |
| 配置量 | 一个环境变量 | Zero Trust 控制台创建 Tunnel + 配域名路由 |
| 适合 | 试用、演示、验证连通 | 生产、长期给客户端用 |

### 3. Quick Tunnel：五分钟试用

任一形态，给网关进程加一个变量：

```yaml
# Docker / docker-compose.yml
environment:
  AGENT2API_CLOUDFLARED_ENABLED: "1"
```

```bash
# Linux 服务端（/etc/agent2api/agent2api.env）
AGENT2API_CLOUDFLARED_ENABLED=1
```

重启网关，打开面板「日志」页搜 `Cloudflared`，能看到一行：

```
🌍 Quick Tunnel 公网地址：https://quick-words-does-matter-1234.trycloudflare.com
```

用这个地址（`http://<地址>/v1`）就能从公网访问网关。**注意**：地址每次重启都变，客户端要跟着改；仅用于临时验证。

### 4. 具名隧道：生产部署（完整步骤）

**第 1 步：创建 Tunnel 并拿 token**

1. 打开 [Cloudflare Zero Trust 控制台](https://one.dash.cloudflare.com/)（免费版即可）
2. 左侧 **Networks → Tunnels → Create a tunnel**，选 **Cloudflared** 类型，起个名字（如 `agent2api`）
3. 创建后页面显示一串很长的 token（`eyJhbGciOi...` 一整行）——复制它
4. 公开主机名（Public Hostname）页：把你自己的域名（需已托管在该 Cloudflare 账号下）填进子域 + 域名，服务类型 `HTTP`，URL 填网关所在机器/容器的 `localhost:3065`（容器外映射了别的端口就填那个）
5. 保存后，Tunnel 列表里那条的状态应该变成 **HEALTHY**

**第 2 步：把 token 交给网关**

```yaml
# Docker / docker-compose.yml
environment:
  AGENT2API_CLOUDFLARED_ENABLED: "1"
  AGENT2API_CLOUDFLARED_TOKEN: "eyJhbGciOi...（整串粘贴）"
```

```bash
# Linux 服务端
AGENT2API_CLOUDFLARED_ENABLED=1
AGENT2API_CLOUDFLARED_TOKEN=eyJhbGciOi...
```

重启网关，日志里看到「cloudflared 已启动（pid xxx）」且控制台 Tunnel 状态保持 HEALTHY 即成功。之后客户端接入信息不变，`base_url` 换成 `https://<你的域名>/v1`。

**桌面形态**：设置同样的环境变量再启动应用即可（Windows 用系统环境变量，macOS 用 `launchctl setenv` 或从终端启动）。

### 5. 全部变量

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `AGENT2API_CLOUDFLARED_ENABLED` | 关 | 置 `1` / `true` / `on` 开启 |
| `AGENT2API_CLOUDFLARED_TOKEN` | 空 | 具名隧道 token；**只进子进程环境变量，不进命令行、不落日志**（日志里只显示首尾 4 位的脱敏形态）。留空走 Quick Tunnel |
| `AGENT2API_CLOUDFLARED_URL` | `http://127.0.0.1:{网关端口}` | 隧道转发到的本机地址；一般不用改 |
| `AGENT2API_CLOUDFLARED_BIN` | 自动下载 | 已有 cloudflared 的路径（离线环境 / GitHub 不可达时用），设置后跳过下载 |
| `AGENT2API_CLOUDFLARED_VERSION` | `latest` | 钉版本（如 `2026.11.2`），避免 latest 重定向变化 |
| `AGENT2API_CLOUDFLARED_ARGS` | 空 | 追加给 cloudflared 的原始参数（空格分隔，双引号可包空格参数）。内置默认带 `--protocol http2`（隧道传输走 TCP 443，兼容性比默认 QUIC 好——很多网络拦 UDP）；要换回 QUIC 设 `--protocol quic` 覆盖 |

### 6. 安全清单（公网部署必读）

- 隧道把网关**整个端口**（面板 + `/v1/*`）都暴露出去。面板有管理员登录 + 人机验证；`/v1/*` 没有 API Key 时 fail-closed（拒绝服务）——部署后**立即在面板注册管理员、创建网关 Key**
- 只想暴露 API、不想暴露面板：设置 `AGENT2API_PANEL_PORT=3066` 分端口，Tunnel 的服务 URL 指向 `localhost:3065`（只挂 `/v1`），面板端口留在内网
- **首次注册管理员的窗口期**（未注册时管理接口不校验来源）在公网部署下要尽量缩短：部署完立刻打开面板完成注册
- 不要把 token 提交进仓库 / 贴到群里；泄露后在 Zero Trust 控制台删掉 Tunnel 重建即可

### 7. 排障

| 现象 | 原因与处理 |
| --- | --- |
| 日志反复出现「下载失败：HTTP 404」 | `AGENT2API_CLOUDFLARED_VERSION` 写错（版本号不存在）；改回 `latest` 或核对 [Release 页](https://github.com/cloudflare/cloudflared/releases) |
| 「已下载的 cloudflared 自检失败」 | 上次下载损坏；日志会自动删掉重下，反复出现就删 `{数据目录}/bin/cloudflared*` 手动重下，或设 `AGENT2API_CLOUDFLARED_BIN` 指向手动下载的程序 |
| 控制台 Tunnel 一直 DOWN | token 粘贴不全（要整行）；或控制台的 Public Hostname 服务 URL 填错（应指向网关真实端口） |
| 面板打得开、`/v1` 401 | 正常——未配 API Key 时 fail-closed；建 Key 后恢复 |
| Quick Tunnel 地址打不开 | trycloudflare 偶发限流；重启网关换一个地址 |

---

## 第二部分：Relay 代理池（出站经 Cloudflare Worker 中转）

### 1. 原理与适用场景

「网络代理」页新增的 **Cloudflare Relay** 类型：条目是一个部署在 Cloudflare Workers 上的 HTTPS 中转地址。启用它的账号出站时，请求被改写成 `{relay}/{原路径}` 并注入 `x-relay-target` / `x-relay-path` 两个头，Worker 收到后转发到真实上游——**出口 IP 变成 Cloudflare 边缘的 IP**。

适用：本机直连上游 AI 服务被墙 / 被风控 / 出口 IP 不干净。不适用：上游明确封 Cloudflare IP 段的（少见）。

与既有 HTTP / SOCKS5 代理的关系：**互斥且并存**——账号配了 relay 就走 relay（不双重代理）；没配 relay 的账号照常走普通代理或直连。轮询档（`rotate`）里也可以混着放 relay 条目。

### 2. 前置：一个 Cloudflare 账号

- 免费版即可；Workers 免费额度每天 10 万次请求，个人用绰绰有余
- 需要两样东西：**Account ID**（Cloudflare 控制台首页右侧，或任一域名概览页右下角）和 **API Token**（My Profile → API Tokens → Create Token → 用 **"Edit Cloudflare Workers"** 模板，它自带所需的 `Workers Scripts: Edit` 权限）

### 3. 方式 A：面板一键部署（推荐）

1. 面板 → **网络代理** → 新增代理 → 协议选 **Cloudflare Relay**
2. 展开凭据折叠区，填 Account ID 与 API Token；点 **一键部署 Relay Worker**
3. 网关调 Cloudflare API 完成部署（10-30 秒），成功后自动回填 Relay 地址、登记条目并启用——日志页能看到「Relay Worker「xxx」部署完成」
4. （可选）**部署区域**：默认「自动」（Cloudflare 就近分配）。想指定就先选区域再点部署；已部署的用 **仅切换区域** 改（Worker 名不变、地址不变，只重传脚本换位置）
5. 给账号配上这条代理：账号列表 → 编辑账号 → 代理选它（或账号代理设为「轮询」把它圈进去）

失败时看报错文案：凭据无效（Token 权限不够）/ 名称被占用（换名重试）/ 拿不到子域（去控制台给 workers.dev 配子域）/ 网络异常（重试）。部署失败**不会**留下半条脏条目。

### 4. 方式 B：手动部署 Worker 再填地址

不方便给面板 Token 时（例如多人共用面板），手动部署：

1. 本地装 wrangler：`npm install -g wrangler`，`wrangler login`
2. 存这份 `worker.js`（就是面板一键部署用的同一份脚本）：

```js
export default {
  async fetch(request) {
    const target = request.headers.get("x-relay-target");
    const relayPath = request.headers.get("x-relay-path") || "/";
    if (!target) {
      return new Response(JSON.stringify({ error: "Missing x-relay-target header" }), {
        status: 400, headers: { "content-type": "application/json" } });
    }
    const targetUrl = target.replace(/\/$/, "") + relayPath;
    const init = { method: request.method, headers: new Headers(request.headers) };
    if (request.method !== "GET" && request.method !== "HEAD") {
      init.body = request.body; init.duplex = "half";
    }
    init.headers.delete("x-relay-target");
    init.headers.delete("x-relay-path");
    init.headers.delete("host");
    try {
      const response = await fetch(targetUrl, init);
      return new Response(response.body, { status: response.status, headers: response.headers });
    } catch (error) {
      return new Response(JSON.stringify({ error: "relay upstream failed" }),
        { status: 502, headers: { "content-type": "application/json" } });
    }
  },
};
```

3. 存 `wrangler.toml`（`name` 全局唯一；想固定区域加 `placement` 段）：

```toml
name = "agent2api-relay"
main = "worker.js"
compatibility_date = "2024-03-20"

[placement]
hint = "weur"   # 可选：wnam/enam/sam/weur/eeur/me/afr/apac/oce，删掉整段 = 自动
```

4. `wrangler deploy` → 输出 `https://agent2api-relay.<你的子域>.workers.dev`
5. 面板 → 网络代理 → 新增 → 协议 **Cloudflare Relay** → 地址填这个 URL → 保存。凭据区不用填（不部署就不用）

### 5. 凭据与安全说明

- 凭据（Account ID / API Token）**明文**存在本机代理池数据里（当前版本不做加密）——它只存在你自己的机器 / 数据卷里，列表与日志**不会回显 Token**（只显示「已保存」状态）
- 担心明文的话用方式 B：Token 走 wrangler 本机环境，面板里永远没有 Token
- relay 地址本身也是凭据（拿到就能白嫖你的 Workers 额度）：workers.dev 地址默认公开可达。介意的话在 Cloudflare 控制台给 Worker 加一层校验（比如要求 `x-relay-path` 带固定密钥串），或者别把条目截图外传
- 测试按钮（「测试出口」）打的是 Cloudflare 自己的 `/cdn-cgi/trace`，成功显示的出口 IP 就是分配到的 Cloudflare 边缘 IP

### 6. 免费额度与注意事项

- Workers 免费版 **10 万请求/天**、单请求 CPU 10ms——AI 转发基本只透传，CPU 时间远低于上限；但大流量账号池要注意请求数
- 中转有少量延迟增加（多一跳 Cloudflare 边缘）；流式响应（SSE）全程透传，不影响打字机效果
- 上游返回 403 / 429 与 relay 无关（那是上游对 Cloudflare IP 的态度）；表现为 relay 测试通、但账号请求失败时，先看面板日志里上游的真实返回

### 7. 排障

| 现象 | 原因与处理 |
| --- | --- |
| 部署报「凭据无效或权限不足」 | Token 没用 "Edit Cloudflare Workers" 模板；或复制时带了空格 |
| 部署报「名称已被占用」 | Worker 名全局唯一；换个 `name`（或删掉控制台里的旧 Worker） |
| 部署报「无法获取 workers.dev 子域」 | 账号没启用 workers.dev 子域：控制台 → Workers & Pages → 域名与路由 → 开启 |
| 「测试出口」失败但部署成功 | 本机到 workers.dev 不通（网络问题）；relay 条目本身在云端，服务端侧仍可能正常——用**账号实际请求**验证 |
| 切区域后地址没变 | 正常：区域只改 Worker 的部署位置提示（Cloudflare 尽力而为，不保证精确），URL 不变 |

---

## 组合部署示例（公网 + Relay）

一台内网机器，既要公网访问面板，又要出站走 Relay：

```yaml
# docker-compose.yml
services:
  agent2api:
    image: aimodcc/agent2api:latest
    restart: unless-stopped
    ports:
      - "3065:3065"          # 内网访问入口（可选）
    environment:
      # —— 公网入口（第一部分）——
      AGENT2API_CLOUDFLARED_ENABLED: "1"
      AGENT2API_CLOUDFLARED_TOKEN: "eyJhbGciOi..."
      # —— 数据 ——
      AGENT2API_PROXY_HOME: /data
    volumes:
      - ./data:/data
```

启动后：面板管理员注册 → 建 API Key → 网络代理页一键部署 Relay → 给账号配 relay 出口。公网客户端用 `https://你的域名/v1`，出站走 Cloudflare 边缘——**两端都过 Cloudflare，本机不开任何端口也能用**（`ports` 都可以注释掉，仅保留 Tunnel 入口）。

---

## 相关文档

- 安装与部署总览：[install.md](./install.md)（三种形态 + 环境变量总表）
- Cloudflare Tunnel 快速参考：install.md 的「Cloudflare Tunnel（可选）」小节
- 上游与网络问题排查：面板「网络代理」页的测试按钮 + 「日志」页
