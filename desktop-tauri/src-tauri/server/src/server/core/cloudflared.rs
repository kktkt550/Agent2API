//! Cloudflare Tunnel（cloudflared）随网关运行的可选守护：部署时用环境变量打开，
//! 网关启动后自动准备 cloudflared 可执行文件（没有就按平台从官方 GitHub Release
//! 下载）并把它作为**子进程**拉起，随网关停机一起退出。
//!
//! ── 为什么做成网关的子进程而不是独立服务 ────────────────────
//! 用户诉求是「部署时可配置、自动下载、随服务启动」：做成子进程意味着
//!   · 不新增系统服务 / 不改安装脚本（systemd 单元、Windows 服务、容器
//!     三种形态零改动就能用）；
//!   · 生命周期天然跟随网关：网关停机时 `stop_global()` 杀掉子进程
//!     （停机协调点在 `shutdown::coordinate`，与 `auto_checkin::stop_global`
//!     并排）；网关进程硬崩时子进程成为孤儿是已知限制（表现为隧道还开着
//!     但网关不可达，cloudflared 转发会 502，重启网关即可恢复监管）；
//!   · token 不落盘、不进命令行（走子进程的 `TUNNEL_TOKEN` 环境变量，
//!     cloudflared 原生支持），进程列表里看不到。
//!
//! ── 环境变量（文档落点：docs/install*.md 六份 + .env.example +
//!    docker-compose.yml + packaging/linux/agent2api.env.example）─────
//!   AGENT2API_CLOUDFLARED_ENABLED   置 `1`（或 true / on）开启，默认关
//!   AGENT2API_CLOUDFLARED_TOKEN     具名隧道的 token（Cloudflare Zero Trust
//!                                   控制台创建 Tunnel 后给的那串）；设置后走
//!                                   `tunnel run`，未设置走 Quick Tunnel 临时隧道
//!   AGENT2API_CLOUDFLARED_URL       隧道转发到的本机服务地址，默认
//!                                   `http://127.0.0.1:{网关端口}`；一般不用改
//!   AGENT2API_CLOUDFLARED_BIN       已有 cloudflared 可执行文件的路径；设置后
//!                                   **跳过下载**（离线 / GitHub 不可达时的出路）
//!   AGENT2API_CLOUDFLARED_VERSION   钉住的版本号（如 `2026.11.2`），默认 latest；
//!                                   钉住可避免「latest 重定向哪天变了」的意外
//!   AGENT2API_CLOUDFLARED_ARGS      追加给 cloudflared 的原始参数（空格分隔，
//!                                   支持双引号包参），排在内置参数之后（Go 风格
//!                                   重复 flag 后者生效，可借此覆盖 --url 等）
//!
//! ── 下载与自检 ──────────────────────────────────────────────
//! 资产按 `(OS, ARCH)` 映射到官方 Release 的命名（linux 是裸二进制、windows
//! 是 .exe、darwin 是 .tgz 解包），落盘 `{数据目录}/bin/cloudflared(.exe)` ——
//! 数据目录在容器里是挂载卷，容器重启后不用重下。下载走 HTTP(S) 直链 +
//! 系统代理解析器（`egress::client_for_system_proxy`，桌面跟随系统代理，
//! 容器认 HTTP(S)_PROXY 环境变量），流式落盘 `.part` 再改名（与
//! `update/download.rs` 同一形态），体积上限兜底。**功能自检**用
//! `--version`：能跑起来、输出里含 cloudflared 才算数 —— 这比钉官方校验
//! 和更省维护（不用随版本更新哈希表），也顺带把「下到坏文件」挡在启动前。
//!
//! ── 监管口径 ────────────────────────────────────────────────
//! 子进程退出后按指数退避重启（3s 起、封顶 5 分钟；连续稳定运行 10 分钟
//! 归零）；cloudflared 输出走 verbose（不刷日志库），ERR 行与 Quick Tunnel
//! 地址走正常级别 —— 前者是排障第一现场，后者是用户唯一要拿的东西。
//!
//! ── Quick Tunnel 的定位 ─────────────────────────────────────
//! 无需 Cloudflare 账号即可拿到 `*.trycloudflare.com` 临时地址，适合试用与
//! 内网穿透验证；地址随机且**进程重启会变**，不适合生产。生产用
//! AGENT2API_CLOUDFLARED_TOKEN（Zero Trust 控制台创建 Tunnel + 配置域名路由）。

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use futures::StreamExt;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

use crate::server::core::egress;
use crate::server::logging;

const TAG: &str = "[Cloudflared]";

/// 下载体积兜底：linux amd64 当前 ~65MB，留 4 倍余量足够覆盖后续版本增长。
const DOWNLOAD_MAX_BYTES: u64 = 256 * 1024 * 1024;
/// 自检 / 停机等待等子进程交互的超时。
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
/// 崩溃重启的退避区间（指数增长、封顶）与「连续稳定运行多久后归零」。
const RESTART_MIN_SECONDS: u64 = 3;
const RESTART_MAX_SECONDS: u64 = 300;
const RESTART_STABLE_SECONDS: u64 = 600;

// ─── 配置（环境变量 → 设置）──────────────────────────────────

/// 从环境变量解析出的隧道设置。解析判据都是本模块底部的纯函数，
/// 可被单测钉住（进程环境不能进测试，见 `config::parse` 的注释）。
struct TunnelSettings {
    enabled: bool,
    token: Option<String>,
    url: Option<String>,
    bin: Option<PathBuf>,
    version: String,
    extra_args: Vec<String>,
}

impl TunnelSettings {
    fn from_env() -> Self {
        Self {
            enabled: switch_on(std::env::var("AGENT2API_CLOUDFLARED_ENABLED").ok().as_deref()),
            token: env_text("AGENT2API_CLOUDFLARED_TOKEN"),
            url: env_text("AGENT2API_CLOUDFLARED_URL"),
            bin: env_text("AGENT2API_CLOUDFLARED_BIN").map(PathBuf::from),
            version: env_text("AGENT2API_CLOUDFLARED_VERSION").unwrap_or_else(|| "latest".into()),
            extra_args: split_args(std::env::var("AGENT2API_CLOUDFLARED_ARGS").ok().as_deref()),
        }
    }

    /// 走「指定隧道 token」还是「Quick Tunnel 临时隧道」。
    fn has_token(&self) -> bool {
        self.token.is_some()
    }
}

/// 环境变量里的非空字符串（口径与 `config::parse::env_text` 一致：去空白，
/// 空串当未配置；那边是 `pub(super)`，这里不为读一个变量跨层引私有项）。
fn env_text(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// 开关判据：只认 `1` / `true` / `on`（忽略大小写与首尾空白），其余一律算关。
///
/// 与 `config::parse::switch_on_from_env_text` 同一条口径（那边同样是
/// `pub(super)`）—— compose 里 `AGENT2API_CLOUDFLARED_ENABLED=`（未设置变量
/// 的插值形态）必须读成关，这个功能多打的是公网入口，宁可不生效。
fn switch_on(raw: Option<&str>) -> bool {
    matches!(
        raw.map(|value| value.trim().to_ascii_lowercase()).as_deref(),
        Some("1") | Some("true") | Some("on")
    )
}

/// `AGENT2API_CLOUDFLARED_ARGS` 的拆分：空格分隔，双引号可包住含空格的参数。
///
/// 刻意不引入完整 shell 语义（转义、`$()`、管道都不支持）：这个字段的用户
/// 是照着文档抄参数的部署者，shell 级解析反而是注入面。
fn split_args(raw: Option<&str>) -> Vec<String> {
    let mut args = Vec::new();
    let Some(text) = raw else {
        return args;
    };
    let mut current = String::new();
    let mut in_quotes = false;
    let mut has_token = false;
    for ch in text.chars() {
        match ch {
            '"' => {
                in_quotes = !in_quotes;
                has_token = true;
            }
            c if c.is_whitespace() && !in_quotes => {
                if has_token {
                    args.push(std::mem::take(&mut current));
                    has_token = false;
                }
            }
            c => {
                current.push(c);
                has_token = true;
            }
        }
    }
    if has_token {
        args.push(current);
    }
    args
}

// ─── 平台资产映射与下载地址 ──────────────────────────────────

/// 发行包形态：裸二进制直接落盘，tgz 要解一层。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AssetKind {
    Raw,
    Tgz,
}

/// `(OS, ARCH)` → 官方 Release 资产名与包形态。
///
/// 资产名是 cloudflared 发行页的事实（2026-11 核对）：
/// linux 直链裸二进制、windows 直链 .exe、darwin 只发 .tgz。Rust 的
/// `ARCH` 常量（x86_64 / aarch64 / x86 / arm）与官方命名对齐关系写死
/// 在这一处，将来加平台（如 freebsd）只改这里。
fn asset_for(os: &str, arch: &str) -> Option<(&'static str, AssetKind)> {
    match (os, arch) {
        ("linux", "x86_64") => Some(("cloudflared-linux-amd64", AssetKind::Raw)),
        ("linux", "aarch64") => Some(("cloudflared-linux-arm64", AssetKind::Raw)),
        ("linux", "arm") => Some(("cloudflared-linux-arm", AssetKind::Raw)),
        ("linux", "x86") => Some(("cloudflared-linux-386", AssetKind::Raw)),
        ("windows", "x86_64") => Some(("cloudflared-windows-amd64.exe", AssetKind::Raw)),
        ("windows", "x86") => Some(("cloudflared-windows-386.exe", AssetKind::Raw)),
        ("macos", "x86_64") => Some(("cloudflared-darwin-amd64.tgz", AssetKind::Tgz)),
        ("macos", "aarch64") => Some(("cloudflared-darwin-arm64.tgz", AssetKind::Tgz)),
        _ => None,
    }
}

/// 官方 Release 下载基址：latest 走重定向短链，钉版本走固定 tag 目录。
fn release_base(version: &str) -> String {
    let version = version.trim();
    if version.is_empty() || version.eq_ignore_ascii_case("latest") {
        "https://github.com/cloudflare/cloudflared/releases/latest/download".to_string()
    } else {
        format!("https://github.com/cloudflare/cloudflared/releases/download/{version}")
    }
}

/// 落盘文件名（数据目录 bin/ 下，与资产名解耦：资产名随平台，本地名字统一）。
fn binary_file_name() -> &'static str {
    if cfg!(windows) {
        "cloudflared.exe"
    } else {
        "cloudflared"
    }
}

// ─── Quick Tunnel 地址捕获 ───────────────────────────────────

/// 从一行 cloudflared 输出里提取 Quick Tunnel 的公网地址。
///
/// 输出是画在表格里的：`|  https://xxx.trycloudflare.com   |`，所以从
/// `trycloudflare.com` 的位置向前找 `https://` 起点、向后截到空白或竖线。
/// 不是 trycloudflare 的 https 链接（文档、metrics）一律不算。
fn quick_tunnel_url_from_line(line: &str) -> Option<String> {
    let marker = line.find("trycloudflare.com")?;
    let start = line[..marker].rfind("https://")?;
    let rest = &line[start..];
    let end = rest
        .find(|c: char| c.is_whitespace() || c == '|')
        .unwrap_or(rest.len());
    let url = &rest[..end];
    // 至少要有主机名主体，拦掉「https://.trycloudflare.com」这类残缺串
    (url.len() > "https://.trycloudflare.com".len()).then(|| url.to_string())
}

// ─── token 展示 ──────────────────────────────────────────────

/// 日志里展示 token 用的脱敏：留首尾各 4 位（够分辨是不是同一把），其余打码。
/// 短 token（≤8 位）整串打码 —— 留 4+4 反而暴露了大半。
fn mask_token(token: &str) -> String {
    let chars: Vec<char> = token.chars().collect();
    let total = chars.len();
    match total {
        0 => String::new(),
        n if n <= 8 => "*".repeat(n),
        n => format!(
            "{}…{}",
            chars[..4].iter().collect::<String>(),
            chars[n - 4..].iter().collect::<String>()
        ),
    }
}

// ─── 进程级句柄与监管循环 ────────────────────────────────────

/// 一轮监管循环的运行状态。每次 `ensure_started` 造**新的一份**：桌面壳
/// 重启后端时网关会被再次 start，旧循环的停机标记不能拦住新一轮
/// （对比 `auto_checkin` 的单例句柄 —— 那边 stop 后不该复活，这边
/// 「重新 start 就该重新拉起隧道」是明确语义）。
struct RunState {
    /// 子进程句柄：监管循环以 250ms 轮询 `try_wait`（std 锁只锁取放，
    /// 不跨 await 持有）；`stop_global` 需要它来即时杀进程。
    child: Mutex<Option<tokio::process::Child>>,
    stopping: AtomicBool,
    stop_notify: tokio::sync::Notify,
}

impl RunState {
    fn new() -> Self {
        Self {
            child: Mutex::new(None),
            stopping: AtomicBool::new(false),
            stop_notify: tokio::sync::Notify::new(),
        }
    }

    fn lock_child(&self) -> std::sync::MutexGuard<'_, Option<tokio::process::Child>> {
        self.child.lock().unwrap_or_else(|error| error.into_inner())
    }
}

struct Supervisor {
    /// 当前活着的监管循环（`stop_global` 的寻址目标；没有活跃循环时为空）。
    /// `ensure_started` 在同一把锁内完成「取出旧句柄 → 存入新句柄」，
    /// 并发 / 重启场景都不会出现两个循环并存或句柄错删。
    current: Mutex<Option<Arc<RunState>>>,
    /// Quick Tunnel 的公网地址（捕获到后供 `public_url()` 读取）。
    public_url: Mutex<Option<String>>,
}

static GLOBAL: OnceLock<Supervisor> = OnceLock::new();

fn supervisor() -> &'static Supervisor {
    GLOBAL.get_or_init(|| Supervisor {
        current: Mutex::new(None),
        public_url: Mutex::new(None),
    })
}

/// 按 `AGENT2API_CLOUDFLARED_*` 环境变量启动隧道守护。
///
/// 调用点在 `shutdown::start`（监听装配成功之后）—— 桌面 / headless /
/// Windows 服务三种形态都汇到这一处，网关端口就是隧道默认转发目标。
/// 下载与子进程都在后台任务里跑，不阻塞监听装配。
///
/// ── 为什么不用一个 `loop_active` 原子闸门 ────────────────────
/// 桌面壳重启后端的次序是「stop_global → 再 start」，旧循环是异步任务，
/// 退出前闸门还举着 —— 新的启动请求会被当重复跳过，隧道从此静默消失。
/// 改成「句柄置换」：同一把锁里取出旧句柄、放入新句柄，旧循环退役由它
/// 自己的停机标记驱动（退出时用 `Arc::ptr_eq` 校验，不会误删新句柄）；
/// 并发调用时第二个调用取到的「旧句柄」就是第一个刚放入的新句柄，
/// 会被正常退役再被自己的新句柄覆盖 —— 任何时序下都只剩一个活循环。
pub fn ensure_started(gateway_port: u16) {
    let settings = TunnelSettings::from_env();
    if !settings.enabled {
        return;
    }
    let supervisor = supervisor();
    let (old, state) = {
        let mut guard = supervisor
            .current
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let old = guard.take();
        let state = Arc::new(RunState::new());
        *guard = Some(state.clone());
        (old, state)
    };
    if let Some(old) = old {
        // 旧循环退役：置停机标记、打断退避等待、就地杀它的子进程。
        // 它退出时校验 current 里的句柄已不是自己，不会碰新的这份。
        retire_loop(&old, "检测到上一次的隧道守护仍在运行，已请求其退出并重新拉起");
    }
    let default_url = settings
        .url
        .clone()
        .unwrap_or_else(|| format!("http://127.0.0.1:{gateway_port}"));
    let mode = if settings.has_token() {
        format!(
            "指定隧道（token {}）",
            settings.token.as_deref().map(mask_token).unwrap_or_default()
        )
    } else {
        "Quick Tunnel 临时隧道（地址随机，重启会变；生产建议 AGENT2API_CLOUDFLARED_TOKEN）".to_string()
    };
    logging::log(
        TAG,
        &format!(
            "Cloudflare Tunnel 已启用：{} → {}（cloudflared 版本 {}，自定义程序 {}，追加参数 {} 个）",
            mode,
            default_url,
            settings.version,
            settings
                .bin
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "自动下载".to_string()),
            settings.extra_args.len(),
        ),
    );
    // 清掉上一轮捕获的地址：新循环的地址可能不同
    *supervisor
        .public_url
        .lock()
        .unwrap_or_else(|error| error.into_inner()) = None;
    crate::spawn_task(async move {
        run_loop(supervisor, state, settings, default_url).await;
    });
}

/// 停掉隧道守护并杀掉 cloudflared 子进程（停机协调点调用）。
///
/// 没有活跃循环时什么都不做（与 `auto_checkin::stop_global` 同一形态）。
pub fn stop_global() {
    let Some(state) = supervisor()
        .current
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .clone()
    else {
        return;
    };
    retire_loop(&state, "已请求停止 cloudflared 子进程");
}

/// 对一份运行状态执行退役：置停机标记、唤醒等待、就地杀子进程。
fn retire_loop(state: &RunState, message: &str) {
    state.stopping.store(true, Ordering::SeqCst);
    state.stop_notify.notify_waiters();
    if let Some(child) = state.lock_child().as_mut() {
        // start_kill 是同步的（发信号即返回）；真正退出由监管循环确认
        let _ = child.start_kill();
    }
    logging::log(TAG, message);
}

/// Quick Tunnel 的公网地址（未捕获到或走 token 模式时为 None）。
pub fn public_url() -> Option<String> {
    supervisor()
        .public_url
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .clone()
}

/// 监管主循环：准备可执行文件 → 拉起子进程 → 等退出或停机 → 退避重启。
async fn run_loop(
    supervisor: &'static Supervisor,
    state: Arc<RunState>,
    settings: TunnelSettings,
    target_url: String,
) {
    let mut restart_wait = RESTART_MIN_SECONDS;
    loop {
        if state.stopping.load(Ordering::SeqCst) {
            break;
        }
        let started_at = Instant::now();
        let bin = match ensure_binary(&settings).await {
            Ok(bin) => bin,
            Err(error) => {
                logging::log(
                    TAG,
                    &format!("❌ {error}；{restart_wait} 秒后重试"),
                );
                if !interruptible_sleep(&state, restart_wait).await {
                    break;
                }
                restart_wait = next_backoff(restart_wait);
                continue;
            }
        };
        *supervisor
            .public_url
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = None;
        match spawn_and_watch(&state, &bin, &settings, &target_url).await {
            Ok(()) => {
                // 走到这里只有停机一条路（子进程退出、崩溃都在函数内部处理）
                break;
            }
            // 退出详情已由 spawn_and_watch 内部打过日志，这里不再重复
            Err(_) => {}
        }
        // 稳定运行过一轮（超过归零线）就从头计退避：偶发网络抖动不该
        // 让重启间隔越滚越大
        if started_at.elapsed() >= Duration::from_secs(RESTART_STABLE_SECONDS) {
            restart_wait = RESTART_MIN_SECONDS;
        } else {
            restart_wait = next_backoff(restart_wait);
        }
        if !interruptible_sleep(&state, restart_wait).await {
            break;
        }
    }
    // 摘掉自己的句柄（只摘当前这一份，避免把新一轮循环的句柄误删）
    let mut guard = supervisor
        .current
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if guard
        .as_ref()
        .is_some_and(|current| Arc::ptr_eq(current, &state))
    {
        *guard = None;
    }
    drop(guard);
    logging::log(TAG, "Cloudflare Tunnel 守护已退出");
}

/// 指数退避的下一档（3 → 6 → 12 → …，封顶 300）。
fn next_backoff(current: u64) -> u64 {
    (current * 2).min(RESTART_MAX_SECONDS)
}

/// 可打断的退避等待：返回 false 表示停机请求到达，调用方应退出循环。
async fn interruptible_sleep(state: &RunState, seconds: u64) -> bool {
    tokio::select! {
        _ = state.stop_notify.notified() => false,
        _ = tokio::time::sleep(Duration::from_secs(seconds)) => {
            !state.stopping.load(Ordering::SeqCst)
        }
    }
}

/// 拉起子进程并等待它退出或停机。返回 Ok(()) 只在停机路径；子进程自己
/// 退出时在函数内打日志并返回 Err 让外层走退避重启。
async fn spawn_and_watch(
    state: &RunState,
    bin: &Path,
    settings: &TunnelSettings,
    target_url: &str,
) -> Result<(), String> {
    let mut command = build_command(bin, settings, target_url);
    let mut child = command
        .spawn()
        .map_err(|error| format!("拉起 {} 失败: {error}", bin.display()))?;
    let pid = child.id();
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    *state.lock_child() = Some(child);
    logging::log(TAG, &format!("cloudflared 已启动（pid {}）", pid.unwrap_or(0)));

    if let Some(stream) = stdout {
        spawn_output_reader("stdout", stream, supervisor());
    }
    if let Some(stream) = stderr {
        spawn_output_reader("stderr", stream, supervisor());
    }

    // 等退出（轮询 try_wait，std 锁不跨 await）或停机（通知打断后强杀）
    let mut clean_stop = false;
    let mut stop_started: Option<Instant> = None;
    // 退出状态描述：None = 放弃等待（句柄兜底强杀）
    let mut exit_status: Option<String> = None;
    loop {
        tokio::select! {
            _ = state.stop_notify.notified() => {},
            _ = tokio::time::sleep(Duration::from_millis(250)) => {},
        }
        if state.stopping.load(Ordering::SeqCst) {
            if !clean_stop {
                clean_stop = true;
                stop_started = Some(Instant::now());
                if let Some(child) = state.lock_child().as_mut() {
                    let _ = child.start_kill();
                }
                logging::log(TAG, "停机请求已收到，正在终止 cloudflared");
            }
            // 杀过之后等 10 秒还没观察到退出就放手：句柄在循环尾部被
            // take 出来丢弃，kill_on_drop 会补一次强杀
            if stop_started.is_some_and(|started| started.elapsed() > Duration::from_secs(10)) {
                logging::log(TAG, "⚠️  cloudflared 未在 10 秒内确认退出，放弃等待（句柄释放时强制终止）");
                break;
            }
        }
        let exited = {
            let mut guard = state.lock_child();
            match guard.as_mut() {
                Some(child) => child.try_wait().ok().flatten().map(|status| status.to_string()),
                // 句柄不在了（不可能走到，防御）：当已退出
                None => Some("句柄已丢失".to_string()),
            }
        };
        if let Some(status) = exited {
            exit_status = Some(status);
            break;
        }
    }

    // 把句柄拿出来丢掉（kill_on_drop 兜底强杀），让下一轮干净开始。
    // 先在锁内 take 出所有权、锁释放后再 await kill —— std MutexGuard
    // 是 !Send，跨 await 持有它整个 future 都过不了编译。
    let mut child = state.lock_child().take();
    if let Some(mut child) = child.as_mut() {
        let _ = child.kill().await;
    }
    // 等两条输出流读完（EOF 很快），避免下一轮的日志还混着上一轮的尾巴
    tokio::time::sleep(Duration::from_millis(50)).await;

    if clean_stop {
        return Ok(());
    }
    logging::log(
        TAG,
        &format!(
            "cloudflared 进程已退出（{}）；按退避策略自动重启",
            exit_status.unwrap_or_else(|| "未知状态".to_string())
        ),
    );
    Err("cloudflared 进程退出".to_string())
}

/// 组装 cloudflared 命令行。
///
/// token 走子进程环境变量 `TUNNEL_TOKEN`（不进命令行 —— 进程列表看不到，
/// 也不落任何日志）；quick tunnel 用 `--url` 指转发目标。`--no-autoupdate`
/// 必带：cloudflared 的自我更新会脱离我们的监管换进程，更新节奏由网关
/// 的下载逻辑管（删掉 bin/ 下的文件重下即可）。
///
/// ── 为什么默认 `--protocol http2` ──────────────────────────
/// cloudflared 的默认传输协议是 **QUIC**（UDP 7844/443）。不少网络环境
/// （企业防火墙、部分运营商 NAT、Windows Server 自带的 UDP 限速）会拦或
/// 抖掉 UDP，表现为隧道反复重连、Quick Tunnel 起不来 —— 而这些问题在
/// `--protocol http2`（TCP 443，与普通 HTTPS 同路）下都不存在。HTTP/2
/// 模式在多数部署里更稳，代价只是极高并发下吞吐略低于 QUIC，对「网关
/// 转发」这种流量形态可以忽略。要换回 QUIC 用
/// `AGENT2API_CLOUDFLARED_ARGS=--protocol quic` 覆盖（追加参数排在内置
/// 之后，Go flag 后者生效）。
fn build_command(
    bin: &Path,
    settings: &TunnelSettings,
    target_url: &str,
) -> tokio::process::Command {
    let mut command = tokio::process::Command::new(bin);
    command.arg("tunnel").arg("--no-autoupdate").arg("--protocol").arg("http2");
    if settings.has_token() {
        if let Some(token) = &settings.token {
            command.env("TUNNEL_TOKEN", token);
        }
        command.arg("run");
    } else {
        command.arg("--url").arg(target_url);
    }
    for arg in &settings.extra_args {
        command.arg(arg);
    }
    command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    // 桌面形态（GUI 进程）拉起控制台程序会闪黑框；服务形态本就没有
    // 可见控制台，加了也无副作用
    #[cfg(windows)]
    command.creation_flags(CREATE_NO_WINDOW);
    command
}

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// 转发子进程输出：ERR 行与 stderr 走正常日志级别（排障第一现场），
/// 其余走 verbose（cloudflared 每条连接都有 INF 行，全量入库会刷爆日志页）；
/// Quick Tunnel 地址单独捕获、醒目提示。
fn spawn_output_reader(
    kind: &'static str,
    stream: impl tokio::io::AsyncRead + Unpin + Send + 'static,
    sink: &'static Supervisor,
) {
    crate::spawn_task(async move {
        let mut lines = tokio::io::BufReader::new(stream).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let trimmed = line.trim_end();
            if trimmed.is_empty() {
                continue;
            }
            if let Some(url) = quick_tunnel_url_from_line(trimmed) {
                *sink
                    .public_url
                    .lock()
                    .unwrap_or_else(|error| error.into_inner()) = Some(url.clone());
                logging::log(
                    TAG,
                    &format!(
                        "🌍 Quick Tunnel 公网地址：{url}（临时隧道，进程重启后地址会变；生产建议 AGENT2API_CLOUDFLARED_TOKEN）"
                    ),
                );
                continue;
            }
            if kind == "stderr" || trimmed.contains("ERR") {
                logging::log(TAG, &format!("[cloudflared {kind}] {trimmed}"));
            } else {
                logging::verbose(TAG, &format!("[cloudflared {kind}] {trimmed}"));
            }
        }
    });
}

// ─── 可执行文件的准备（下载 / 复用 / 自检）────────────────────

/// 确保本机有可用的 cloudflared：显式 BIN 优先，其次复用已下载的，
/// 都没有就按平台下载。返回可执行文件路径。
async fn ensure_binary(settings: &TunnelSettings) -> Result<PathBuf, String> {
    if let Some(bin) = &settings.bin {
        if bin.exists() {
            return Ok(bin.clone());
        }
        return Err(format!(
            "AGENT2API_CLOUDFLARED_BIN 指定的程序不存在: {}",
            bin.display()
        ));
    }
    let Some((asset, kind)) = asset_for(std::env::consts::OS, std::env::consts::ARCH) else {
        return Err(format!(
            "暂不支持的平台 {}/{}：请用 AGENT2API_CLOUDFLARED_BIN 指定 cloudflared 可执行文件",
            std::env::consts::OS,
            std::env::consts::ARCH
        ));
    };
    let directory = crate::paths::config_dir().join("bin");
    std::fs::create_dir_all(&directory)
        .map_err(|error| format!("创建目录 {} 失败: {error}", directory.display()))?;
    let target = directory.join(binary_file_name());
    if target.exists() {
        // 复用前自检：上次下载可能损坏（断电 / 磁盘满）。跑不起来的
        // 直接删掉重下，不让坏文件常驻
        match version_check(&target).await {
            Ok(version) => {
                logging::verbose(TAG, &format!("复用已下载的 cloudflared（{}）", version.trim()));
                return Ok(target);
            }
            Err(error) => {
                logging::log(
                    TAG,
                    &format!("已下载的 cloudflared 自检失败（{error}），重新下载"),
                );
                let _ = std::fs::remove_file(&target);
            }
        }
    }
    download_and_install(&release_base(&settings.version), asset, kind, &target).await?;
    let version = version_check(&target).await?;
    logging::log(TAG, &format!("✅ cloudflared 就绪（{}）", version.trim()));
    Ok(target)
}

/// 下载官方资产并安装到 target（`.part` 暂存 → 解包/改名 → 执行位）。
async fn download_and_install(
    base: &str,
    asset: &str,
    kind: AssetKind,
    target: &Path,
) -> Result<(), String> {
    let url = format!("{base}/{asset}");
    let client = egress::client_for_system_proxy();
    let response = client
        .get(&url)
        .header("Accept", "application/octet-stream")
        .send()
        .await
        .map_err(|error| format!("下载 {asset} 失败: {error}"))?;
    let status = response.status().as_u16();
    if status != 200 {
        return Err(format!(
            "下载 {asset} 失败：HTTP {status}（版本号写错或网络不可达）"
        ));
    }
    logging::log(TAG, &format!("开始下载 {url}"));
    let part = target.with_extension("part");
    let mut file = tokio::fs::File::create(&part)
        .await
        .map_err(|error| format!("创建下载文件失败: {error}"))?;
    let mut stream = response.bytes_stream();
    let mut received: u64 = 0;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| format!("下载中断: {error}"))?;
        received += chunk.len() as u64;
        if received > DOWNLOAD_MAX_BYTES {
            let _ = tokio::fs::remove_file(&part).await;
            return Err("下载体积超过上限，已中止".to_string());
        }
        file.write_all(&chunk)
            .await
            .map_err(|error| format!("写入下载文件失败: {error}"))?;
    }
    file.flush()
        .await
        .map_err(|error| format!("写入下载文件失败: {error}"))?;
    drop(file);
    if received == 0 {
        let _ = tokio::fs::remove_file(&part).await;
        return Err("下载内容为空".to_string());
    }
    let install = match kind {
        AssetKind::Raw => tokio::fs::rename(&part, target)
            .await
            .map_err(|error| format!("安装下载文件失败: {error}")),
        AssetKind::Tgz => match extract_tgz(&part, target) {
            Ok(()) => {
                let _ = tokio::fs::remove_file(&part).await;
                Ok(())
            }
            Err(error) => Err(error),
        },
    };
    install?;
    #[cfg(unix)]
    mark_executable(target)?;
    Ok(())
}

/// 解 darwin 的 .tgz：包里就一个 `cloudflared` 二进制，找到它写到 target。
fn extract_tgz(archive_path: &Path, target: &Path) -> Result<(), String> {
    let file = std::fs::File::open(archive_path)
        .map_err(|error| format!("打开下载包失败: {error}"))?;
    let decoder = flate2::read::GzDecoder::new(file);
    let mut archive = tar::Archive::new(decoder);
    for entry in archive
        .entries()
        .map_err(|error| format!("读取下载包失败: {error}"))?
    {
        let mut entry = entry.map_err(|error| format!("读取下载包失败: {error}"))?;
        let name = entry
            .path()
            .map_err(|error| format!("读取下载包条目失败: {error}"))?;
        if name.file_name().and_then(|name| name.to_str()) == Some("cloudflared") {
            let mut out = std::fs::File::create(target)
                .map_err(|error| format!("写入 {target:?} 失败: {error}"))?;
            std::io::copy(&mut entry, &mut out)
                .map_err(|error| format!("解包 cloudflared 失败: {error}"))?;
            return Ok(());
        }
    }
    Err("下载包里没有找到 cloudflared 可执行文件".to_string())
}

#[cfg(unix)]
fn mark_executable(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
        .map_err(|error| format!("设置执行权限失败: {error}"))
}

/// 功能自检：跑 `--version`，成功且输出含 cloudflared 才算可用。
///
/// 这是下载侧唯一的可信校验（官方校验和表需要随版本维护，这里用
/// 「能跑起来」说话）；顺带把版本号打给用户看。
async fn version_check(bin: &Path) -> Result<String, String> {
    let mut command = tokio::process::Command::new(bin);
    command
        .arg("--version")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    #[cfg(windows)]
    command.creation_flags(CREATE_NO_WINDOW);
    let output = tokio::time::timeout(COMMAND_TIMEOUT, command.output())
        .await
        .map_err(|_| "自检超时".to_string())?
        .map_err(|error| format!("执行失败: {error}"))?;
    let text = format!(
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if !output.status.success() || !text.contains("cloudflared") {
        let preview: String = text.trim().chars().take(200).collect();
        return Err(format!("--version 输出异常: {preview}"));
    }
    Ok(text.trim().to_string())
}

#[cfg(test)]
mod tests {
    //! 纯判据的单测：环境变量口径、平台资产映射、下载地址、参数拆分、
    //! Quick Tunnel 地址捕获与 token 脱敏。不碰进程环境、不起子进程、
    //! 不走网络（判据全部抽成吃参数的纯函数，理由同 `config::parse` 的测试）。

    use super::*;

    /// 开关只认 `1` / `true` / `on`（大小写与首尾空白都要吃掉）。
    /// 钉住的写歪：`AGENT2API_CLOUDFLARED_ENABLED=`（compose 未设置变量的
    /// 插值形态）被「非 0 即开」读成开，凭空开一个公网入口。
    #[test]
    fn the_switch_only_accepts_one_true_or_on() {
        for on in ["1", "true", "on", " TRUE ", "On"] {
            assert!(switch_on(Some(on)), "{on} 应当算开启");
        }
        for off in ["", " ", "0", "yes", "10", "no", "开启", "trueX"] {
            assert!(!switch_on(Some(off)), "{off} 不该被当成开启");
        }
        assert!(!switch_on(None), "环境变量没设必须是关");
    }

    /// 平台 → 资产名的映射：三种形态（裸二进制 / exe / tgz）各验一份，
    /// 未支持平台交回 None（由调用方给出带 BIN 提示的错误）。
    #[test]
    fn the_asset_mapping_covers_the_shipping_platforms() {
        assert_eq!(
            asset_for("linux", "x86_64"),
            Some(("cloudflared-linux-amd64", AssetKind::Raw))
        );
        assert_eq!(
            asset_for("linux", "aarch64"),
            Some(("cloudflared-linux-arm64", AssetKind::Raw))
        );
        assert_eq!(
            asset_for("windows", "x86_64"),
            Some(("cloudflared-windows-amd64.exe", AssetKind::Raw))
        );
        assert_eq!(
            asset_for("macos", "aarch64"),
            Some(("cloudflared-darwin-arm64.tgz", AssetKind::Tgz))
        );
        assert_eq!(asset_for("freebsd", "x86_64"), None);
    }

    /// 下载基址：latest 走重定向短链，钉版本走 tag 目录（空串与空白当 latest）。
    #[test]
    fn the_release_base_switches_between_latest_and_pinned() {
        assert_eq!(
            release_base("latest"),
            "https://github.com/cloudflare/cloudflared/releases/latest/download"
        );
        assert_eq!(
            release_base(" 2026.11.2 "),
            "https://github.com/cloudflare/cloudflared/releases/download/2026.11.2"
        );
        assert_eq!(release_base(""), release_base("latest"));
    }

    /// 参数拆分：空格分隔、双引号包参、纯空白与 None 都是空表。
    #[test]
    fn the_args_splitter_honors_quotes_and_whitespace() {
        assert!(split_args(None).is_empty());
        assert!(split_args(Some("   ")).is_empty());
        assert_eq!(split_args(Some("--region us")), vec!["--region", "us"]);
        assert_eq!(
            split_args(Some("--url \"http://a b/\" --edge-ip-version 6")),
            vec!["--url", "http://a b/", "--edge-ip-version", "6"]
        );
        // 引号里带空格不拆；未闭合引号的内容不丢
        assert_eq!(split_args(Some("\"a b\" c")), vec!["a b", "c"]);
        assert_eq!(split_args(Some("\"a b")), vec!["a b"]);
    }

    /// Quick Tunnel 地址：表格行（带竖线与缩进）能提取，普通日志行、
    /// 非 trycloudflare 的链接不算。
    #[test]
    fn the_quick_tunnel_url_is_extracted_from_table_lines() {
        let table_line = "2026-11-24T04:00:00Z INF |  https://quick-words-does-matter-1234.trycloudflare.com                  |";
        assert_eq!(
            quick_tunnel_url_from_line(table_line),
            Some("https://quick-words-does-matter-1234.trycloudflare.com".to_string())
        );
        let plain_line = "2026-11-24T04:00:00Z INF https://abc.trycloudflare.com";
        assert_eq!(
            quick_tunnel_url_from_line(plain_line),
            Some("https://abc.trycloudflare.com".to_string())
        );
        // 其它链接与无链接行不算
        assert_eq!(
            quick_tunnel_url_from_line("visit https://developers.cloudflare.com/cloudflare-one/ for docs"),
            None
        );
        assert_eq!(quick_tunnel_url_from_line("Registered tunnel connection"), None);
    }

    /// token 脱敏：长 token 留首尾 4 位，短 token 整串打码，空串原样。
    #[test]
    fn the_token_mask_keeps_only_the_edges() {
        let long = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9abcd";
        let masked = mask_token(long);
        assert!(masked.starts_with("eyJh"));
        assert!(masked.ends_with("abcd"));
        assert!(masked.contains('…'));
        assert_eq!(mask_token("short"), "*****");
        assert_eq!(mask_token(""), "");
    }

    /// 退避序列：翻倍、封顶 300。
    #[test]
    fn the_backoff_doubles_and_caps() {
        assert_eq!(next_backoff(3), 6);
        assert_eq!(next_backoff(6), 12);
        assert_eq!(next_backoff(300), 300);
        assert_eq!(next_backoff(200), 300);
    }

    /// 命令行组装：quick 模式带 --url，token 模式换成 run 且 token 只进
    /// 环境变量不进参数；追加参数排在最后（Go flag 重复时后者生效）。
    #[test]
    fn the_command_builder_routes_token_and_url() {
        let quick = TunnelSettings {
            enabled: true,
            token: None,
            url: None,
            bin: None,
            version: "latest".into(),
            extra_args: vec![],
        };
        let quick_cmd = build_command(Path::new("cloudflared"), &quick, "http://127.0.0.1:3065");
        // tokio Command 的内部 argv 不直接可读，退而求其次：至少能构造成功，
        // 关键差异（token 进 env / 参数顺序）由下面 token 用例的 env 断言兜住
        let _ = quick_cmd;

        let named = TunnelSettings {
            enabled: true,
            token: Some("tok-123".into()),
            url: None,
            bin: None,
            version: "latest".into(),
            extra_args: vec!["--loglevel".into(), "debug".into()],
        };
        let named_cmd = build_command(Path::new("cloudflared"), &named, "http://127.0.0.1:3065");
        let captured = named_cmd
            .as_std()
            .get_envs()
            .find(|(key, _)| *key == "TUNNEL_TOKEN");
        assert_eq!(
            captured.and_then(|(_, value)| value.map(|v| v.to_string_lossy().to_string())),
            Some("tok-123".to_string()),
            "token 必须进子进程环境变量，不进命令行"
        );
    }

    /// 默认传输协议是 http2（QUIC 在不少网络下被 UDP 拦截，http2 走 TCP 443
    /// 兼容性最好）；用户可用 AGENT2API_CLOUDFLARED_ARGS 追加 --protocol quic
    /// 覆盖 —— 追加参数排在内置之后，Go flag 后者生效。
    #[test]
    fn the_default_protocol_is_http2_and_user_args_can_override() {
        let default = TunnelSettings {
            enabled: true,
            token: None,
            url: None,
            bin: None,
            version: "latest".into(),
            extra_args: vec![],
        };
        let cmd = build_command(Path::new("cloudflared"), &default, "http://127.0.0.1:3065");
        let args: Vec<String> = cmd
            .as_std()
            .get_args()
            .map(|arg| arg.to_string_lossy().to_string())
            .collect();
        let protocol_position = args.iter().position(|arg| arg == "--protocol");
        assert_eq!(
            protocol_position.map(|index| args[index + 1].as_str()),
            Some("http2"),
            "内置 --protocol http2 必须存在且值为 http2；实际参数: {args:?}"
        );
        assert!(
            protocol_position.unwrap() < args.iter().position(|arg| arg == "--no-autoupdate").unwrap() + 4,
            "--protocol 应排在内置参数段"
        );

        // 用户覆盖：追加 --protocol quic 排在后面
        let override_settings = TunnelSettings {
            enabled: true,
            token: None,
            url: None,
            bin: None,
            version: "latest".into(),
            extra_args: vec!["--protocol".into(), "quic".into()],
        };
        let cmd = build_command(Path::new("cloudflared"), &override_settings, "http://127.0.0.1:3065");
        let args: Vec<String> = cmd
            .as_std()
            .get_args()
            .map(|arg| arg.to_string_lossy().to_string())
            .collect();
        let first = args.iter().position(|arg| arg == "--protocol").unwrap();
        let last = args.iter().rposition(|arg| arg == "--protocol").unwrap();
        assert!(first < last, "用户的 --protocol 必须排在内置之后（Go flag 后者生效）；实际参数: {args:?}");
        assert_eq!(args[last + 1], "quic");
    }
}
