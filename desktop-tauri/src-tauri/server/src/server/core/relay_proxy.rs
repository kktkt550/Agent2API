//! Cloudflare Relay 中转（来自 Coding2API 的代理池方案）：池里的条目是
//! **HTTPS relay URL**（部署在 Cloudflare Workers 上的转发脚本），不是
//! host:port 代理。出站请求被改写成 `{relay}/{原路径}` 并注入两个头：
//!
//!   · `x-relay-target`: 原请求的 origin（如 `https://api.example.com`）
//!   · `x-relay-path`:   原请求的 path+query
//!
//! Worker 收到后取这两个头、删掉 `host`、把请求转发到真实上游（原样透传
//! body 与响应流）。它的价值：出口 IP 变成 Cloudflare 边缘的 IP，且区域
//! 可指定（`placements` hint）—— 适合「本机直连上游不通」的场景。
//!
//! ── 与 host:port 代理的关系 ─────────────────────────────────
//! 两者是**并行的两种出口形态**：host:port 走 reqwest 的 proxy 层
//! （`egress::build_client`），relay 走「URL 改写 + 头注入 + 直连 Client」。
//! 池条目的 `protocol == "relay"` 是区分标志：`ResolvedProxy.host` 存完整
//! relay URL、`port = None`。出站点（`egress::relay_rewrite` /
//! `upstream::request::send_chat_request` / `auth_http::send_raw`）见到
//! relay 形态就走改写分支，互斥地**不**走代理层 —— 不会双重代理。
//!
//! ── 凭据 ───────────────────────────────────────────────────
//! CF Account ID 与 API Token **明文**存在池条目上（`cfAccountId` /
//! `cfApiToken`；本模块是唯一读写点）。列表接口（`describe_item`）不回显
//! Token；切地区时凭据留空则用已存的。
//!
//! ── 部署协议（照搬 Coding2API relay/deploy.ts）──────────────
//!   1. `PUT /accounts/{id}/workers/scripts/{name}`（multipart：index.js +
//!      metadata，metadata.placements[0].hint = 区域 hint）
//!   2. best-effort `POST …/scripts/{name}/subdomain` `{enabled:true}`
//!   3. `GET /accounts/{id}/workers/subdomain` 取 subdomain
//!   → URL = `https://{name}.{subdomain}.workers.dev`
//! 失败归四类（凭据 / 网络 / 名称占用 / 子域），只回可读中文，不回显
//! 原始 body（可能带 Token）。

use serde_json::{json, Value};

use crate::server::logging;

const TAG: &str = "[Relay]";

/// relay 出口的协议名（池条目与 `ResolvedProxy.protocol` 都用它区分）。
pub const PROTOCOL: &str = "relay";

/// 连通性测试的固定目标（与 Coding2API 同源）：Cloudflare 自己的 trace 端点。
pub const RELAY_TRACE_TARGET: &str = "https://www.cloudflare.com";
pub const RELAY_TRACE_PATH: &str = "/cdn-cgi/trace";
/// 测试超时（毫秒）。
pub const RELAY_TEST_TIMEOUT_MS: u64 = 10_000;

/// Worker 名称合法性（与 Coding2API PROJECT_NAME_PATTERN 一致）。
pub fn is_valid_project_name(name: &str) -> bool {
    let name = name.trim();
    !name.is_empty()
        && name.len() <= 100
        && name.chars().next().is_some_and(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit())
        && name.chars().all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
}

/// 地区 hint 白名单（空串 = auto）。与 Coding2API PLACEMENT_REGIONS 一致。
const REGIONS: &[&str] = &["", "wnam", "enam", "sam", "weur", "eeur", "me", "afr", "apac", "oce"];

pub fn is_valid_region(region: &str) -> bool {
    REGIONS.contains(&region)
}

/// 地区下拉的元数据（前端用；顺序即展示顺序）。
pub fn region_options() -> Value {
    json!([
        { "value": "", "label": "自动" },
        { "value": "wnam", "label": "wnam · 北美西部" },
        { "value": "enam", "label": "enam · 北美东部" },
        { "value": "sam", "label": "sam · 南美" },
        { "value": "weur", "label": "weur · 西欧" },
        { "value": "eeur", "label": "eeur · 东欧" },
        { "value": "me", "label": "me · 中东" },
        { "value": "afr", "label": "afr · 非洲" },
        { "value": "apac", "label": "apac · 亚太" },
        { "value": "oce", "label": "oce · 大洋洲" },
    ])
}

// ─── URL 归一化与 SSRF 校验（七步，照搬 normalize.ts）──────────

/// 内网 / 回环 / 链路本地 / 组播 / 保留段（IPv4+IPv6，与 normalize.ts 同名单）。
const BLOCKED_NETWORKS: &[(&str, u8, u8)] = &[
    // (网络前缀文本, 前缀长度, 版本) —— v4 用首字节段快速判定，v6 用完整前缀
    ("0.0.0.0", 8, 4),
    ("10.0.0.0", 8, 4),
    ("100.64.0.0", 10, 4),
    ("127.0.0.0", 8, 4),
    ("169.254.0.0", 16, 4),
    ("172.16.0.0", 12, 4),
    ("192.0.0.0", 24, 4),
    ("192.0.2.0", 24, 4),
    ("192.168.0.0", 16, 4),
    ("198.18.0.0", 15, 4),
    ("198.51.100.0", 24, 4),
    ("203.0.113.0", 24, 4),
    ("224.0.0.0", 4, 4),
    ("240.0.0.0", 4, 4),
];

/// 本地域名黑名单：localhost / *.localhost / *.local / *.internal / *.home.arpa。
fn is_local_domain(hostname: &str) -> bool {
    let name = hostname.trim_end_matches('.').to_ascii_lowercase();
    matches!(name.as_str(), "localhost" | "local" | "internal" | "home.arpa")
        || name.ends_with(".localhost")
        || name.ends_with(".local")
        || name.ends_with(".internal")
        || name.ends_with(".home.arpa")
}

/// IPv4 地址是否落在某个被禁网段（前缀匹配）。
fn ipv4_in_blocked_networks(address: std::net::Ipv4Addr) -> bool {
    let bytes = address.octets();
    BLOCKED_NETWORKS.iter().any(|(network, prefix, version)| {
        if *version != 4 {
            return false;
        }
        let Ok(parsed) = network.parse::<std::net::Ipv4Addr>() else { return false };
        let target = parsed.octets();
        let full_bits = *prefix as usize;
        // 按字节比对前缀（prefix 是 4/8/10/12/15/16/24：整字节 + 残位两种情形）
        let whole = full_bits / 8;
        if bytes[..whole] != target[..whole] {
            return false;
        }
        let rest = full_bits % 8;
        if rest == 0 {
            return true;
        }
        let mask = !(0xffu8 >> rest);
        (bytes[whole] & mask) == (target[whole] & mask)
    })
}

/// IPv6 地址是否落在被禁段（回环 / 唯一本地 fc00::/7 / 链路本地 fe80::/10 / 组播）。
fn ipv6_in_blocked_networks(address: std::net::Ipv6Addr) -> bool {
    let segments = address.segments();
    // ::1 回环
    if address.is_loopback() {
        return true;
    }
    // fc00::/7：首字节 0xfc / 0xfd
    if segments[0] & 0xfe00 == 0xfc00 {
        return true;
    }
    // fe80::/10
    if segments[0] & 0xffc0 == 0xfe80 {
        return true;
    }
    // ff00::/8 组播
    if segments[0] & 0xff00 == 0xff00 {
        return true;
    }
    // :: 未指定地址
    segments.iter().all(|segment| *segment == 0)
}

/// 字面 IP（v4/v6）是否命中被禁网段。
fn is_blocked_ip(host: &str) -> bool {
    if let Ok(v4) = host.parse::<std::net::Ipv4Addr>() {
        return ipv4_in_blocked_networks(v4);
    }
    // IPv6 可能带方括号（URL hostname 不带，但归一化输入宽容处理）
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    match bare.parse::<std::net::Ipv6Addr>() {
        Ok(v6) => ipv6_in_blocked_networks(v6),
        Err(_) => false,
    }
}

/// relay URL 归一化 + SSRF 校验（七步，照搬 `normalize_relay_url`）。
/// 合法返回 `origin + pathname`（去尾斜杠）；任何一步非法返回 `None`。
///
///   1. trim + 去尾斜杠
///   2. 可解析且**仅 https**
///   3. 拒 userinfo（URL 即凭据）
///   4. hostname 非空、小写、去 IPv6 方括号
///   5. 本地域名黑名单（先于 IP 判定，防 `foo.localhost` 误判成 IPv6）
///   6. 字面 IP 命中内网 / 回环 / 保留段即拒
///   7. 返回 `origin + pathname`
pub fn normalize_relay_url(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_end_matches('/').to_string();
    if trimmed.is_empty() {
        return None;
    }
    // 2. 仅 https
    let parsed = url::Url::parse(&trimmed).ok()?;
    if parsed.scheme() != "https" {
        return None;
    }
    // 3. 拒 userinfo
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return None;
    }
    // 4. hostname 非空（url crate 已小写化、去方括号）
    let hostname = parsed.host_str()?.to_ascii_lowercase();
    if hostname.is_empty() {
        return None;
    }
    // 5. 本地域名
    if is_local_domain(&hostname) {
        return None;
    }
    // 6. 字面 IP 判定
    if is_blocked_ip(&hostname) {
        return None;
    }
    // 7. origin + pathname（去尾斜杠）
    let origin = format!("{}://{}", parsed.scheme(), match parsed.host_str()? {
        host if host.contains(':') => format!("[{host}]"),
        host => host.to_string(),
    });
    let port = match parsed.port() {
        Some(443) | None => String::new(),
        Some(port) => format!(":{port}"),
    };
    let path = parsed.path().trim_end_matches('/').to_string();
    Some(format!("{origin}{port}{path}"))
}

/// 从 relay URL 提取展示用主机名（日志 / 列表列）。
pub fn display_host(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .and_then(|parsed| parsed.host_str().map(str::to_string))
        .unwrap_or_else(|| url.to_string())
}

// ─── Relay Worker 脚本（与 deploy.ts 的 RELAY_WORKER_CODE 逐字一致）───

pub const RELAY_WORKER_CODE: &str = r#"export default {
  async fetch(request) {
    const target = request.headers.get("x-relay-target");
    const relayPath = request.headers.get("x-relay-path") || "/";

    if (!target) {
      return new Response(JSON.stringify({ error: "Missing x-relay-target header" }), {
        status: 400,
        headers: { "content-type": "application/json" },
      });
    }

    const targetUrl = target.replace(/\/$/, "") + relayPath;
    const init = {
      method: request.method,
      headers: new Headers(request.headers),
    };

    if (request.method !== "GET" && request.method !== "HEAD") {
      init.body = request.body;
      init.duplex = "half";
    }

    init.headers.delete("x-relay-target");
    init.headers.delete("x-relay-path");
    init.headers.delete("host");

    try {
      const response = await fetch(targetUrl, init);
      return new Response(response.body, {
        status: response.status,
        headers: response.headers,
      });
    } catch (error) {
      return new Response(JSON.stringify({ error: "relay upstream failed" }), {
        status: 502,
        headers: { "content-type": "application/json" },
      });
    }
  },
};
"#;

// ─── 部署（Cloudflare API）────────────────────────────────────

/// 部署失败的分类（与 Coding2API DeployErrorKind 一致）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeployErrorKind {
    Credentials,
    Network,
    NameTaken,
    Subdomain,
}

impl DeployErrorKind {
    /// 中文文案（与设计 §7.2 逐字一致；不回显原始 body / Token）。
    pub fn message(self) -> &'static str {
        match self {
            Self::Credentials => {
                "Cloudflare 凭据无效或权限不足，请确认 API Token 具备 Workers Scripts: Edit 权限"
            }
            Self::Network => "Cloudflare 接口暂时不可用或网络异常，请稍后重试",
            Self::NameTaken => "该 Worker 名称已被占用，请换一个名称",
            Self::Subdomain => {
                "Worker 已部署但无法获取 workers.dev 子域，请在 Cloudflare 控制台配置子域后重试"
            }
        }
    }
}

/// CF API 错误提取：`errors[0].message || fallback`（json 解析失败兜底 fallback）。
async fn cf_api_error(response: reqwest::Response, fallback: &str) -> String {
    match response.json::<Value>().await {
        Ok(payload) => payload
            .get("errors")
            .and_then(Value::as_array)
            .and_then(|errors| errors.first())
            .and_then(|error| error.get("message"))
            .and_then(Value::as_str)
            .filter(|text| !text.is_empty())
            .unwrap_or(fallback)
            .to_string(),
        Err(_) => fallback.to_string(),
    }
}

/// 依据 CF 响应状态 + 安全短消息归类上传失败。
fn classify_upload_failure(status: u16, detail: &str) -> DeployErrorKind {
    let lowered = detail.to_ascii_lowercase();
    if lowered.contains("10037") || lowered.contains("already exists") || lowered.contains("name") && lowered.contains("taken") {
        return DeployErrorKind::NameTaken;
    }
    if status >= 500 {
        return DeployErrorKind::Network;
    }
    if status >= 400 {
        return DeployErrorKind::Credentials;
    }
    DeployErrorKind::Network
}

fn api_base(account_id: &str) -> String {
    format!("https://api.cloudflare.com/client/v4/accounts/{}", urlencoding(account_id))
}

/// 百分号编码（与 egress 的 urlencoding 同规则；避免跨模块私有依赖）。
fn urlencoding(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        let ch = byte as char;
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '~') {
            out.push(ch);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// 上传脚本：`PUT /accounts/{id}/workers/scripts/{name}`，multipart
/// （`index.js` + `metadata`）。失败返回分类。
///
/// ⚠️ 请求体里带 API Token（Authorization 头），错误信息绝不回显原始 body。
async fn upload_relay_script(
    client: &reqwest::Client,
    account_id: &str,
    api_token: &str,
    project_name: &str,
    region: &str,
) -> Result<(), DeployErrorKind> {
    let url = format!(
        "{}/workers/scripts/{}",
        api_base(account_id),
        urlencoding(project_name)
    );
    // multipart：文件部分（index.js）+ JSON 部分（metadata）。
    // reqwest 的 async multipart（项目已启用 `multipart` feature）；
    // blocking 模块未启用，不为此加 feature。
    let metadata = json!({
        "main_module": "index.js",
        "compatibility_date": "2024-03-20",
        "observability": { "enabled": true },
        "placements": match region.trim() {
            "" => Vec::<Value>::new(),
            hint => vec![json!({ "hint": hint })],
        },
    });
    let form = reqwest::multipart::Form::new()
        .part(
            "index.js",
            reqwest::multipart::Part::text(RELAY_WORKER_CODE)
                .file_name("index.js")
                .mime_str("application/javascript+module")
                .map_err(|_| DeployErrorKind::Network)?,
        )
        .part(
            "metadata",
            reqwest::multipart::Part::text(metadata.to_string())
                .file_name("metadata.json")
                .mime_str("application/json")
                .map_err(|_| DeployErrorKind::Network)?,
        );
    let response = client
        .put(&url)
        .header("Authorization", format!("Bearer {api_token}"))
        .multipart(form)
        .timeout(std::time::Duration::from_secs(60))
        .send()
        .await
        .map_err(|_| DeployErrorKind::Network)?;
    if !response.status().is_success() {
        let status = response.status().as_u16();
        let detail = cf_api_error(response, "Failed to upload Worker to Cloudflare").await;
        return Err(classify_upload_failure(status, &detail));
    }
    Ok(())
}

/// 取 workers.dev URL：best-effort 开 subdomain，再取账户 subdomain。
async fn get_workers_dev_url(
    client: &reqwest::Client,
    account_id: &str,
    api_token: &str,
    project_name: &str,
) -> Result<String, DeployErrorKind> {
    let base = api_base(account_id);
    // best-effort：已开启时该调用可能报错，忽略
    let _ = client
        .post(format!("{}/workers/scripts/{}/subdomain", base, urlencoding(project_name)))
        .header("Authorization", format!("Bearer {api_token}"))
        .header("Content-Type", "application/json")
        .body(json!({ "enabled": true }).to_string())
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await;
    let response = client
        .get(format!("{base}/workers/subdomain"))
        .header("Authorization", format!("Bearer {api_token}"))
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .map_err(|_| DeployErrorKind::Subdomain)?;
    if !response.status().is_success() {
        return Err(DeployErrorKind::Subdomain);
    }
    let payload: Value = response
        .json()
        .await
        .map_err(|_| DeployErrorKind::Subdomain)?;
    let subdomain = payload
        .get("result")
        .and_then(|result| result.get("subdomain"))
        .and_then(Value::as_str)
        .unwrap_or("");
    if subdomain.is_empty() {
        return Err(DeployErrorKind::Subdomain);
    }
    Ok(format!("https://{project_name}.{subdomain}.workers.dev"))
}

/// 部署（或带新地区重新上传）：成功返回 workers.dev URL，失败返回分类文案。
///
/// 客户端走 `egress::client_for_system_proxy`（跟随系统代理 / HTTP(S)_PROXY）：
/// 部署是**一次性管理操作**，不是转发链路 —— 用户环境里网络代理是常态。
pub async fn deploy_relay_worker(
    account_id: &str,
    api_token: &str,
    project_name: &str,
    region: &str,
) -> Result<String, String> {
    if !is_valid_project_name(project_name) {
        return Err("Worker 名称只能包含小写字母、数字和连字符，且以字母或数字开头".to_string());
    }
    if !is_valid_region(region) {
        return Err("未知区域".to_string());
    }
    if account_id.trim().is_empty() || api_token.trim().is_empty() {
        return Err("请填写 Cloudflare Account ID 与 API Token".to_string());
    }
    let client = super::egress::client_for_system_proxy();
    upload_relay_script(&client, account_id.trim(), api_token.trim(), project_name.trim(), region.trim())
        .await
        .map_err(|kind| kind.message().to_string())?;
    let url = get_workers_dev_url(&client, account_id.trim(), api_token.trim(), project_name.trim())
        .await
        .map_err(|kind| kind.message().to_string())?;
    logging::log(
        TAG,
        &format!("✅ Relay Worker「{project_name}」部署完成（区域 {}）: {url}", if region.trim().is_empty() { "自动" } else { region.trim() }),
    );
    Ok(url)
}

#[cfg(test)]
mod tests {
    //! 纯判据单测：URL 七步校验、项目名/区域判定、IP 网段。不碰网络。

    use super::*;

    /// 七步校验：合法公网 https 通过并归一化（去尾斜杠、保留路径）。
    #[test]
    fn normal_https_urls_pass() {
        assert_eq!(
            normalize_relay_url("https://relay-abc.workers.dev"),
            Some("https://relay-abc.workers.dev".to_string())
        );
        assert_eq!(
            normalize_relay_url("https://relay-abc.workers.dev/"),
            Some("https://relay-abc.workers.dev".to_string())
        );
        assert_eq!(
            normalize_relay_url("  https://x.example.com/path/  "),
            Some("https://x.example.com/path".to_string())
        );
        assert_eq!(
            normalize_relay_url("https://x.example.com:8443/"),
            Some("https://x.example.com:8443".to_string())
        );
    }

    /// 仅 https：http 明文被拒（relay URL 本身就是凭据）。
    #[test]
    fn plain_http_is_rejected() {
        assert_eq!(normalize_relay_url("http://relay.workers.dev"), None);
        assert_eq!(normalize_relay_url("ftp://relay.workers.dev"), None);
    }

    /// userinfo 拒绝；内网 / 回环 / 本地域名拒绝；垃圾输入拒绝。
    #[test]
    fn ssrf_guards_reject_private_and_local() {
        assert_eq!(normalize_relay_url("https://user:pass@relay.workers.dev"), None);
        assert_eq!(normalize_relay_url("https://127.0.0.1/"), None);
        assert_eq!(normalize_relay_url("https://192.168.1.1/"), None);
        assert_eq!(normalize_relay_url("https://10.0.0.1/"), None);
        assert_eq!(normalize_relay_url("https://172.16.0.5/"), None);
        assert_eq!(normalize_relay_url("https://169.254.1.1/"), None);
        assert_eq!(normalize_relay_url("https://[::1]/"), None);
        assert_eq!(normalize_relay_url("https://[fe80::1]/"), None);
        assert_eq!(normalize_relay_url("https://[fc00::1]/"), None);
        assert_eq!(normalize_relay_url("https://localhost/"), None);
        assert_eq!(normalize_relay_url("https://foo.localhost/"), None);
        assert_eq!(normalize_relay_url("https://api.local/"), None);
        assert_eq!(normalize_relay_url("https://svc.internal/"), None);
        assert_eq!(normalize_relay_url("not-a-url"), None);
        assert_eq!(normalize_relay_url(""), None);
        assert_eq!(normalize_relay_url("   "), None);
        // 公网 IP 可以
        assert_eq!(
            normalize_relay_url("https://1.2.3.4/"),
            Some("https://1.2.3.4".to_string())
        );
    }

    /// Worker 名称：小写字母/数字开头，仅含小写、数字、连字符。
    #[test]
    fn project_name_pattern_is_enforced() {
        assert!(is_valid_project_name("relay-abc"));
        assert!(is_valid_project_name("relay123"));
        assert!(!is_valid_project_name("Relay"));
        assert!(!is_valid_project_name("-relay"));
        assert!(!is_valid_project_name("relay_abc"));
        assert!(!is_valid_project_name(""));
        assert!(!is_valid_project_name("relay--abc x"));
    }

    /// 区域白名单。
    #[test]
    fn regions_match_the_whitelist() {
        for region in ["", "wnam", "enam", "sam", "weur", "eeur", "me", "afr", "apac", "oce"] {
            assert!(is_valid_region(region), "{region} 应当合法");
        }
        assert!(!is_valid_region("nowhere"));
        assert!(!is_valid_region("WNAM"));
    }

    /// IPv4 前缀匹配的边界：198.18.0.0/15（含 198.19.x）；224/4 组播。
    #[test]
    fn ipv4_prefix_boundaries_hold() {
        assert!(is_blocked_ip("198.18.255.255"));
        assert!(is_blocked_ip("198.19.0.1"));
        assert!(!is_blocked_ip("198.20.0.1"));
        assert!(is_blocked_ip("224.0.0.1"));
        assert!(is_blocked_ip("100.64.0.1"));
        assert!(!is_blocked_ip("100.128.0.1"));
        assert!(is_blocked_ip("172.31.255.255"));
        assert!(!is_blocked_ip("172.32.0.1"));
        // 非 IP 文本不算（域名走黑名单分支）
        assert!(!is_blocked_ip("relay.workers.dev"));
    }
}
