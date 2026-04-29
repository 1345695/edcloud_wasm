#![no_std]
#[cfg(not(test))]
use core::panic::PanicInfo;

// ==========================================
// 内存布局与全局状态 (紧凑版)
// ==========================================

/// RESULT 槽位分配 (WASM 与 JS 共享的 32 个状态标志/返回值):
/// --- 全局配置区域 ---
/// [0]: 是否启用 VLESS UUID 验证 (1为启用)
/// [1]: 是否启用 Trojan 密码 Hash 验证 (1为启用)
/// [2]: 启用的 HTTP 认证字符串长度
/// [3]: 启用的 SOCKS5 认证包长度 (SOCKS5_AUTH 缓冲区中有效数据的长度)
/// [4]: SOCKS5 下一步状态 (0: 无/初始, 1: 等待认证, 2: 等待请求)
/// [14]: 是否还需要更多协议头数据 (0:不需要, 1:需要)
///
/// --- 协议解析结果 (每次 parseProtocolWasm 后更新) ---
/// [5]: 目标地址类型 (1: IPv4, 3: 域名, 4: IPv6)
/// [6]: 目标端口号
/// [7]: 真实数据偏移量 (协议头之后的 payload 起始位置)
/// [8]: 是否为 DNS 请求 (目标端口为 53 则是)
/// [9]: 目标地址在 COMMON_BUF 中的起始索引
/// [10]: 目标地址的长度
/// [11]: 识别到的协议 ID (0: VLESS, 1: Trojan, 2: Shadowsocks, 3: HTTP, 4: SOCKS5)
/// [12]: 需要发送给客户端的握手回包长度 (如 HTTP 200 OK 或 VLESS 的响应)
///
/// --- URL 解析结果 (parseUrlWasm 后更新) ---
/// [15]: Socks5 参数偏移, [16]: Socks5 参数长度
/// [17]: Http 参数偏移,   [18]: Http 参数长度
/// [19]: Nat64 参数偏移,  [20]: Nat64 参数长度
/// [21]: IP 参数偏移,     [22]: IP 参数长度
/// [23]: 是否为全局代理模式 (ProxyAll)
/// [24]: Turn 参数偏移,   [25]: Turn 参数长度
/// [26]: Https 参数偏移,  [27]: Https 参数长度
static mut RESULT: [i32; 32] = [0; 32];

static mut COMMON_BUF: [u8; 1024] = [0; 1024]; // 1KB 通用数据缓冲区
static mut UUID: [u8; 16] = [0; 16]; // VLESS UUID
static mut HASH: [u8; 56] = [0; 56]; // Trojan Hash
static mut HTTP_AUTH: [u8; 256] = [0; 256]; // HTTP Auth (Base64) - 256 字节
static mut SOCKS5_AUTH: [u8; 256] = [0; 256]; // SOCKS5 Auth Packet (Raw bytes) - 256 字节

// 预编译打包的 Web 页面资源
static PANEL_HTML: &[u8] = include_bytes!("index.html.gz");
static ERROR_HTML: &[u8] = include_bytes!("404.html.gz");

// ==========================================
// 导出函数
// ==========================================

/// 获取 RESULT 数组指针
#[no_mangle]
pub unsafe extern "C" fn getResultPtr() -> *const i32 {
    core::ptr::addr_of!(RESULT) as *const i32
}
/// 获取通用数据缓冲区指针
#[no_mangle]
pub unsafe extern "C" fn getDataPtr() -> *const u8 {
    core::ptr::addr_of!(COMMON_BUF) as *const u8
}
/// 获取 UUID 缓冲区指针
#[no_mangle]
pub unsafe extern "C" fn getUuidPtr() -> *const u8 {
    core::ptr::addr_of!(UUID) as *const u8
}
/// 获取 HTTP 认证缓冲区指针
#[no_mangle]
pub unsafe extern "C" fn getHttpAuthPtr() -> *const u8 {
    core::ptr::addr_of!(HTTP_AUTH) as *const u8
}
/// 获取 SOCKS5 认证缓冲区指针
#[no_mangle]
pub unsafe extern "C" fn getSocks5AuthPtr() -> *const u8 {
    core::ptr::addr_of!(SOCKS5_AUTH) as *const u8
}

/// 获取面板 HTML 资源指针
#[no_mangle]
pub unsafe extern "C" fn getPanelHtmlPtr() -> *const u8 {
    PANEL_HTML.as_ptr()
}
/// 获取面板 HTML 资源长度
#[no_mangle]
pub unsafe extern "C" fn getPanelHtmlLen() -> i32 {
    PANEL_HTML.len() as i32
}
/// 获取错误页 HTML 资源指针
#[no_mangle]
pub unsafe extern "C" fn getErrorHtmlPtr() -> *const u8 {
    ERROR_HTML.as_ptr()
}
/// 获取错误页 HTML 资源长度
#[no_mangle]
pub unsafe extern "C" fn getErrorHtmlLen() -> i32 {
    ERROR_HTML.len() as i32
}

/// 设置 HTTP 认证长度
#[no_mangle]
pub unsafe extern "C" fn setHttpAuthLenWasm(len: i32) {
    *RESULT.get_unchecked_mut(2) = len;
}

/// 设置 SOCKS5 认证长度
#[no_mangle]
pub unsafe extern "C" fn setSocks5AuthLenWasm(len: i32) {
    *RESULT.get_unchecked_mut(3) = len;
}

// ==========================================
// 节点生成与字符串常量 (明文极速版)
// ==========================================

static TEMPLATES: [&[u8]; 12] = [
    b"vless://{{UUID}}@{{IP}}:{{port}}?sni={{HOST}}&host={{HOST}}&path={{PATH}}&encryption=none&security=tls&fp=chrome&alpn=http%2F1.1&insecure=1&allowInsecure=0&type=ws#ws-vless-{{name}}",
    b"vless://{{UUID}}@{{IP}}:{{port}}?sni={{HOST}}&host={{HOST}}&path={{PATH}}&encryption=none&security=tls&fp=chrome&allowInsecure=0&type=ws&ech={{ECHDNS}}&alpn=http%2F1.1&insecure=0#[ECH]-ws-vless-{{name}}",
    b"vless://{{UUID}}@{{IP}}:{{port}}?sni={{HOST}}&host={{HOST}}&path={{PATH}}&encryption=none&security=tls&fp=chrome&alpn=h2&type=xhttp&headerType=none&mode=stream-one&extra=%7B%22xPaddingObfsMode%22%3Atrue%2C%22xPaddingMethod%22%3A%22tokenish%22%2C%22xPaddingHeader%22%3A%22referer%22%2C%22xPaddingKey%22%3A%22key%22%7D#xhttp-vless-{{name}}",
    b"vless://{{UUID}}@{{IP}}:{{port}}?sni={{HOST}}&host={{HOST}}&path={{PATH}}&encryption=none&security=tls&fp=chrome&type=xhttp&headerType=none&ech={{ECHDNS}}&alpn=h2&insecure=0&mode=stream-one&extra=%7B%22xPaddingObfsMode%22%3Atrue%2C%22xPaddingMethod%22%3A%22tokenish%22%2C%22xPaddingHeader%22%3A%22referer%22%2C%22xPaddingKey%22%3A%22key%22%7D#[ECH]-xhttp-vless-{{name}}",
    b"vless://{{UUID}}@{{IP}}:{{port}}?sni={{HOST}}&host={{HOST}}&serviceName={{PATH}}&encryption=none&security=tls&fp=chrome&alpn=h2&type=grpc&mode=gun&insecure=1&allowInsecure=0#grpc-vless-{{name}}",
    b"vless://{{UUID}}@{{IP}}:{{port}}?sni={{HOST}}&host={{HOST}}&serviceName={{PATH}}&encryption=none&security=tls&fp=chrome&alpn=h2&type=grpc&mode=gun&ech={{ECHDNS}}&allowInsecure=0&insecure=0#[ECH]-grpc-vless-{{name}}",
    b"trojan://{{PASSWORD}}@{{IP}}:{{port}}?sni={{HOST}}&host={{HOST}}&path={{PATH}}&security=tls&fp=chrome&alpn=http%2F1.1&insecure=1&allowInsecure=0&type=ws#ws-trojan-{{name}}",
    b"trojan://{{PASSWORD}}@{{IP}}:{{port}}?sni={{HOST}}&host={{HOST}}&path={{PATH}}&security=tls&fp=chrome&allowInsecure=0&type=ws&ech={{ECHDNS}}&alpn=http%2F1.1&insecure=0#[ECH]-ws-trojan-{{name}}",
    b"trojan://{{PASSWORD}}@{{IP}}:{{port}}?sni={{HOST}}&host={{HOST}}&path={{PATH}}&encryption=none&security=tls&fp=chrome&alpn=h2&type=xhttp&headerType=none&mode=stream-one&extra=%7B%22xPaddingObfsMode%22%3Atrue%2C%22xPaddingMethod%22%3A%22tokenish%22%2C%22xPaddingHeader%22%3A%22referer%22%2C%22xPaddingKey%22%3A%22key%22%7D#xhttp-trojan-{{name}}",
    b"trojan://{{PASSWORD}}@{{IP}}:{{port}}?sni={{HOST}}&host={{HOST}}&path={{PATH}}&encryption=none&security=tls&fp=chrome&type=xhttp&headerType=none&ech={{ECHDNS}}&alpn=h2&insecure=0&mode=stream-one&extra=%7B%22xPaddingObfsMode%22%3Atrue%2C%22xPaddingMethod%22%3A%22tokenish%22%2C%22xPaddingHeader%22%3A%22referer%22%2C%22xPaddingKey%22%3A%22key%22%7D#[ECH]-xhttp-trojan-{{name}}",
    b"trojan://{{PASSWORD}}@{{IP}}:{{port}}?sni={{HOST}}&host={{HOST}}&serviceName={{PATH}}&security=tls&fp=chrome&alpn=h2&type=grpc&mode=gun&insecure=1&allowInsecure=0#grpc-trojan-{{name}}",
    b"trojan://{{PASSWORD}}@{{IP}}:{{port}}?sni={{HOST}}&host={{HOST}}&serviceName={{PATH}}&security=tls&fp=chrome&alpn=h2&type=grpc&mode=gun&ech={{ECHDNS}}&allowInsecure=0&insecure=0#[ECH]-grpc-trojan-{{name}}",
];

/// 获取节点模板字符串并写入 COMMON_BUF
#[no_mangle]
pub unsafe extern "C" fn getTemplateWasm(index: i32) -> i32 {
    if (0..12).contains(&index) {
        let t = TEMPLATES.get_unchecked(index as usize);
        core::ptr::copy_nonoverlapping(t.as_ptr(), COMMON_BUF.as_mut_ptr(), t.len());
        return t.len() as i32;
    }
    0
}

static SECRET_STRINGS: [&[u8]; 20] = [
    b"https://SUBAPI.cmliussss.net",
    b"https://raw.githubusercontent.com/cmliu/ACL4SSR/main/Clash/config/ACL4SSR_Online_Mini_MultiMode_CF.ini",
    b"edgetunnel",
    b"(https://github.com/cmliu/",
    b")",
    b"clash",
    b"singbox",
    b"surge&ver=4",
    b"quanx",
    b"loon",
    b"stash",
    b"sb",
    b"sing-box",
    b"surge",
    b"quantumult",
    b"mihomo",
    b"meta",
    b"MyCloudflareNodes",
    b"subconverter",
    b"Subconverter",
];

/// 获取内置密钥/常量字符串并写入 COMMON_BUF
#[no_mangle]
pub unsafe extern "C" fn getSecretStringWasm(index: i32) -> i32 {
    if (0..20).contains(&index) {
        let s = SECRET_STRINGS.get_unchecked(index as usize);
        core::ptr::copy_nonoverlapping(s.as_ptr(), COMMON_BUF.as_mut_ptr(), s.len());
        return s.len() as i32;
    }
    0
}

// ==========================================
// 辅助工具函数 (极致性能版)
// ==========================================

/// 极速 ASCII 转小写
#[inline(always)]
fn ascii_lower(b: u8) -> u8 {
    b.wrapping_add(((b.wrapping_sub(b'A') <= 25) as u8).wrapping_mul(32))
}

/// 极速设置 RESULT 槽位
#[inline(always)]
unsafe fn set_res(idx: usize, val: i32) {
    *RESULT.get_unchecked_mut(idx) = val;
}

/// 极速获取地址长度
#[inline(always)]
unsafe fn get_addr_len(at: i32, off: usize, len: usize) -> i32 {
    match at {
        1 => 4,
        4 => 16,
        3 => {
            if off < len {
                *COMMON_BUF.get_unchecked(off) as i32
            } else {
                -2
            }
        }
        _ => -1,
    }
}

/// 极速写入握手回包数据
#[inline(always)]
unsafe fn write_handshake(data: &[u8]) {
    set_res(12, data.len() as i32);
    core::ptr::copy_nonoverlapping(data.as_ptr(), COMMON_BUF.as_mut_ptr(), data.len());
}

/// 分层块比较: simd128 > 64 > 32 > 16 > 8
#[inline(always)]
unsafe fn eq_bytes_u64(a: *const u8, b: *const u8, len: usize) -> bool {
    let mut off = 0usize;
    use core::arch::wasm32::{v128, v128_any_true, v128_load, v128_xor};
    while off + 16 <= len {
        let va = v128_load(a.add(off) as *const v128);
        let vb = v128_load(b.add(off) as *const v128);
        if v128_any_true(v128_xor(va, vb)) {
            return false;
        }
        off += 16;
    }

    while off + 8 <= len {
        if core::ptr::read_unaligned(a.add(off) as *const u64)
            != core::ptr::read_unaligned(b.add(off) as *const u64)
        {
            return false;
        }
        off += 8;
    }

    if off + 4 <= len {
        if core::ptr::read_unaligned(a.add(off) as *const u32)
            != core::ptr::read_unaligned(b.add(off) as *const u32)
        {
            return false;
        }
        off += 4;
    }

    if off + 2 <= len {
        if core::ptr::read_unaligned(a.add(off) as *const u16)
            != core::ptr::read_unaligned(b.add(off) as *const u16)
        {
            return false;
        }
        off += 2;
    }

    if off < len && *a.add(off) != *b.add(off) {
        return false;
    }

    true
}

/// 向前查找单字节 (SIMD 优先)
#[inline(always)]
unsafe fn find_byte_forward(data: *const u8, mut i: usize, end: usize, needle: u8) -> Option<usize> {
    use core::arch::wasm32::{i8x16_eq, u8x16_bitmask, u8x16_splat, v128, v128_load};
    let nv = u8x16_splat(needle);
    while i + 16 <= end {
        let vv = v128_load(data.add(i) as *const v128);
        let mask = u8x16_bitmask(i8x16_eq(vv, nv)) as u32;
        if mask != 0 {
            return Some(i + mask.trailing_zeros() as usize);
        }
        i += 16;
    }
    while i < end {
        if *data.add(i) == needle {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// 向后查找单字节 (SIMD 优先)
#[inline(always)]
unsafe fn find_byte_backward(data: *const u8, start: usize, end: usize, needle: u8) -> Option<usize> {
    let mut tail_end = end;
    use core::arch::wasm32::{i8x16_eq, u8x16_bitmask, u8x16_splat, v128, v128_load};
    let nv = u8x16_splat(needle);
    while tail_end >= start + 16 {
        tail_end -= 16;
        let vv = v128_load(data.add(tail_end) as *const v128);
        let mask = u8x16_bitmask(i8x16_eq(vv, nv)) as u32;
        if mask != 0 {
            let hi = (31 - mask.leading_zeros()) as usize;
            return Some(tail_end + hi);
        }
    }
    while tail_end > start {
        tail_end -= 1;
        if *data.add(tail_end) == needle {
            return Some(tail_end);
        }
    }
    None
}

/// 查找 URL value 结束位置: '&' 或可选 '='
#[inline(always)]
unsafe fn find_value_end(data: *const u8, mut i: usize, end: usize, stop_eq: bool) -> usize {
    use core::arch::wasm32::{i8x16_eq, u8x16_bitmask, u8x16_splat, v128, v128_load, v128_or};
    let amp = u8x16_splat(b'&');
    let eq = u8x16_splat(b'=');
    while i + 16 <= end {
        let vv = v128_load(data.add(i) as *const v128);
        let mask = if stop_eq {
            u8x16_bitmask(v128_or(i8x16_eq(vv, amp), i8x16_eq(vv, eq))) as u32
        } else {
            u8x16_bitmask(i8x16_eq(vv, amp)) as u32
        };
        if mask != 0 {
            return i + mask.trailing_zeros() as usize;
        }
        i += 16;
    }
    while i < end {
        let b = *data.add(i);
        if b == b'&' || (stop_eq && b == b'=') {
            break;
        }
        i += 1;
    }
    i
}

/// 查找下一个可能的 URL 参数 key 起点。
#[inline(always)]
unsafe fn find_next_key_start(data: *const u8, mut i: usize, end: usize) -> Option<usize> {
    use core::arch::wasm32::{i8x16_eq, u8x16_bitmask, u8x16_splat, v128, v128_load, v128_or};
    let g = u8x16_splat(b'g');
    let s = u8x16_splat(b's');
    let h = u8x16_splat(b'h');
    let n = u8x16_splat(b'n');
    let t = u8x16_splat(b't');
    let ip = u8x16_splat(b'i');
    let p = u8x16_splat(b'p');
    let qm = u8x16_splat(b'?');
    let amp = u8x16_splat(b'&');
    while i + 16 <= end {
        let vv = v128_load(data.add(i) as *const v128);
        let m0 = v128_or(i8x16_eq(vv, g), i8x16_eq(vv, s));
        let m1 = v128_or(i8x16_eq(vv, h), i8x16_eq(vv, n));
        let m2 = v128_or(i8x16_eq(vv, t), i8x16_eq(vv, ip));
        let m3 = v128_or(i8x16_eq(vv, p), i8x16_eq(vv, qm));
        let mask = u8x16_bitmask(v128_or(v128_or(m0, m1), v128_or(v128_or(m2, m3), i8x16_eq(vv, amp)))) as u32;
        if mask != 0 {
            return Some(i + mask.trailing_zeros() as usize);
        }
        i += 16;
    }
    while i < end {
        match *data.add(i) {
            b'g' | b's' | b'h' | b'n' | b't' | b'i' | b'p' | b'?' | b'&' => return Some(i),
            _ => i += 1,
        }
    }
    None
}

// ==========================================
// 核心入站协议解析逻辑
// ==========================================

/// 解析入站代理协议 (VLESS/Trojan/SS/SOCKS5/HTTP)
#[no_mangle]
pub unsafe extern "C" fn parseProtocolWasm(chunk_len: i32, step: i32) -> bool {
    let len = chunk_len as usize;
    *RESULT.get_unchecked_mut(12) = 0; // [12] 回包长度归零
    *RESULT.get_unchecked_mut(4) = 0;  // [4] SOCKS5 下一步状态归零
    *RESULT.get_unchecked_mut(14) = 0; // [14] 是否需要更多数据归零 (0:不需要, 1:需要)

    // 1. SOCKS5 状态处理
    if step == 1 {
        let auth_len = *RESULT.get_unchecked(3) as usize;
        if len < auth_len {
            *RESULT.get_unchecked_mut(14) = 1;
            return false;
        }
        if len != auth_len {
            write_handshake(&[1, 1]);
            return false;
        }
        let cb = COMMON_BUF.as_ptr();
        let sa = SOCKS5_AUTH.as_ptr();
        let match_auth = eq_bytes_u64(cb, sa, auth_len);
        if match_auth {
            write_handshake(&[1, 0]);
            *RESULT.get_unchecked_mut(4) = 2; // 下一步: 等待请求
        } else {
            write_handshake(&[1, 1]);
        }
        return false;
    }

    if step == 2 {
        if len < 4 {
            *RESULT.get_unchecked_mut(14) = 1;
            return false;
        }
        if *COMMON_BUF.get_unchecked(0) != 5 || *COMMON_BUF.get_unchecked(1) != 1 {
            return false;
        }
        let at = *COMMON_BUF.get_unchecked(3) as i32;
        let al = get_addr_len(at, 4, len);
        if al == -2 {
            *RESULT.get_unchecked_mut(14) = 1;
            return false;
        }
        if !(al > 0) {
            return false;
        }
        let as_ = if at == 3 { 5 } else { 4 };
        let full_len = as_ + al as usize + 2;
        if len < full_len {
            *RESULT.get_unchecked_mut(14) = 1;
            return false;
        }

        let doff = as_ + al as usize;
        let p = ((*COMMON_BUF.get_unchecked(doff) as i32) << 8)
            | (*COMMON_BUF.get_unchecked(doff + 1) as i32);
        set_res(5, at);
        set_res(6, p);
        set_res(7, full_len as i32);
        set_res(8, if p == 53 { 1 } else { 0 });
        set_res(9, as_ as i32);
        set_res(10, al);
        set_res(11, 4);
        write_handshake(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        return true;
    }

    if len < 1 {
        *RESULT.get_unchecked_mut(14) = 1;
        return false;
    }
    let b0 = *COMMON_BUF.get_unchecked(0);

    // 2. SOCKS5 Init
    if b0 == 5 {
        if len < 2 {
            *RESULT.get_unchecked_mut(14) = 1;
            return false;
        }
        let nmethods = *COMMON_BUF.get_unchecked(1) as usize;
        let full_len = 2 + nmethods;
        if len < full_len {
            *RESULT.get_unchecked_mut(14) = 1;
            return false;
        }
        let auth_len = *RESULT.get_unchecked(3) as usize;
        let required = if auth_len > 0 { 2 } else { 0 };
        let mut supported = false;
        for i in 0..nmethods {
            if *COMMON_BUF.get_unchecked(2 + i) == required {
                supported = true;
                break;
            }
        }
        if supported {
            write_handshake(&[5, required]);
            *RESULT.get_unchecked_mut(4) = if required == 2 { 1 } else { 2 };
        } else {
            write_handshake(&[5, 0xFF]);
        }
        return false;
    }

    // 3. HTTP CONNECT
    if b0 == b'C' {
        if len < 48 {
            *RESULT.get_unchecked_mut(14) = 1;
            return false;
        }
        if *COMMON_BUF.get_unchecked(1) == b'O' {
            if core::ptr::read_unaligned(COMMON_BUF.as_ptr().add(len - 4) as *const u32)
                == u32::from_le_bytes(*b"\r\n\r\n")
            {
                let second_space = find_byte_forward(COMMON_BUF.as_ptr(), 8, len, b' ').unwrap_or(0);
                if second_space != 0 {
                    let auth_len = *RESULT.get_unchecked(2) as usize;
                    if auth_len > 0 {
                        let mut match_auth = false;
                        let search_limit = if len > 1024 { 1024 } else { len };
                        let cb = COMMON_BUF.as_ptr();
                        let ha = HTTP_AUTH.as_ptr();
                        let mut p = second_space + 30;
                        let limit = search_limit.saturating_sub(auth_len + 6);
                        while p <= limit {
                            let Some(pb) = find_byte_forward(cb, p, limit + 1, b'B') else {
                                break;
                            };
                            if *COMMON_BUF.get_unchecked(pb + 1) == b'a'
                                && *COMMON_BUF.get_unchecked(pb + 2) == b's'
                                && *COMMON_BUF.get_unchecked(pb + 3) == b'i'
                                && *COMMON_BUF.get_unchecked(pb + 4) == b'c'
                                && *COMMON_BUF.get_unchecked(pb + 5) == 32
                            {
                                if eq_bytes_u64(cb.add(pb + 6), ha, auth_len) {
                                    match_auth = true;
                                    break;
                                }
                            }
                            p = pb + 1;
                        }
                        if !match_auth {
                            write_handshake(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\n\r\n");
                            return false;
                        }
                    }

                    let last_colon = if second_space > 11 {
                        find_byte_backward(COMMON_BUF.as_ptr(), 8, second_space - 3, b':').unwrap_or(0)
                    } else {
                        0
                    };
                    if last_colon > 8 {
                        let mut port = 0;
                        for i in (last_colon + 1)..second_space {
                            let digit = *COMMON_BUF.get_unchecked(i) as i32 - 48;
                            if digit >= 0 && digit <= 9 {
                                port = port * 10 + digit;
                            } else {
                                break;
                            }
                        }
                        set_res(5, 3);
                        set_res(6, port);
                        set_res(7, len as i32);
                        set_res(8, 0);
                        set_res(9, 8);
                        set_res(10, (last_colon - 8) as i32);
                        set_res(11, 3);
                        write_handshake(b"HTTP/1.1 200 Connection Established\r\n\r\n");
                        return true;
                    }
                }
            } else {
                *RESULT.get_unchecked_mut(14) = 1;
                return false;
            }
        }
    }

    // 4. Trojan
    if *RESULT.get_unchecked(1) == 1 {
        if len >= 56 {
            let hash_ok = {
                let a = COMMON_BUF.as_ptr();
                let b = HASH.as_ptr();
                use core::arch::wasm32::{v128, v128_any_true, v128_load, v128_xor};
                let a0 = v128_load(a as *const v128);
                let b0 = v128_load(b as *const v128);
                if v128_any_true(v128_xor(a0, b0)) {
                    false
                } else {
                    let a1 = v128_load(a.add(16) as *const v128);
                    let b1 = v128_load(b.add(16) as *const v128);
                    if v128_any_true(v128_xor(a1, b1)) {
                        false
                    } else {
                        let a2 = v128_load(a.add(32) as *const v128);
                        let b2 = v128_load(b.add(32) as *const v128);
                        if v128_any_true(v128_xor(a2, b2)) {
                            false
                        } else {
                            core::ptr::read_unaligned(a.add(48) as *const u64)
                                == core::ptr::read_unaligned(b.add(48) as *const u64)
                        }
                    }
                }
            };
            if hash_ok {
                if len < 60 {
                    *RESULT.get_unchecked_mut(14) = 1;
                    return false;
                }
                let at = *COMMON_BUF.get_unchecked(59) as i32;
                let al = get_addr_len(at, 60, len);
                if al == -2 {
                    *RESULT.get_unchecked_mut(14) = 1;
                    return false;
                }
                if al > 0 {
                    let as_ = if at == 3 { 61 } else { 60 };
                    let full_len = as_ + al as usize + 4; // Addr + Port(2) + \r\n(2)
                    if len < full_len {
                        *RESULT.get_unchecked_mut(14) = 1;
                        return false;
                    }
                    let doff = as_ + al as usize;
                    let p = ((*COMMON_BUF.get_unchecked(doff) as i32) << 8)
                        | (*COMMON_BUF.get_unchecked(doff + 1) as i32);
                    set_res(5, at);
                    set_res(6, p);
                    set_res(7, full_len as i32);
                    set_res(8, if p == 53 { 1 } else { 0 });
                    set_res(9, as_ as i32);
                    set_res(10, al);
                    set_res(11, 1);
                    return true;
                }
            }
        }
    } else {
        if len >= 58 && *COMMON_BUF.get_unchecked(56) == 13 && *COMMON_BUF.get_unchecked(57) == 10 {
            if len < 60 {
                *RESULT.get_unchecked_mut(14) = 1;
                return false;
            }
            let at = *COMMON_BUF.get_unchecked(59) as i32;
            let al = get_addr_len(at, 60, len);
            if al == -2 {
                *RESULT.get_unchecked_mut(14) = 1;
                return false;
            }
            if al > 0 {
                let as_ = if at == 3 { 61 } else { 60 };
                let full_len = as_ + al as usize + 4;
                if len < full_len {
                    *RESULT.get_unchecked_mut(14) = 1;
                    return false;
                }
                let doff = as_ + al as usize;
                let p = ((*COMMON_BUF.get_unchecked(doff) as i32) << 8)
                    | (*COMMON_BUF.get_unchecked(doff + 1) as i32);
                set_res(5, at);
                set_res(6, p);
                set_res(7, full_len as i32);
                set_res(8, if p == 53 { 1 } else { 0 });
                set_res(9, as_ as i32);
                set_res(10, al);
                set_res(11, 1);
                return true;
            }
        }
    }

    // 5. VLESS
    let check_vless = if *RESULT.get_unchecked(0) == 1 {
        if len >= 17 {
            let a = COMMON_BUF.as_ptr().add(1);
            let b = UUID.as_ptr();
            use core::arch::wasm32::{v128, v128_any_true, v128_load, v128_xor};
            let va = v128_load(a as *const v128);
            let vb = v128_load(b as *const v128);
            !v128_any_true(v128_xor(va, vb))
        } else {
            false
        }
    } else {
        b0 != 1 && b0 != 3 && b0 != 4
    };

    if check_vless {
        if len < 18 {
            *RESULT.get_unchecked_mut(14) = 1;
            return false;
        }
        let off = 19 + (*COMMON_BUF.get_unchecked(17) as usize);
        if len < off + 4 {
            *RESULT.get_unchecked_mut(14) = 1;
            return false;
        }
        let mut at = *COMMON_BUF.get_unchecked(off + 2) as i32;
        if at != 1 {
            at += 1;
        }
        let al = get_addr_len(at, off + 3, len);
        if al == -2 {
            *RESULT.get_unchecked_mut(14) = 1;
            return false;
        }
        if al > 0 {
            let as_ = if at == 3 { off + 4 } else { off + 3 };
            let full_len = as_ + al as usize;
            if len < full_len {
                *RESULT.get_unchecked_mut(14) = 1;
                return false;
            }
            let p = ((*COMMON_BUF.get_unchecked(off) as i32) << 8)
                | (*COMMON_BUF.get_unchecked(off + 1) as i32);
            set_res(5, at);
            set_res(6, p);
            set_res(7, full_len as i32);
            set_res(8, if p == 53 { 1 } else { 0 });
            set_res(9, as_ as i32);
            set_res(10, al);
            set_res(11, 0);
            write_handshake(&[b0, 0]);
            return true;
        }
    }

    // 6. Shadowsocks
    let at = b0 as i32;
    if at == 1 || at == 3 || at == 4 {
        if len < 2 {
            *RESULT.get_unchecked_mut(14) = 1;
            return false;
        }
        let al = get_addr_len(at, 1, len);
        if al == -2 {
            *RESULT.get_unchecked_mut(14) = 1;
            return false;
        }
        if al > 0 {
            let addr_start = if at == 3 { 2 } else { 1 };
            let port_off = addr_start + al as usize;
            let full_len = port_off + 2;
            if len < full_len {
                *RESULT.get_unchecked_mut(14) = 1;
                return false;
            }
            let p = ((*COMMON_BUF.get_unchecked(port_off) as i32) << 8)
                | (*COMMON_BUF.get_unchecked(port_off + 1) as i32);
            set_res(5, at);
            set_res(6, p);
            set_res(7, full_len as i32);
            set_res(8, if p == 53 { 1 } else { 0 });
            set_res(9, addr_start as i32);
            set_res(10, al);
            set_res(11, 2);
            return true;
        }
    }

    // fallback: 如果是非明确SS特征头，且极有可能属于 Trojan/Vless 因为数据极短导致还未完成校验，给予最后一次保底等待
    if at != 1 && at != 3 && at != 4 {
        if *RESULT.get_unchecked(1) == 1 && len < 56 {
            *RESULT.get_unchecked_mut(14) = 1;
            return false;
        }
        if *RESULT.get_unchecked(0) == 1 && len < 17 {
            *RESULT.get_unchecked_mut(14) = 1;
            return false;
        }
    }

    false
}

// ==========================================
// SHA224 算法实现 (专用于 Trojan 密码 Hash)
// ==========================================

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// 循环右移
#[inline(always)]
fn rotr(x: u32, n: u32) -> u32 {
    (x >> n) | (x << (32 - n))
}

/// SHA224 单块处理
#[inline(always)]
unsafe fn sha224_block(state: &mut [u32; 8], block: &[u8]) {
    let mut w = [0u32; 64];
    let bp = block.as_ptr();
    for i in 0..16 {
        *w.get_unchecked_mut(i) = ((*bp.add(i * 4) as u32) << 24)
            | ((*bp.add(i * 4 + 1) as u32) << 16)
            | ((*bp.add(i * 4 + 2) as u32) << 8)
            | (*bp.add(i * 4 + 3) as u32);
    }
    for i in 16..64 {
        let w15 = *w.get_unchecked(i - 15);
        let s0 = rotr(w15, 7) ^ rotr(w15, 18) ^ (w15 >> 3);
        let w2 = *w.get_unchecked(i - 2);
        let s1 = rotr(w2, 17) ^ rotr(w2, 19) ^ (w2 >> 10);
        *w.get_unchecked_mut(i) = (*w.get_unchecked(i - 16))
            .wrapping_add(s0)
            .wrapping_add(*w.get_unchecked(i - 7))
            .wrapping_add(s1);
    }
    let mut a = *state.get_unchecked(0);
    let mut b = *state.get_unchecked(1);
    let mut c = *state.get_unchecked(2);
    let mut d = *state.get_unchecked(3);
    let mut e = *state.get_unchecked(4);
    let mut f = *state.get_unchecked(5);
    let mut g = *state.get_unchecked(6);
    let mut h = *state.get_unchecked(7);
    let k_ptr = K.as_ptr();
    let w_ptr = w.as_ptr();
    let mut i = 0usize;
    while i < 64 {
        let s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        let ch = (e & f) ^ ((!e) & g);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(*k_ptr.add(i))
            .wrapping_add(*w_ptr.add(i));
        let s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
        i += 1;
    }
    let s = state.as_mut_ptr();
    *s.add(0) = (*s.add(0)).wrapping_add(a);
    *s.add(1) = (*s.add(1)).wrapping_add(b);
    *s.add(2) = (*s.add(2)).wrapping_add(c);
    *s.add(3) = (*s.add(3)).wrapping_add(d);
    *s.add(4) = (*s.add(4)).wrapping_add(e);
    *s.add(5) = (*s.add(5)).wrapping_add(f);
    *s.add(6) = (*s.add(6)).wrapping_add(g);
    *s.add(7) = (*s.add(7)).wrapping_add(h);
}

/// 初始化 Trojan 密码 Hash
#[no_mangle]
pub unsafe extern "C" fn initCredentialsWasm(pass_len: i32) {
    let mut state: [u32; 8] = [
        0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7,
        0xbefa4fa4,
    ];
    let input = core::slice::from_raw_parts(COMMON_BUF.as_ptr(), pass_len as usize);
    let mut buffer = [0u8; 64];
    let bit_len = (pass_len as u64) * 8;
    let mut offset = 0;
    while offset + 64 <= input.len() {
        sha224_block(&mut state, &input[offset..offset + 64]);
        offset += 64;
    }
    let rem = input.len() - offset;
    buffer[..rem].copy_from_slice(&input[offset..offset + rem]);
    buffer[rem] = 0x80;
    if rem >= 56 {
        buffer[(rem + 1)..64].fill(0);
        sha224_block(&mut state, &buffer);
        buffer[..56].fill(0);
    } else {
        buffer[(rem + 1)..56].fill(0);
    }
    for i in 0..8 {
        *buffer.get_unchecked_mut(63 - i) = (bit_len >> (i * 8)) as u8;
    }
    sha224_block(&mut state, &buffer);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let hash_ptr = HASH.as_mut_ptr();
    let state_ptr = state.as_ptr();
    let mut out = 0usize;
    let mut i = 0usize;
    while i < 7 {
        let v = *state_ptr.add(i);
        let mut sh: u32 = 24;
        let mut j = 0usize;
        while j < 4 {
            let byte = ((v >> sh) & 0xff) as u8;
            *hash_ptr.add(out) = *HEX.get_unchecked((byte >> 4) as usize);
            *hash_ptr.add(out + 1) = *HEX.get_unchecked((byte & 0x0f) as usize);
            out += 2;
            sh = sh.wrapping_sub(8);
            j += 1;
        }
        i += 1;
    }
}

// ==========================================
// URL 解析逻辑 (明文极速版)
// ==========================================

/// 极速忽略大小写比较
#[inline(always)]
unsafe fn equals_ignore_case(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0usize;
    use core::arch::wasm32::{
        i8x16_ge, i8x16_le, i8x16_splat, v128, v128_and, v128_any_true, v128_load, v128_or,
        v128_xor,
    };
    let az_lo = i8x16_splat(b'A' as i8);
    let az_hi = i8x16_splat(b'Z' as i8);
    let bit_20 = i8x16_splat(32);
    while i + 16 <= a.len() {
        let va = v128_load(a.as_ptr().add(i) as *const v128);
        let vb = v128_load(b.as_ptr().add(i) as *const v128);

        let ma = v128_and(i8x16_ge(va, az_lo), i8x16_le(va, az_hi));
        let mb = v128_and(i8x16_ge(vb, az_lo), i8x16_le(vb, az_hi));
        let va_l = v128_or(va, v128_and(ma, bit_20));
        let vb_l = v128_or(vb, v128_and(mb, bit_20));
        if v128_any_true(v128_xor(va_l, vb_l)) {
            return false;
        }
        i += 16;
    }
    while i < a.len() {
        if ascii_lower(*a.get_unchecked(i)) != ascii_lower(*b.get_unchecked(i)) {
            return false;
        }
        i += 1;
    }
    true
}

/// 极速忽略大小写前缀匹配
#[inline(always)]
unsafe fn starts_with_ignore_case(data: &[u8], prefix: &[u8]) -> bool {
    if data.len() < prefix.len() {
        return false;
    }
    equals_ignore_case(
        core::slice::from_raw_parts(data.as_ptr(), prefix.len()),
        prefix,
    )
}

/// 极速匹配 URL 参数分隔符
#[inline(always)]
unsafe fn match_separator(d: &[u8]) -> Option<usize> {
    let len = d.len();
    if len == 0 {
        return None;
    }
    let b0 = *d.get_unchecked(0);
    if b0 == b'=' {
        return Some(1);
    }
    if len >= 3 && b0 == b':' && *d.get_unchecked(1) == b'/' && *d.get_unchecked(2) == b'/' {
        return Some(3);
    }
    if len >= 7
        && b0 == b':'
        && *d.get_unchecked(1) == b'%'
        && *d.get_unchecked(2) == b'2'
        && ascii_lower(*d.get_unchecked(3)) == b'f'
        && *d.get_unchecked(4) == b'%'
        && *d.get_unchecked(5) == b'2'
        && ascii_lower(*d.get_unchecked(6)) == b'f'
    {
        return Some(7);
    }
    if len >= 9 && b0 == b'%' {
        if *d.get_unchecked(1) == b'3'
            && ascii_lower(*d.get_unchecked(2)) == b'a'
            && *d.get_unchecked(3) == b'%'
            && *d.get_unchecked(4) == b'2'
            && ascii_lower(*d.get_unchecked(5)) == b'f'
            && *d.get_unchecked(6) == b'%'
            && *d.get_unchecked(7) == b'2'
            && ascii_lower(*d.get_unchecked(8)) == b'f'
        {
            return Some(9);
        }
    }
    None
}

struct UrlKeyDef {
    buf: &'static [u8],
    res_idx: usize,
    is_g: bool,
}

static URL_PARSE_KEYS: [UrlKeyDef; 17] = [
    UrlKeyDef { buf: b"gs5", res_idx: 15, is_g: true },
    UrlKeyDef { buf: b"s5all", res_idx: 15, is_g: true },
    UrlKeyDef { buf: b"ghttp", res_idx: 17, is_g: true },
    UrlKeyDef { buf: b"ghttps", res_idx: 26, is_g: true },
    UrlKeyDef { buf: b"gnat64", res_idx: 19, is_g: true },
    UrlKeyDef { buf: b"nat64all", res_idx: 19, is_g: true },
    UrlKeyDef { buf: b"httpall", res_idx: 17, is_g: true },
    UrlKeyDef { buf: b"httpsall", res_idx: 26, is_g: true },
    UrlKeyDef { buf: b"gturn", res_idx: 24, is_g: true },
    UrlKeyDef { buf: b"turnall", res_idx: 24, is_g: true },
    UrlKeyDef { buf: b"s5", res_idx: 15, is_g: false },
    UrlKeyDef { buf: b"socks", res_idx: 15, is_g: false },
    UrlKeyDef { buf: b"http", res_idx: 17, is_g: false },
    UrlKeyDef { buf: b"https", res_idx: 26, is_g: false },
    UrlKeyDef { buf: b"ip", res_idx: 21, is_g: false },
    UrlKeyDef { buf: b"nat64", res_idx: 19, is_g: false },
    UrlKeyDef { buf: b"turn", res_idx: 24, is_g: false },
];

/// 解析 URL 参数并提取配置
#[no_mangle]
pub unsafe extern "C" fn parseUrlWasm(url_len: i32) {
    let len = url_len as usize;
    let data_ptr = COMMON_BUF.as_ptr();
    let mut is_all = false;
    
    for idx in [15, 16, 17, 18, 19, 20, 21, 22, 24, 25, 26, 27] {
        set_res(idx, -1);
    }

    let mut i = 0usize;
    while i < len {
        while i < len {
            let b = *data_ptr.add(i);
            if b != b'?' && b != b'&' {
                break;
            }
            i += 1;
        }
        if i >= len {
            break;
        }

        let rem_len = len - i;
        let rem_data = core::slice::from_raw_parts(data_ptr.add(i), rem_len);
        
        // [分支] 全局标志判定
        if starts_with_ignore_case(rem_data, b"proxyall") {
            is_all = true;
            i += 8;
            continue;
        }
        if starts_with_ignore_case(rem_data, b"globalproxy") {
            is_all = true;
            i += 11;
            continue;
        }
        
        let mut matched = false;
        // [循环] 参数匹配
        for j in 0..17 {
            let key = URL_PARSE_KEYS.get_unchecked(j);
            let k_len = key.buf.len();
            
            if i + k_len < len && starts_with_ignore_case(rem_data, key.buf) {
                let after_key = core::slice::from_raw_parts(data_ptr.add(i + k_len), len - i - k_len);
                if let Some(s_len) = match_separator(after_key) {
                    let is_custom_sep = s_len > 1;
                    let v_start = i + k_len + s_len;
                    let v_end = find_value_end(data_ptr, v_start, len, is_custom_sep);
                    
                    if v_end > v_start {
                        if key.is_g {
                            is_all = true;
                        }
                        set_res(key.res_idx, v_start as i32);
                        set_res(key.res_idx + 1, (v_end - v_start) as i32);
                        i = if v_end < len { v_end + 1 } else { v_end };
                        matched = true;
                        break;
                    }
                }
            }
        }
        if !matched {
            if let Some(next_i) = find_next_key_start(data_ptr, i + 1, len) {
                i = next_i;
            } else {
                break;
            }
        }
    }
    set_res(23, if is_all { 1 } else { 0 });
}

// ==========================================
// 地址类型修正逻辑 (极致性能版)
// ==========================================

/// 修正并识别目标地址类型 (IPv4/IPv6/Domain)
#[no_mangle]
pub unsafe extern "C" fn getCorrectAddrTypeWasm(len: i32) -> i32 {
    let len = len as usize;
    if len == 0 {
        return 3;
    }
    let char0 = *COMMON_BUF.get_unchecked(0);

    if char0 == b'[' {
        return 4;
    }
    if char0.wrapping_sub(b'0') > 9 {
        return 3;
    }
    if len < 7 || len > 15 {
        return 3;
    }

    let mut part = 0u32;
    let mut dots = 0u32;
    let mut part_len = 0u32;
    let mut head = 0u8;
    let mut i = 0;

    while i < len {
        let b = *COMMON_BUF.get_unchecked(i);
        i += 1;
        if b == b'.' {
            if part_len == 0 || (part_len > 1 && head == b'0') {
                return 3;
            }
            dots += 1;
            if dots > 3 {
                return 3;
            }
            part = 0;
            part_len = 0;
        } else {
            let d = b.wrapping_sub(b'0');
            if d > 9 {
                return 3;
            }
            if part_len == 0 {
                head = b;
            }
            part_len += 1;
            if part_len > 3 {
                return 3;
            }
            part = part * 10 + (d as u32);
            if part > 255 {
                return 3;
            }
        }
    }

    if dots == 3 && part_len > 0 && !(part_len > 1 && head == b'0') {
        1
    } else {
        3
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
