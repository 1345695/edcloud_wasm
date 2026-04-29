## 项目简介 🚀

本项目是一个部署在 **Cloudflare Workers** 上的高性能多协议代理入口 / 订阅面板。

### 功能特性 ✨

- **多入站协议支持**
  - VLESS
  - Trojan
  - Shadowsocks
  - SOCKS5
  - HTTP
- **多传输方式与性能优化**
  - 同时支持 **WebSocket** 和 **xHTTP** 和 **Grpc** 传输方式；
  - 独家采用优化的 `manualPipe` 函数进行流量转发，相比传统stream流式的 `pipeTo` ，CPU 开销大幅降低 **6 倍**。
- **WASM 加速解析**
  - 将复杂的协议解析、节点模板拼装、订阅转换前处理等逻辑封装在 `protocol.wasm` 中；
  - 使用 Rust 编写并编译为 WebAssembly，由 `_worker.js` 在 Worker 侧调用；
  - 在兼顾体积与性能的同时彻底隐藏各个代理协议头部固定特征增强cloudflare代码审查难度。
- **订阅与面板一体化**
  - 访问 `/UUID` 或 `/PASSWORD` 即可打开管理面板页面，需要在代码或者环境变量配置uuid或者trojan密码
  - 订阅后端基于 cmliu 的实现，支持 Clash / SingBox / Surge / Quantumult / Loon / Stash 等多客户端订阅。

---

## 部署到 Cloudflare Workers ☁️

> ⚠️ **重要警告（关于免费 Workers）**
>
> - 使用 **Cloudflare 免费 Workers 计划** 直接部署本项目时，当前实测可能出现 **1101 错误（Worker 内部异常）**，导致服务无法正常运行。
> - 在 **付费 Workers 计划** 下部署可以正常工作。
> - 使用 **Cloudflare Pages + Functions** 部署一切正常，不受上述限制。
> - 免费 Worker 建议使用单文件 [五协议版本](https://github.com/1345695/edcloudwasm/tree/src/%E7%BA%AF%E4%BC%A0%E8%BE%93%E4%BB%A3%E7%A0%81)。
>
> **因此：如果你是免费账户，更推荐使用 _Cloudflare Pages_ 方式部署本项目。**

项目根目录下的 `wrangler.toml` 已提供基础配置，推荐的部署流程如下。

### 1. 准备工作

- **Fork 本仓库**
  - 在 GitHub 上 Fork 本仓库到你自己的账号。
- **连接到 Cloudflare Workers**
  - 在 Cloudflare Dashboard 中创建 Worker；
  - 将该 Worker 连接到你 Fork 之后的 GitHub 仓库，可选开启自动部署。

### 2. 核心配置（`wrangler.toml`）

- **入口文件**
  - `main = "_worker.js"`
- **兼容日期**
  - `compatibility_date = "2026-02-26"`
- **环境变量 `vars`**

  | 变量名       | 说明                                                                 |
  | ------------ | -------------------------------------------------------------------- |
  | `UUID`       | VLESS 的 UUID，用于面板路径与连接认证，两个地方都不写为不验证 UUID  |
  | `PASSWORD`   | Trojan 密码，两个地方都不写为不验证密码                           |
  | `SSPASS`     | SS使用aes128加密的密码                                           |
  | `S5HTTPUSER` | SOCKS5 / HTTP 入站认证用户名，两个地方都不写为不验证密码           |
  | `S5HTTPPASS` | SOCKS5 / HTTP 入站认证密码，两个地方都不写为不验证密码             |
- **WASM 绑定规则**
  - `[[rules]] type = "CompiledWasm" globs = ["**/*.wasm"]`
  - Wrangler 会自动将同目录下的 `protocol.wasm` 作为 CompiledWasm 模块绑定到 `_worker.js` 中的
    `import wasmModule from './protocol.wasm';`。

### 2.1 使用 Pages 部署时的差异说明 📝

如果你选择通过 **Cloudflare Pages + Functions** 的方式部署，而不是直接使用 Workers，`wrangler.toml` 中的部分配置会被 Pages 的项目设置接管，需要注意以下几点：

- **入口文件与构建方式**
  - Pages 项目中同样可以使用 `_worker.js` 作为 Functions 入口，但构建产物路径、输出目录等由 Pages 配置页面管理；
  - `wrangler.toml` 中与构建 / 预览相关的配置可能不会完全生效，请以 Pages 控制台中的说明为准。
- **环境变量配置位置不同**
  - 在纯 Workers 部署场景下，可以在 `wrangler.toml` 中通过 `vars` 写死部分变量，或在 Worker 的 **Settings → Variables** 中配置；
  - 在 Pages 部署场景下，**必须在 Pages 项目的「Environment Variables」面板中为对应环境（Production / Preview）手动添加 `UUID`、`PASSWORD`、`S5HTTPUSER`、`S5HTTPPASS` 变量**。
- **修改环境变量后的生效方式**
  - 修改或新增环境变量后，需要在 Cloudflare Pages 控制台中重新触发一次部署（例如重新从 Git 提交 / 手动点击「Retry deployment」），新的变量值才会真正生效；
  - 如果只是改了面板里的变量而未重新部署，老版本的函数代码仍然会使用旧的环境变量。

### 3. 自定义 Worker 名称 / 域名 🔧

如需修改 Worker 名称、域名或路由，可按需调整：

- **修改 Worker 名称**
  - 在 `wrangler.toml` 中将 `name = "edcloudwasm"` 修改为你自己的名称。
- **配置自定义域名 / 路由**
  - 在 Cloudflare Dashboard 中为该 Worker 添加路由；或
  - 按 Wrangler 文档在 `wrangler.toml` 中增加 `routes` / `workers_dev` 等配置（根据你的使用习惯选择）。

### 4. 核心文件说明 📁

- **`_worker.js`**：Cloudflare Worker 入口，负责：
  - 接收 HTTP / WebSocket 请求；
  - 调用 `protocol.wasm` 暴露的解析函数；
  - 建立 TCP 连接、转发流量、处理 DoH DNS；
  - 生成订阅与面板页面。
- **`protocol.wasm`**：由 Rust crate **`protocol-parser`** 编译生成的 WASM 模块。
- **`Cargo.toml` / `src/lib.rs`**：`protocol-parser` crate 源码，包含：
  - 多协议入站解析（VLESS / Trojan / Shadowsocks / HTTP CONNECT / SOCKS5）；
  - URL 解析与出站策略解析（`s5` / `http` / `nat64` / `ip` / `proxyall` 等参数）；
  - 节点模板与订阅相关字符串表；
  - 面板与错误页的 gzip 压缩静态资源。
- **`wrangler.toml`**：Cloudflare Worker 配置，包括入口文件、环境变量及 WASM 绑定规则。

---

## 编译 `protocol.wasm` ⚙️

### 1. 环境准备 🔧

确保已经安装 **Rust 工具链**（推荐 stable）：

- 参考 `https://www.rust-lang.org/` 安装 Rust；

### 2. 安装 wasm 目标 📦

首次在本机环境使用时，为 Rust 安装 wasm32 目标：

```bash
rustup target add wasm32-unknown-unknown
```

### 3. 编译生成 WASM 🏗️

在 项目根目录执行：

```bash
# Release 构建为 wasm
cargo build --release
```

构建成功后，Rust 会在：

```text
target/wasm32-unknown-unknown/release/protocol_parser.wasm
```

生成对应的 wasm 文件。需要将其拷贝 / 重命名为项目中使用的 `protocol.wasm`：

```bash
copy target\wasm32-unknown-unknown\release\protocol_parser.wasm protocol.wasm
```

> Windows PowerShell 下可直接使用上述命令；
> 若使用 WSL / Linux / macOS，可改为：
>
> ```bash
> cp target/wasm32-unknown-unknown/release/protocol_parser.wasm protocol.wasm
> ```

此时，`_worker.js` 中的：

```js
import wasmModule from './protocol.wasm';
```

即可正确加载最新编译的 WASM 模块。

### 4. （可选）进一步瘦身与优化 🪄

在必要时，可使用 `binaryen` / `wasm-opt` 等工具对 `protocol.wasm` 做进一步体积优化，例如：

```bash
wasm-opt -O4 --enable-bulk-memory --enable-simd --strip-debug --strip-producers target\wasm32-unknown-unknown\release\protocol_parser.wasm -o protocol.wasm
mv protocol.opt.wasm protocol.wasm
```

在 `Cargo.toml` 已经开启 `strip` + `lto` + `opt-level = 3` 的情况下，体积与性能通常已经可以满足绝大部分 Worker 场景。

---

## 项目热度 ⭐

[![Stargazers over time](https://starchart.cc/1345695/edcloudwasm.svg?variant=adaptive)](https://starchart.cc/1345695/edcloudwasm)

## 鸣谢 🙏

- [杨幂的脚 (cmliu)](https://github.com/cmliu/edgetunnel)
- [AK大佬 (Alexandre_Kojeve)](https://t.me/Notif_Chat)
- [天书 (HeroCore)](https://t.me/HeroCore)
- [zizifn/edgetunnel](https://github.com/zizifn/edgetunnel)

