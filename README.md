# sing-box 单功能配置下发服务

新仓库，目标为 **sing-box Android 1.14.2**。没有复制旧 marko-network 的实现、密钥、服务配置或 Git 历史。
只生成并下发一个客户端配置，不部署或修改 WireGuard 服务端、VPS、DDNS、frp、Apache 或宿主路由。

## 固定合同

| 顺序 | 目标 | 出站 |
|---|---|---|
| 1 | 10.77.0.0/24 | WireGuard；外层仅公网 IPv6/AAAA，没有 IPv4 或代理备用 |
| 2 | 自定义强制 DIRECT 集 | DIRECT，覆盖新加坡白名单 |
| 3 | 新加坡白名单：目标 IP/CIDR、精确域名、域名后缀 | 新加坡 |
| 4 | 其他 | 香港 |

DIRECT 初始收录 35 个中国公共 DNS IP、5 个域名后缀；见 `data/direct.json` 和 `docs/rule-source.md`。
没有 geoip:cn/geosite:cn，没有推测补入公共上报 API。`360.cn` 按确认保留，含其所有子域名。
`domain` 表示精确域名，`domain_suffix` 表示域名及子域名；不写 `domain:`、`*.` 或 URL。
IP 和域名条件是 **OR**，不是 AND。域名未提前命中时，解析后再次按内网 → DIRECT → SG 检查目标 IP。

DNS 处理：发往 DIRECT 列表的 DNS 流量直接发出；其他识别到的普通 DNS 交给 sing-box DNS。
DIRECT 域名走设备系统/底层 DNS，SG 白名单域名的 DoH 经 SG，其他 DoH 经 HK（Cloudflare 1.1.1.1）。
节点域名与 WG endpoint 用本地 DNS 引导，WG endpoint 明确 `ipv6_only`；这不是“所有 DNS 查询直连”。
IP 白名单要等解析后才知道是否命中，因此未匹配域名白名单的 DNS 查询仍按默认 HK 解析。

## 选路与故障边界

- 容器从一个 HTTPS 订阅拉取节点，用已有 `sing-box-subscribe-cli v1.0.4` 转换；不向第三方转换 API 提交订阅。
- 通过节点真实访问 `https://www.google.com/`，测完整 HTTPS 请求耗时，非 ICMP。环境代理只用于拉订阅，不能替代被测节点。
- 按备注正则区分 HK/SG。默认 k=3，每轮测全部匹配候选，每组保留成功者中最快的 k 个（不足 k 就保留全部成功者）。
- 默认每轮结束后 300 秒再刷新；k、间隔、并发、超时、上限可调。超过上限报错，不截断候选。
- SFA 中 HK/SG 各一个 selector，默认是本轮最快节点，其余 top-k 供手动选择。**不在手机上运行 urltest。**
- 只有本轮全部订阅 HK 节点探测失败，才探测并下发自有 HK hy2。正常配置不包含自有 hy2；订阅 HK 恢复后下一份配置恢复订阅节点。
- 缺少地区、订阅获取/转换失败、SG 全失败、HK 与自有 hy2 都失败、核心检查失败：不发布新配置，保留旧快照。
- **切换需要 SFA 重新拉取并应用配置。** 纯配置 URL 服务不能修改已经运行的客户端配置。手机网络上的节点状态可能不同于容器的探测结果。
- `10.77.0.0/24` 不通时由用户手动切换 v2rayNG，本服务不自动处理。

## 私有配置：先初始化，再编辑，后 render

本地入口是 `cli.py`。默认是 Rich + questionary 菜单，仅有“初始化模板 / 渲染 / 退出”，没有部署菜单。
菜单可选依赖在 `requirements-menu.txt`，只装进 venv；`init`、`render` 直接动作仅使用 Python 标准库。

1. 打开该入口，选择“初始化 private-config 模板”。已有文件绝不覆盖。
2. 用 Neovim 或其他编辑器填写 `private-config/settings.json` 的占位符。
3. 填入订阅 URL、32–128 位 URL-safe 随机 API key、WG 客户端地址（/32）及密钥、WG endpoint、自有 hy2。
4. 填写 `singapore` 白名单。可在 `direct` 加个人强制直连条目，它与内置列表合并。
5. 选择“渲染私有运行配置”。校验通过后产生 `runtime/settings.json` 和 Compose 所需 `.env`，创建 `state/`。

**render 不拉订阅、不测速、不生成假节点、不启动容器。** 完整 SFA JSON 由容器获取订阅并完成验证后产生。
未填写占位符会拒绝 render，这是有意的；不需要把真实私钥交给代理。

## Docker 部署边界

用 Docker Compose 打开仓库根目录的 `compose.yml`，构建并启动唯一的 `config` 服务。
首次交付只支持 **linux/amd64**，其他架构显式构建失败。固定核心与转换器版本并校验下载 SHA-256；基础 Python 镜像按版本系列，不宣称整个镜像字节级可复现。

| 宿主路径 | 容器路径 | 权限/用途 |
|---|---|---|
| runtime/ | /config/（只读目录挂载） | 目录 0700，settings.json 0600；原子 render 后容器可读到新文件 |
| state/ | /state/ | 目录 0700，snapshot.json 0600；重启时验证后恢复 |
| .env | Compose 变量文件 | render 用户的 UID/GID；服务以相同身份运行 |

不要用另一用户或 sudo render 后再混用不同身份；容器 loader 检查文件所有者及权限。
无 host 网络、无 privileged、无 NET_ADMIN，不访问宿主 TUN；容器内仅开临时 loopback HTTP 代理用于测速。
挂载私有目录被 `.dockerignore` 排除，构建上下文仅包含服务代码和 Dockerfile。

监听默认仅绑定宿主 `127.0.0.1:8787`。外部 SFA 使用你已有的 HTTPS 反向代理映射到它；本仓库不自动安装、改写反代或暴露公网端口。
外层反代不要记录带 `key` 的查询串，也不要缓存配置响应。

代理分三层：Docker daemon 拉基础镜像、构建期下载、运行期拉订阅。Compose 传入标准大小写 HTTP_PROXY/HTTPS_PROXY；daemon 的代理需由现有 Docker 环境提供。
配置 API 的容器内健康检查不走环境代理。`NO_PROXY` 不会绕过节点测速。

## 唯一业务接口

- 方法：**GET**
- URL：`https://<你的配置域名>/api/config?key=<API_KEY>`，适用于只接受订阅 URL 的客户端。
- 也支持 `Authorization: Bearer <API_KEY>`，此时 URL 不需要 key 参数。
- 成功 200：完整 sing-box JSON；密钥错误 401；尚无有效配置 503；POST 405。
- `/healthz` 仅返回 ready/stale、刷新阶段、静态错误码、数量、是否启用 hy2，不输出节点、密钥或订阅地址。
- 健康检查检查 `ready`，不是仅看 HTTP 200。已有旧配置时 ready=true、刷新失败 stale=true。

没有上传配置接口、远程修改接口、模式枚举或管理 WebUI。服务日志不记录请求 URL。
更换 API key 后旧 key 立即不再有效；策略改动在下一次成功刷新后发布。

## 回退与验收

在 SFA 中保留原有可用配置，新增这条远程配置，避免覆盖唯一救援入口；WG 失败按约定手动切换 v2rayNG。
仓库尚未在你的服务器部署；`docs/acceptance.md` 列出本地证据与必须由真实环境完成的验收。
测试使用标准库 unittest 和真实 1.14.2 核心、v1.0.4 转换器；测试解释器从 `SING_BOX`/`SING_BOX_SUB` 环境变量定位本地二进制。
真实订阅、私钥、渲染产物与快照均不进 Git/交付压缩包。
