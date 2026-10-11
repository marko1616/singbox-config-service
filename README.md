# sing-box 单功能配置下发服务

新仓库，目标为 **sing-box Android 1.14.2**。没有复制旧 marko-network 的实现、密钥、服务配置或 Git 历史。
每台设备生成并下发一份客户端配置，不部署或修改 WireGuard 服务端、VPS、DDNS、frp、Apache 或宿主路由。

## 多设备私有配置

`private-config/settings.json` 顶层恰好包含 `devices`（1–64 个设备的列表）和 `shared`（服务器共有设置对象）。
每个设备必须有唯一 `id`、`api_key`；`wireguard` 可省略或设为 `null`。未配置 WireGuard 的设备
只能使用三个 `proxyonly` 接口；要启用 `full`，添加完整的 `wireguard` 对象，且客户端地址、私钥不能与其他设备复用。
订阅地址、测速参数、规则、手动节点和自有 hy2 放在 `shared`，只拉取、转换和测速一次。
所有设备配置都经 sing-box 校验后，才作为一份快照原子发布；一台设备失败就保留整组旧快照。
所有六个配置 URL 沿用该设备现有 API key；key 自动识别设备并只返回该设备的配置。
旧 `/api/config` 不再提供，原订阅 URL 需改为 `/api/config-global-full` 等新路径。
`/healthz` 仍只显示整体状态，不列设备或密钥。仅在为设备启用 WireGuard 前，才需在服务端分配独立 peer。

从旧版扁平 `private-config/settings.json` 转换：在仓库根目录执行以下一次性命令。
它验证旧格式，保留 `settings.json.bak`（已有备份时拒绝覆盖），再以原权限原子写入新格式；不会自动部署。

```sh
python3 -c 'import json,os,shutil,tempfile; from pathlib import Path; from service import validate,device_settings,encode; p=Path("private-config/settings.json"); s=json.loads(p.read_bytes()); validate(s); b=p.with_name(p.name+".bak"); assert not b.exists(), "backup already exists"; d={"id":"phone","api_key":s.pop("api_key")}; w=s.pop("wireguard",None); d.update({"wireguard":w} if w is not None else {}); new={"devices":[d],"shared":s}; device_settings(new); shutil.copy2(p,b); fd,tmp=tempfile.mkstemp(dir=p.parent,prefix=".settings-"); os.fchmod(fd,p.stat().st_mode & 0o777); f=os.fdopen(fd,"wb"); f.write(encode(new)); f.flush(); os.fsync(f.fileno()); f.close(); os.replace(tmp,p); print("converted:",p,"backup:",b)'
```

转换后用编辑器改 `id`、追加其他设备及其独立凭据，再执行 `python3 cli.py render`，最后按原部署流程重启容器。
首次多设备部署会使旧单设备快照的格式失效；新服务成功刷新前返回 503，建议保留客户端原有可用配置。

## global 模式固定合同

| 顺序 | 目标 | 出站 |
|---|---|---|
| 1 | 10.77.0.0/24（仅启用 WireGuard 的 full） | WireGuard；外层仅公网 IPv6/AAAA，没有 IPv4 或代理备用 |
| 2 | 自定义强制 DIRECT 集 | DIRECT，覆盖新加坡白名单 |
| 3 | 新加坡白名单：目标 IP/CIDR、精确域名、域名后缀 | 新加坡 |
| 4 | 其他 | 香港 |

DIRECT 初始收录 35 个中国公共 DNS IP、5 个域名后缀；见 `data/direct.json` 和 `docs/rule-source.md`。
`global` 模式仍没有 GeoIP/Geosite 规则。`360.cn` 按确认保留，含其所有子域名。
`domain` 表示精确域名，`domain_suffix` 表示域名及子域名；不写 `domain:`、`*.` 或 URL。
IP 和域名条件是 **OR**，不是 AND。域名未提前命中时，解析后再次按内网 → DIRECT → SG 检查目标 IP。

下述 DNS 处理仅描述 global 模式：发往 DIRECT 列表的 DNS 流量直接发出；其他识别到的普通 DNS 交给 sing-box DNS。
DIRECT 域名走设备系统/底层 DNS，SG 白名单域名的 DoH 经 SG，其他 DoH 经 HK（Cloudflare 1.1.1.1）。
节点域名与 WG endpoint 用本地 DNS 引导，WG endpoint 明确 `ipv6_only`；这不是“所有 DNS 查询直连”。
IP 白名单要等解析后才知道是否命中，因此未匹配域名白名单的 DNS 查询仍按默认 HK 解析。

## 选路与故障边界

- 容器从一个 HTTPS 订阅拉取节点，用已有 `sing-box-subscribe-cli v1.0.4` 转换；不向第三方转换 API 提交订阅。
- 第一阶段经每个节点请求 `https://www.google.com/generate_204`，**必须返回 204 且正文为空**；不能只凭 curl 退出码把登录页/错误页当成功。环境代理不能替代被测节点。
- 第二阶段仅对每组 Google 耗时最短的 `max(2k, k+2)` 个候选下载 CacheFly `1mb.test` 前 128 KiB，要求 HTTPS、206、精确长度及固定 SHA-256；不足 k 个通过时继续测后续候选。两个目标均通过才算可用。
- 排名分数为 `0.6 × Google 请求耗时 + 0.4 × CacheFly 小块下载耗时`（毫秒，越低越好）。默认每组保留前 k 个；这是服务器视角的短名单排序，不是客户端网速保证。小块下载包含连接延迟，不能当作纯带宽测量。
- 默认每轮结束后 300 秒再刷新；k、间隔、并发、超时、上限可调。超过上限报错，不截断候选。
- SFA 中 HK/SG 各一个 selector，默认是本轮最快节点，其余 top-k 供手动选择。**不在手机上运行 urltest。**
- 自有 HK hy2 **始终列在 HK selector 末尾供手动选择**，不参与订阅节点 top-k 排名；订阅 HK 可用时，默认仍是服务器测得最快的订阅节点。
  只有本轮没有可用的订阅 HK 节点（包括订阅里没有香港节点）时，才探测自有 hy2；探测成功后把它作为默认节点，否则不发布新配置。
  订阅 HK 恢复后，下一份配置重新默认订阅节点，但仍保留自有 hy2 手动选项。
- 服务器测速只验证**容器当时到两个测试 URL**的路径，不能保证 Pad 所在网络或 Google/YouTube App 可用；`connection ... finished` 也不等于业务成功。
- 新加坡没有备份：SG 无候选或全失败都会拒绝发布。
- 订阅获取/转换失败、HK 与自有 hy2 都失败、手动节点被转换器丢弃、核心检查失败：不发布新配置，保留旧快照。
- `manual_nodes` 可放你自己的 vmess/vless/trojan/hysteria2/hysteria/tuic/anytls/ss/socks/http 链接，
  与订阅节点合并后一起参与分类与测速。手动节点只放进私有配置，不进 Git、不进镜像。
- **切换需要 SFA 重新拉取并应用配置。** 纯配置 URL 服务不能修改已经运行的客户端配置。手机网络上的节点状态可能不同于容器的探测结果。
- `10.77.0.0/24` 不通时由用户手动切换 v2rayNG，本服务不自动处理。

## 本地操作入口 `cli.py`（界面与输出全英文）

菜单（Rich + questionary）：Initialize private settings template / Render private runtime settings /
Build service image / Start service / Stop service / Show service logs / Follow service logs /
Show service status / Exit。
菜单依赖在 `requirements-menu.txt`（需 pin `prompt_toolkit==3.0.47`），只装进 venv；
同一批动作也可直接调用：`init`、`render`、`build`、`up`、`down`、`logs`、`status`，仅用标准库。

1. 选择 Initialize，生成 `private-config/settings.json`。已有文件绝不覆盖。
2. 用 Neovim 或其他编辑器填写占位符：`shared` 中的订阅 URL、自有 hy2，以及 `devices` 中每台设备的 API key。初始模板没有 WireGuard，默认只能使用 `proxyonly`。需要 `full` 的设备再添加完整 `wireguard` 对象，填写客户端地址（/32）、密钥和 endpoint。
3. `api_key` 必须为 **32–128 个 URL-safe 字符**：`A-Z a-z 0-9 _ -`。因为该 key 会出现在订阅 URL 的查询串里，
   `+ / = !` 等字符被拒绝（基密码管理器生成、带 `=+/` 的 base64 串会直接报 `api_key_format`）。
4. 填写 `singapore` 白名单。`direct` 可加个人强制直连条目，与内置列表合并。
   `manual_nodes` 是字符串数组，每项一条 URI（例如 `"hysteria2://.../#🇭🇰HK manual"`）；取名带香港/新加坡字样即可被分区正则识别。
   转换器若丢弃任一手动条目，本轮直接失败，不会静默少节点。
5. 选择 Render。校验通过后才产生 `runtime/settings.json` 和 Compose 所需 `.env`，并创建 `state/`。

**render 不拉订阅、不测速、不生成假节点、不启动容器。** 完整 SFA JSON 由容器获取订阅并验证后产生。
界面不会显示裸错误码：`failed: <code> - <fixed guidance>`，且不回显任何用户填写的值。
未填占位符会拒绝 render，这是有意的；不需要把真实私钥交给代理。

## Docker 部署边界

菜单里的 Build / Start / Stop / Logs / Status，或 `cli.py build|up|down|logs|status`，就是对
仓库根目录 `compose.yml` 里唯一 `config` 服务的 `docker compose build|up -d|down|logs --tail=100|ps`。
先探测 `docker info`：能用普通用户就不加 sudo；否则用 `sudo -v` 在终端里显式要密码，
并只把 `HTTP_PROXY/HTTPS_PROXY/NO_PROXY`（大小写都识别）经 `sudo --preserve-env` 传给 Compose。
未先 render 会以 `render_required` 拒绝，不会去动宿主服务。
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

## 配置接口

- 方法：**GET**
- URL：`https://<你的配置域名>/api/config-<模式>-<形态>?key=<该设备的 API_KEY>`。
- 模式：`global`（现有强制直连 → SG 白名单 → 其余 HK）、`blacklist`（再把中国 GeoIP/Geosite 直连，其他 HK）、
  `whitelist`（明确的国外 GeoIP/Geosite 才经 HK；中国及未知归属直连）。SG 白名单仍优先于国外规则，
  强制直连始终优先于 SG。`whitelist` 的国外 IP 来自 [SagerNet/sing-geoip](https://github.com/SagerNet/sing-geoip)
  常用的 20 个非 `cn` 国家/地区规则集合并，不以“不是中国 IP”代替“有明确国外归属”：
  US、GB、CA、AU、NZ、DE、FR、NL、CH、SE、NO、FI、JP、KR、SG、HK、TW、IN、IE、IL。
  合并源为其 `rule-set` 分支提交 `7fe82a879ad2666526730c195b55a6d8d9147908`，
  二进制文件 SHA-256 为 `717c07df3f02ec9ce215e14c3554fa20d27c82e93fa510f36c7071e56444d1e6`。
- 形态：`full` 保留 TUN 和 WireGuard；`proxyonly` 只提供混合代理入站，没有 TUN/WireGuard，适合服务器和过渡使用。未配置 WireGuard 的设备请求任一 `full` 接口返回 409 `wireguard_not_configured`；同一设备的三个 `proxyonly` 接口仍可正常下发。
- 六个路径：`/api/config-global-full`、`/api/config-blacklist-full`、`/api/config-whitelist-full`、
  `/api/config-global-proxyonly`、`/api/config-blacklist-proxyonly`、`/api/config-whitelist-proxyonly`。
- 每份配置都追加 `mixed` 入站（同端口提供 SOCKS4/4a/5 与 HTTP），默认 `127.0.0.1:10808`、无认证。
  可传 `port=20808&listen=127.0.0.1&user=alice&password=<密码>`；`user` 和 `password` 必须同时提供，
  不允许只传一项。`listen=0.0.0.0` 等非 loopback 地址会把代理暴露到该设备可达的网络，只有你主动传入才启用。
- `whitelist` 的 GeoIP 国外合并规则从相同配置域名的 `/api/rules/geoip-foreign.srs` 下载，
  URL 自动带同一个设备 key，由 HK 出站获取；反向代理须转发该路径并保留原始 Host。
  规则文件与服务代码同版本交付，不依赖客户端再从 GitHub 下载国外 GeoIP 数据。
- 旧 `/api/config` 返回 404，不作兼容别名。
- 也支持 `Authorization: Bearer <API_KEY>`，此时 URL 不需要 key 参数。
- 成功 200：完整 sing-box JSON；无效参数 400；密钥错误 401；缺少 WireGuard 的 `full` 请求 409；尚无有效配置 503；POST 405。
- `/healthz` 仅返回 ready/stale、刷新阶段、静态错误码、数量、是否启用 hy2，不输出节点、密钥或订阅地址。
- 健康检查检查 `ready`，不是仅看 HTTP 200。已有旧配置时 ready=true、刷新失败 stale=true。
- 诊断只走 stdout：菜单的 Follow service logs（`cli.py logs-follow`）持续显示每轮结果，
  失败时是 `refresh failed stage=<阶段> error=<静态码> | <异常类型>: <详情>`。
  **服务不往宿主写任何诊断文件**，`state/` 里只有 `snapshot.json`。
  API 仍只返回静态码；日志中的订阅 URL、API key、hy2 与手动节点凭据会被替换成 `<redacted>`。

默认 INFO 仅记录发布结果与失败摘要。需要查具体节点为何被筛掉时，在执行菜单的 Start service
（或 `cli.py up`）时设置 `SINGBOX_LOG_LEVEL=DEBUG`；Compose 将其传入容器，服务启动时生效。
DEBUG 逐个记录候选所属地区、标准化 tag、节点地址/端口/协议、Google 与 CacheFly 的探测
结果（HTTP 状态、字节数、耗时或 curl 退出码）、综合分数，以及最终 `selected`、
`google_failed`、`cachefly_failed`、`not_shortlisted`、`top_k_excluded` 等取舍原因。
日志中的节点名采用 `hk-007@abcdef123456` 形式：后缀是转换后节点配置（不含易变的 tag）
规范化 SHA-256 的前 12 位，订阅顺序或备注改变仍能关联同一节点。原始订阅 URI 在转换后
不逐条保留；哈希只用于诊断，不改变下发给客户端的节点 tag、排序或路由。
它不输出节点认证信息或原始订阅链接。`logs-follow` 只负责查看日志，按 Ctrl+C 不会停止服务。
仅改变日志等级无需重新 render 或 build，但要再次 Start service 让 Compose 按新环境重建容器；
未设置时恢复 INFO。无效等级会被本地 CLI 拒绝。

没有上传配置接口、远程修改接口或管理 WebUI。服务日志不记录请求 URL。
更换 API key 后旧 key 立即不再有效；策略改动在下一次成功刷新后发布。

## 回退与验收

## 故障排查：先看 healthz 的 stage

| stage | 含义 | 先查什么 |
|---|---|---|
| settings | 私有配置不可读或不合规 | 文件属主/权限 0600、字段是否齐全 |
| fetch | 订阅拉取失败 | 多半是容器没走代理，见下 |
| convert | 本地转换器失败 | 订阅格式、是否含不支持协议 |
| select | 分区或测速阶段 | 缺新加坡、候选超限、地区正则重叠 |
| check | 拼好的配置被核心判非法 | `docker compose logs` 里的 `tool failed: ... FATAL ...` |
| fetch | 订阅拉取失败 | 同上的 `stage=fetch` 行，先确认容器有代理 |
| convert | 本地转换器失败 | 同上的 `stage=convert` 行 |
| select | 分区或测速阶段 | 同上，常见 `singapore_unavailable`、`candidate_limit` |
| publish | 落盘失败 | state 目录权限 |

\`wireguard.address\` 可以写裸 IP（会自动规范成 \`/32\`）；带掩码时必须正好是 \`/32\`，否则拒绝。

容器只持有**启动它的那个 shell** 里的代理变量。宿主有代理并不等于容器有：先
\`export HTTPS_PROXY=http://<proxy>:<port>\` 再 \`cli.py up\`，或写成
\`HTTPS_PROXY=http://<proxy>:<port> python3 cli.py up\`。\`cli.py diagnose\` 会打印容器内代理环境
（只显示 set/unset，不显示值）并当场实拉一次订阅，能直接区分"网络不通"和"配置不对"。

在 SFA 中保留原有可用配置，新增这条远程配置，避免覆盖唯一救援入口；WG 失败按约定手动切换 v2rayNG。
仓库尚未在你的服务器部署；`docs/acceptance.md` 列出本地证据与必须由真实环境完成的验收。
测试使用标准库 unittest 和真实 1.14.2 核心、v1.0.4 转换器；测试解释器从 `SING_BOX`/`SING_BOX_SUB` 环境变量定位本地二进制。
真实订阅、私钥、渲染产物与快照均不进 Git/交付压缩包。
