# sing-box 配置下发服务

[English](README.md) | 中文

为 sing-box Android 提供带认证的远程配置：合并多份 HTTPS 节点订阅生成每台设备的配置，筛选全部地区的可用节点，再供客户端刷新。它不为客户端运行代理，也不配置宿主机的 WireGuard 服务端、反向代理或路由。

## 组合式客户端与 TAG 启动订阅

新模型将节点来源、功能定义和客户端选择分开。完整说明见 [组合配置](docs/composition.md)，可编辑的完整结构见 [示例](docs/composition.example.json)。

- `services` 定义可复用 proxy / singapore / dns / direct / wireguard 功能；`devices[].services` 选择引用，不是固定设备套餐。
- `devices[].mode` 选择 global/blacklist/whitelist，`ingress` 独立选择 mixed/tun/both。TUN 不再要求 WireGuard。
- 新配置地址为 `/api/config?key=<CLIENT_KEY>`，按该客户端选择生成。下表六种老地址仅用于兼容；不能重新打开未选择的功能。
- TAG 的 `update_policy: "startup"` 仅在发布器进程首轮获取；其他订阅可选 poll 并设 interval_seconds。健康探测仍独立周期运行。
- 每源成功节点目录以 0600 保存，重启获取失败可用同源缓存并报告 stale。首次迁移没有目录缓存时，需在 TAG 开关打开的 15 分钟内实际重启服务。
- 旧 settings 无顶层 services 时继续保持原行为；不能将旧 shared.direct/singapore/dns_hosts 与新目录混用。迁移字段及回退见上述文档。

## 配置选择

在 sing-box 中新增远程配置时，选择路由模式和配置形态：

| 模式 | 默认选路 |
| --- | --- |
| `global` | 除明确直连和新加坡规则外，其余走默认 `proxy` selector |
| `blacklist` | 命中中国 GeoIP/Geosite 的目标直连，其余走默认 `proxy` selector |
| `whitelist` | 命中国外 GeoIP/Geosite 的目标走默认 `proxy` selector，未知目标直连 |

三种模式都由自定义强制直连规则优先于新加坡规则。`full` 包含 TUN 和该设备独立的 WireGuard 连接；`proxyonly` 只提供本地混合代理，不含 TUN/WireGuard，适合尚未分配 WireGuard peer 的设备。

例如，`global` + `full` 的远程配置地址是：

```text
https://<你的配置域名>/api/config-global-full?key=<该设备的API_KEY>
```

可将 `global` 换成 `blacklist` 或 `whitelist`，将 `full` 换成 `proxyonly`。如果公网反代带路径前缀，应放在 `/api/` 之前。`/api/config` 现在按客户端组合提供配置。

## 首次使用

服务面向 Linux/amd64 和 Docker Compose。代理功能需要可访问的 HTTPS 订阅；只有选 SG 的客户端才要求可用的新加坡节点，自建香港 Hysteria2 可用 own_hy2=null 关闭。另需现成的 HTTPS 反向代理。设置期间保留客户端已有的可用配置。

1. 运行 `python3 cli.py` 打开交互菜单。菜单依赖列在 `requirements-menu.txt`，应装入虚拟环境；下面的直接动作只依赖 Python 标准库。
2. 选择 **Initialize private settings template**（或 `python3 cli.py init`），编辑被 Git 忽略的 `private-config/settings.json`：填写订阅、各客户端的 API key、公网 HTTPS 基础地址和服务引用。模板默认 own_hy2=null 且没有 WireGuard；需要 overlay 服务的客户端各自添加独立 WireGuard 身份，并在服务端分配 peer。字段结构见[模板](templates/private-config/settings.json)。
3. 选择 **Render private runtime settings**（或 `python3 cli.py render`），再选择 **Build service image**、**Start service**（或依次运行 `python3 cli.py build`、`python3 cli.py up`）。render 只校验和生成私有运行配置，不启动容器。
4. 查看 `/healthz` 是否为 `ready: true`，不能只看 HTTP 200。在客户端**新增**远程配置 URL 并刷新。服务仅监听 `127.0.0.1:8787`，须由已有 HTTPS 反代转发 `/api/`。若反代带路径前缀，`public_base_url` 须填写客户端实际访问的完整基础地址，供 `whitelist` 下载配套规则文件。

状态、日志、诊断和停止服务都可在菜单中操作。不要将私有设置、渲染结果或快照提交到 Git；反代也不应记录或缓存带 key 的配置 URL。

## 多订阅、全量 selector、测试周期与重命名

在 `private-config/settings.json` 的 `shared` 中用 `subscriptions` **替换**旧 `subscription_url`，保留其余配置：

```json
{
  "subscriptions": [
    {
      "name": "tag",
      "url": "<TAG_HTTPS_SUBSCRIPTION_URL>",
      "user_agent": "curl/8.10.1",
      "fetch_method": "curl",
      "rename_rules": [
        {
          "pattern": "^(?:[🇦-🇿]{2}\\s*)?(.+?)[-\\s]?(家宽|住宅|游戏|蜂窝5G|星链|实验节点)?(?:\\s+\\d+)?[丨|].*$",
          "replacement": "$1-$2-$index",
          "capture_defaults": {
            "2": "普通"
          }
        }
      ],
      "update_policy": "startup"
    },
    {
      "name": "other",
      "url": "<OTHER_HTTPS_SUBSCRIPTION_URL>",
      "user_agent": "",
      "fetch_method": "curl",
      "rename_rules": [
        {
          "pattern": "^(?:[🇦-🇿]{2}\\s*)?(?=[A-Za-z]+\\s*(香港|新加坡|日本|台湾|美国|英国|韩国))([A-Za-z]+).*",
          "replacement": "$1-$2-$index"
        }
      ],
      "update_policy": "poll",
      "interval_seconds": 300
    }
  ],
  "refresh_seconds": 300,
  "probe_interval_seconds": 900,
  "max_candidates": 1000,
  "rename_rules": []
}
```

这是要合并的字段片段，不是完整 settings。URL 只在你本机填写，不要发给助手。1—32 个来源，`name` 为唯一的 ASCII 标识。
新来源默认用本地 curl。上例 `user_agent: "curl/8.10.1"` 是显式 UA 示例，不代表探测到本机版本或真实 TAG 验证；也可设 `user_agent: ""`，保留本机 curl 的真实默认 UA，不强制 v2rayNG。curl 不读取 `.curlrc`，沿用容器环境代理。
可为单个来源设置 `fetch_method: "urllib"` 和 User-Agent。旧单链接＋旧 UA 配置仍可用；不能同时配置 `subscription_url` 与 `subscriptions`。
共同的 `subscription_user_agent` 可留作来源默认值，但 TAG 应显式使用空值或已验证的 UA，避免此前 403 情况。

- **全量池**：默认 `proxy` selector 列出所有地区通过两项测试的节点，无 top-k 截断；同名同连接配置跨来源去重，其他重名加后缀。
  测试失败的节点不会进入池；自建 HY2 也必须通过测试才加入。客户端按所选功能下发 `proxy`、`sg` selector；`sg` 继续取新加坡 top-k。`hk` 不再作为 selector 下发，仅保留内部香港统计及初始默认排序。
  默认选项仍优先最优 HK，再自建 HY2；没有可用香港时可选择其他地区。有客户端选择 SG 但无可用 SG 时拒绝新发布，绝不把 SG 规则改走默认池。
- **路由隔离**：一般流量及普通 DNS/规则下载跟随 `proxy`；指定新加坡的业务仍走 `sg`，其 DNS 仍走 `dns-sg → sg`。
  改默认选择到日本/美国不改变这些 SG 规则。直连、DNS hosts、WireGuard 以及三种模式原有优先级保留。
- **两个周期**：poll 来源的 `interval_seconds`（缺省 `refresh_seconds`）控制重取订阅，startup 不轮询，`probe_interval_seconds` 控制每个连接配置的测试结果有效期（30—86400 秒，成功、失败和异常结果都缓存）。
  未配置测试周期时沿用 refresh_seconds；新模板为 900 秒。循环以探测与各 poll 周期的最小值唤醒，实际测试还需等待前一轮完成，周期不是严格的实时 SLA。
  新增或连接参数变化的节点不等旧缓存到期；仅改显示名不改变测试身份。重启不恢复探测缓存，第一轮重新测试。
- **流量成本**：每个 Google 测试通过的节点，每测试轮读取 128 KiB CacheFly 内容；多节点、高倍率节点会增加用量。
  `proxy` 不自动排除 10x 家宽节点，选择此类节点会按机场规则计费。max_candidates 是全地区总上限，不会静默截断；旧配置的 200 可能需手动调高。
- **失败安全**：单来源失败可显式复用同源成功目录，healthz 顶层 sources 报告 stale/failed。全部 poll 来源失败且没有可用 startup 目录，或所选功能要求 SG 而 SG 全不可用时，保留最后成功发布。旧缓存也要通过当前健康探测。
  不把失败来源的旧节点悄悄混入新批次。客户端须刷新并重新应用，服务器更新不能即时改变已经运行的客户端。

### 正则与替换完全由配置决定

`rename_rules` 是按顺序匹配的规则数组，第一条匹配生效；`pattern` 使用 Python 正则，`replacement` 支持 `$1`—`$99`、`$index`（自动三位编号）及 `$$`（字面美元符号）。
捕获组和替换位置均可自行修改，并非固定国家/家宽词表。可选 `capture_defaults` 用字符串组号指定未匹配或空捕获的默认值；默认值按字面插入，不再次解释 `$`。每个来源可设置自己的 `rename_rules` 替代 shared 规则；空数组不重命名。
上面的两份订阅各有自己的规则，不要让 TAG 的规则处理另一家的名称；shared 的空数组只作未配置来源的默认值。
TAG 规则把 `🇭🇰 香港家宽 01丨1x HK` 改为 `香港-家宽-001`，普通节点改为 `香港-普通-001`；第二组未匹配时，`capture_defaults: {"2": "普通"}` 同时为名称和状态类型填入“普通”。
另一来源的规则针对截图可见的 `🇸🇬AWS新加坡04…`、`🇯🇵AWS日本09…` 前缀，生成 `新加坡-AWS-001`、`日本-AWS-001`，不依赖被截图截断的后缀。
因为原文 AWS 位于地区前，但要求 `$1` 地区、`$2` 类型，所以用前瞻 `(?=...)` 先捕获地区，再用第二组捕获英文前缀。国家列表可自行增删；未知格式保持原名。
编号按输入顺序、同一展开模板/类型分别递增，跨来源共享计数；测试失败的条目仍占编号，以免仅因健康状态变化就重编号。
修改来源顺序、删除节点可能改变编号；重名或与系统 selector 名冲突时追加 `[2]` 等后缀。

`$2` 就是正则第二捕获组：它用于名字中的显示类型，并计入状态中的 `display_types`。**它不会覆盖 SS/AnyTLS 等真实协议的 `type`**；原生客户端的协议栏依然显示真实协议。
只有显示名被替换，地区归属始终先按原名称匹配 hk_pattern/sg_pattern，避免替换规则去掉“新加坡”后破坏分流。

完整的来源规则、重命名样例和路由优先级见 [配置与路由说明](docs/subscriptions.md)。

首次更新：审查补丁 → 用 Neovim 编辑本地私有 JSON → 菜单 **Render private runtime settings → Build service image → Start service**，
观察日志成功发布，再刷新并重新应用客户端配置。以后只改 URL/规则/周期，Render 后等一轮即可，无需重建镜像。保留原私有文件和可用客户端配置便于回退。

## 域名解析（DoH）

sing-box 建立节点连接前需要的节点域名（`server`），走 `bootstrap`
这个解析器，类型是 **DoH over IP**，默认 `https://223.5.5.5/dns-query`：

- 不再用系统解析器，节点域名不会以明文 DNS 泄露给本地网络（DoH 提供方仍能看到查询内容）；
- 必须是 IP 字面量：写域名会变成「用 DNS 解析 DNS」的循环；
- 改法：`SINGBOX_BOOTSTRAP_DOH=https://1.1.1.1/dns-query` 后再 `cli.py up`；
- 业务流量仍走 `dns-proxy`（`1.1.1.1` DoH，`detour: proxy`），两条链路互不影响。

订阅抓取发生在发布器的 curl/urllib 中，使用容器的网络和代理解析路径，并不经过客户端配置里的 bootstrap；不要把客户端 DoH 当成订阅抓取 DNS 的保证。

## 手动域名解析记录

组合式配置把下列映射放入所选 DNS 服务的 `services.<名称>.hosts`；以下 `shared.dns_hosts` 写法仅用于旧兼容格式。

在 `private-config/settings.json` 的 `shared` 对象里添加可选的 `dns_hosts`：

```json
"dns_hosts": {
  "app.example.com": ["192.0.2.10"],
  "dual.example.com": ["192.0.2.20", "2001:db8::20"]
}
```

以上地址仅为文档示例，使用时替换为实际目标地址。实际域名和地址只放私有配置，不要改公开模板或提交到 Git。

- 精确匹配域名，不匹配子域名；支持多条 IPv4（A）/IPv6（AAAA）。大小写和末尾一个点会规范化；国际化域名用 punycode。值必须是非空地址数组，不支持 URL、端口、CIDR、zone、通配符或 CNAME。
- 对选择该 DNS 服务的客户端（旧格式为所有设备）、`global` / `blacklist` / `whitelist`、`full` / `proxyonly` 生效。静态记录优先于 DIRECT、SG 和中国域名 DNS 规则；HTTP/SOCKS 的域名目标也会先解析，避免代理节点重新解析绕过覆盖。**解析记录不指定出站**，实际目标仍按原有路由规则选路；IP 类规则会看到覆盖后的 IP。
- 使用 sing-box 原生 [hosts DNS](https://sing-box.sagernet.org/configuration/dns/server/hosts/)。只配置 A 时 AAAA 返回空结果，不回退公网解析（反之亦然）；其他记录类型由 hosts 返回 NXDOMAIN，不支持 TXT/MX/HTTPS 等记录。
- 仅覆盖进入 sing-box DNS 或以域名进入代理的业务请求。不会修改系统 hosts、上游权威 DNS、订阅拉取、节点/WireGuard 端点的 bootstrap 解析；应用自行使用 DoH、已解析成 IP 或被现有 DIRECT DNS 例外放行的查询不保证经过覆盖。
- 不填字段或设为 `{}` 保持旧行为。最多 10000 个域名，每个最多 64 个地址；规范化后的重复域名、空数组或非法地址会拒绝 Render/刷新，不静默忽略。运行中刷新失败保留上一份有效配置。

**首次启用**：审查应用补丁 → 用 Neovim 编辑私有配置 → 菜单 **Render private runtime settings** → **Build service image** → **Start service** → 日志确认本轮发布成功 → 客户端刷新并重新应用远程配置。必要时重启使用该域名的应用，清除其旧连接/缓存。

**后续增删改**：编辑私有配置后只需 Render，等待下一轮成功发布，再刷新并重新应用客户端配置；仅 Build/Start 不会读取新的私有源文件。删除某个键即恢复该域名的原有解析策略，清空 `{}` 可停用全部覆盖，原有救援配置应继续保留。

## 日志与排障

每轮会记录 hk、sg、other 三组的 `tested`、`verified` 和 `default_retained`；空组为 WARNING。
所有地区中同时通过 Google 204 和 CacheFly 指定片段哈希验证的节点都进入 `proxy`；不会因为 top-k 未入选就不测试。
`/healthz` 的 selection 含来源成功/失败状态、全部保留数量与 `$2` 捕获的显示类型计数，不包含订阅地址。
逐节点候选、Google/CacheFly 结果和 curl 退出码仍在 DEBUG 日志中。日志仅写容器 stdout，不写宿主机诊断文件。
订阅拉取最多重试 3 次（1 秒、3 秒退避）；多来源故障日志仅显示来源序号、阶段和异常类别，不反射 URL。

## 边界与文档

节点测速发生在容器网络中；刷新失败时保留上一组有效配置。服务不能即时切换正在运行的客户端配置，不能保证手机网络到同一节点也可用，也不会在 WireGuard 路径故障时自动切换。没有 WireGuard 的设备可用 `proxyonly`；新加坡没有备用节点。

- [设计与实现边界](docs/design.md)
- [直连规则来源](docs/rule-source.md)
- [本地验证证据与实机验收清单](docs/acceptance.md)

本仓库尚未在用户的服务器或 Android 设备上部署和验收。
