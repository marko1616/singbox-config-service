# 多订阅的具体配置与路由

新的功能目录与客户端组合见 [composition.md](composition.md)。本文件的 shared 路由字段说明仅适用于旧兼容格式。

## 应用范围与迁移

本次完整补丁从 GitHub main `ad1f3458c6a36120c9b428a83c741e3811dbe718` 应用；不叠加之前两份补丁。
[subscriptions.example.json](subscriptions.example.json) 是合并到 `private-config/settings.json` 的 **shared 字段片段**，不是完整 settings。

- 用编辑器将旧 `subscription_url` 的值搬到相应 `subscriptions[].url`，然后删除旧 `shared.subscription_url`。
- 旧 `shared.subscription_user_agent` 可删除；若保留，它会成为未显式指定 UA 的来源默认值。示例的两个来源均显式指定了 UA。
- 保留 devices、api_key、wireguard、own_hy2、direct、singapore、dns_hosts、public_base_url 和其他已有字段，不要用片段覆盖整个文件。
- TAG 使用 curl 和示例 UA `curl/8.10.1`；`user_agent: ""` 则让 curl 使用其实际默认 UA。
  此 UA 未经真实 TAG 链接验证。每个来源可独立指定 UA 与 `fetch_method`；这两个字段不是同一个设置。
- curl 不读取 .curlrc、不展开 URL 中的方括号/花括号；链接经 stdin 传入，不放在进程命令行。沿用容器的代理环境。
- 只能在本机填写真实订阅 URL，不需要把 URL 或抓取正文发给助手。

审查并应用补丁 → 编辑本地私有 JSON → 已有菜单 **Render private runtime settings → Build service image → Start service**。
确认发布成功后，在客户端刷新并重新应用配置。之后只改规则/间隔，Render 后由下一轮读取，不必重建镜像；startup 来源 URL/身份更改需要实际重启。
新建的 `docs/subscriptions.md`、`docs/subscriptions.example.json`、`tests/test_catalog.py` 在提交代码时需加入 Git 索引；Python/Docker 运行本身不依赖 staging。

## 规则如何执行

1. 来源配置里的 rename_rules 覆盖 shared.rename_rules；空数组表示本来源不改名。
2. 使用原始名称匹配 hk_pattern/sg_pattern，决定地区。重命名不能把香港节点变成新加坡出口。
3. 规则按顺序执行，第一条匹配即停止；未匹配保持原名。
4. pattern 使用 Python 正则；replacement 支持 `$1` 至 `$99`、`$index`、`$$`。`$0`、`$100` 和未知变量拒绝。
5. capture_defaults 可按组号设置空/未匹配捕获的默认值，例如 `{"2": "普通"}`。非空捕获优先；默认值是字面字符串。
6. 第二捕获组（含默认值）用于显示类型和 display_types 汇总，不修改真实协议字段。
7. 编号按输入顺序，在同一展开模板/显示类型内递增，最少三位；跨来源共享计数，健康失败仍占编号。
8. 调换来源、删除节点、来源抓取失败导致输入减少时，编号可能变化。编号不是永久节点 ID；客户端刷新后应检查手工选择。
   与 direct/proxy/sg/wg-ipv6/hk-own-hy2 重名或节点间重名会加 `[2]` 等后缀。

### 示例输出

| 原名称 | 显示名 | 类型 |
| --- | --- | --- |
| 🇭🇰 香港 01丨1x HK | 香港-普通-001 | 普通 |
| 🇭🇰 香港家宽 01丨1x HK | 香港-家宽-001 | 家宽 |
| 🇭🇰 香港家宽 02丨1x HK | 香港-家宽-002 | 家宽 |
| 🇸🇬 新加坡家宽 01丨10x SG | 新加坡-家宽-001 | 家宽 |
| 🇺🇸 美国-纽约 01丨1x US | 美国-纽约-普通-001 | 普通 |
| 🇺🇸 美国-家宽 01丨5x US | 美国-家宽-001 | 家宽 |
| 🇯🇵 日本蜂窝5G丨10x JP | 日本-蜂窝5G-001 | 蜂窝5G |
| 🇸🇬AWS新加坡04 … | 新加坡-AWS-001 | AWS |
| 🇸🇬AWS新加坡03 … | 新加坡-AWS-002 | AWS |
| 🇯🇵AWS日本09 … | 日本-AWS-001 | AWS |

TAG 的第一组取地区/城市，第二组取家宽、住宅、游戏等；无第二组时填普通。
AWS 规则用前瞻先把地区捕获为 $1，再把实际位于前面的英文标签捕获为 $2，不依赖截图截断的后缀。
规则国家列表可自行增删。示例隐藏原有倍率文字，但 **不改变计费倍率**；10x 节点不会自动排除。

## 实际路由和优先级

选择相应功能后客户端才生成 proxy、sg 两个 selector：proxy 包含所有地区的已验证节点，sg 只包含新加坡 top_k。
没有 HK selector。内部 HK 排序仅决定 proxy 的初始默认：健康订阅 HK → 健康自建 HY2 → 其他健康节点。
这是初始默认，不是自动故障切换；不限制 proxy 的可选地区，也不覆盖用户在客户端的手动选择。

业务规则按下列顺序在每个策略匹配阶段执行，最先命中的终止路由生效：

| 模式 | 每个阶段内的规则顺序 | 最终兜底 |
| --- | --- | --- |
| global | WG 覆盖网段（full）→ force-direct → singapore/sg | proxy |
| blacklist | WG（full）→ force-direct → 国内规则/direct → singapore/sg | proxy |
| whitelist | WG（full）→ force-direct → 国内规则/direct → singapore/sg → 国外规则/proxy | direct |

全链路为 sniff → 配置的 hosts 预解析 → 第一遍策略 → DNS hijack → resolve → 第二遍策略 → final。
**不是所有规则合成一次全局比较**：第一遍若已按域名命中 SG，后面的解析和 IP 规则不会再执行；保留原有行为。
更高优先级的直连/国内规则与 SG 重叠时仍优先直连。修改 proxy 到日本不会把已经命中 SG 的业务改走日本。

DNS：hosts 优先；自定义直连域名走 bootstrap；SG 域名走 dns-sg → sg；普通代理 DNS 为 dns-proxy → proxy。
blacklist 的 geosite-cn DNS 规则位于 hosts 之后、用户直连/SG 之前；whitelist 的国外域名走 dns-proxy，其余 DNS 兜底 bootstrap。
DNS 规则不包含业务 IP 条件，不能把业务 IP 路由顺序直接当成 DNS 顺序。远程规则集下载走 proxy。

## 可用、周期与失败边界

- 状态 counts.hk/sg/other 只统计订阅与手工节点；自建节点单列 counts.own_hy2，counts.all 是全量池，避免出现“测试 3 个、保留 4 个”的混算。
- 可用指服务端通过 Google 204 与 CacheFly 指定 128 KiB 片段验证，不代表用户客户端已实测。
- poll 来源的 interval_seconds（缺省取 refresh_seconds）控制重取订阅；startup 仅进程首轮获取；probe_interval_seconds 控制成功/失败/异常探测结果的有效期，均为 30—86400 秒。
- 新连接参数立即探测；同连接仅改名复用缓存。手工节点的 shared 重命名规则变更在下一轮生效，不等订阅缓存过期。
- 循环在前一轮结束后等待较小周期；单轮耗时、缓存逐项到期会推迟实际测试，不是精确定时 SLA。
- 单来源失败可用同源成功缓存或其他来源继续；healthz 顶层 sources 报告最新 stale/failed 状态，selection.sources 对应最近成功发布。旧节点仍须通过健康探测。
- 全部 poll 来源失败且没有可用 startup 目录、所选功能要求 SG 而 SG 全不可用、配置/内核校验失败时，不覆盖最后成功的内存配置及快照。没有 SG 时不会偷偷换成其他国家。
- 快照采用 version=3；升级前无版本或 version=2 的旧布局快照不恢复为新布局缓存：必须先完成一次成功发布。旧文件不会因恢复失败被删除，客户端现有配置也不会主动被撤销。
  需要回退时保留旧镜像、原私有设置与原快照，再通过已有菜单恢复；不要混用新旧配置格式。
- Docker 构建、真实订阅、用户网络和客户端刷新效果必须在部署端验收；本地 loopback 测试不能代替这些。
