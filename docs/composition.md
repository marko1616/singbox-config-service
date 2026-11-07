# 订阅生命周期与客户端功能组合

本文件是新配置模型的入口。[完整示例](composition.example.json) 含 TAG/AWS 各自命名规则；其中 URL、key、hosts 和业务域名都是占位或保留域示例，不是线上配置。旧两层 settings 仍可读取，不能把旧 shared 路由字段与新 services 模型混用。

## 三个独立维度

1. `shared` 管节点来源和服务端健康检测，不表示某类设备。
2. 顶层 `services` 是可复用的命名功能目录；`devices[].services` 选择服务名。同一种功能可定义多套规则，但一个客户端只能选择其中一套；未选择的功能不下发。保留 `devices` 这个 JSON 键用于兼容，它的对象现在表示功能的消费者，而不是固定设备类别。
3. 客户端独立选择 `mode` 与 `ingress`。不再用“有没有 WG”决定是否拥有 TUN。`mode` 默认为 global；`ingress` 默认为 mixed，可选 tun/both。

```json
{
  "services": {
    "normal": {"type": "proxy"},
    "sg-business": {"type": "singapore", "rules": {
      "domain_suffix": ["sg-business.example.invalid"], "domain": [], "ip_cidr": []
    }},
    "resolver": {"type": "dns", "hosts": {}},
    "bypass": {"type": "direct", "rules": {
      "domain": [], "domain_suffix": [], "ip_cidr": []
    }},
    "overlay": {"type": "wireguard"}
  },
  "devices": [{
    "id": "phone", "api_key": "<KEEP_YOUR_EXISTING_KEY>",
    "services": ["normal", "sg-business", "resolver", "bypass"],
    "mode": "blacklist", "ingress": "both"
  }]
}
```

这是字段示意，`shared` 仍必需；不能将片段当成完整 settings。列表顺序不是规则优先级。

| 功能 type | 实际生成内容 | 未选择时 |
| --- | --- | --- |
| proxy | 全地区健康节点及 proxy selector；普通业务按客户端模式处理 | 无 proxy selector、无普通代理节点凭据；未命中其他服务的流量直连 |
| singapore | SG top_k、sg selector、该服务的业务规则 | 不下发 sg/规则，也不因这个客户端要求 SG 健康 |
| dns | hosts 覆盖、DNS 接管；结合已选择的 proxy/SG 提供相应 DNS 出口 | 无 DNS hijack、无 hosts、无 dns-proxy/dns-sg；基础 bootstrap 仍供核心解析节点/目标域名 |
| direct | 命名直连规则；render 会将仓库内置 DNS 服务直连清单合并到该服务 | 不给客户端注入这套直连规则 |
| wireguard | WG endpoint 与覆盖网段路由 | 不下发 WG 身份/endpoint |

WireGuard 是共享功能定义 + 每客户端私有身份：选 `overlay` 时必须在同一个 device 上保留原 `wireguard` 对象；不选时不能留下未使用的 `wireguard`，避免误解其是否生效。peer/address/private_key 仍必须各客户端独立。`own_hy2: null` 表示不配置自建香港节点。

DNS-only 是此代理配置中的 DNS 功能，不是额外启动一个宿主机 53 端口 DNS 服务器。mixed 处理进入代理的请求；需要接管系统流量时选择 tun/both 并由客户端授予相应权限。DNS 服务默认使用现有 bootstrap DoH；启用 proxy/SG 时对应 DoH 跟随相应 selector。

新地址：`https://<PROFILE_HOST>/api/config?key=<CLIENT_KEY>`。从客户端对象读 mode/ingress/services；依旧接受 port/listen/user/password 这些 mixed 参数。tun-only 不生成 mixed，故这些参数不会创建监听器。旧六种 `/api/config-<mode>-<full|proxyonly>` 地址保留兼容：full 仍要求 WG，proxyonly 仍移除 WG/TUN，但不能重新打开未选择的 proxy/SG/DNS 功能。新模型建议统一使用 `/api/config`。

## 组合约束与冲突

- `normal + resolver` 不带强制 SG 业务；`sg-business + resolver` 只将指定业务及其 DNS 放到 SG，其余业务/DNS 直连；`resolver` 可独立使用。
- blacklist/whitelist 依赖 proxy；SG/DNS/WG 不隐式启用 proxy。不满足依赖时拒绝配置，不静默补能力。
- 未知服务名、重复引用、同 type 多重选择、未知字段均拒绝。可以定义 `work-sg` 与 `game-sg` 两个 singapore 服务，让不同客户端选择不同规则；同一个客户端不允许同时引用二者。
- 为保持现有选路，本轮不改变匹配优先级：WG → 显式直连 → 国内规则（非 global 模式）→ SG → 国外规则（whitelist）→ final。即“强制 SG”不覆盖更高优先级的显式直连/国内规则；重叠时按该顺序处理，不按 services 列表顺序。具体两遍解析/DNS 优先级见 [subscriptions.md](subscriptions.md)。
- 仍使用原子的整批发布：只要有客户端选择 SG，SG 全不可用会阻止整批更新并保留上次成功配置；没有客户端选择 SG 时，不再要求 SG。每客户端独立 last-good 发布不在本轮范围内。
- 当前客户端服务/规则/入口发生变化、但尚未成功发布时，GET 返回 503 `client_configuration_pending`，不能借旧快照取得已取消的能力。单纯 API key 轮换继续即时生效，不等待重新抓取节点。

## 订阅获取策略不是节点协议

```json
{
  "name": "tag",
  "url": "<TAG_HTTPS_URL>",
  "fetch_method": "curl",
  "user_agent": "curl/8.10.1",
  "update_policy": "startup"
}
```

另一源使用 `"update_policy": "poll", "interval_seconds": 300`。原有 `rename_rules` 留在各自来源内，不受策略改变影响。

| 场景 | startup | poll |
| --- | --- | --- |
| 首次启动刷新，需要代理节点 | 一次获取操作（底层有最多 3 次有界 HTTP 重试） | 立即获取 |
| 后续定时刷新/客户端下载 | 不再获取；只复用节点目录、按探测周期重新测健康 | 到期获取；客户端下载本身不触发获取 |
| 返回 403、空内容、转换/核心校验失败 | 有同源缓存则继续使用并报告 stale；无缓存报告 failed，本进程不自动重试 | 保留同源缓存，下一获取周期重试；无缓存报告 failed |
| 服务重启 | 再尝试一次；失败可回退同源磁盘缓存 | 再立即获取 |
| 运行中新增/更改来源身份 | 等服务重启；无匹配缓存报告 pending_restart | 下一轮按新来源获取 |
| 诊断菜单 | 跳过，避免绕过仅启动约束 | 明确诊断动作可现场获取；不写发布器缓存 |

默认策略为 poll，缺少 interval_seconds 时取 shared.refresh_seconds；startup 禁止设置轮询间隔。probe_interval_seconds 与获取策略无关，取值仍为 30—86400 秒。循环按探测和 poll 的最短周期唤醒；这是周期性工作，不是精确定时 SLA。

“启动”是这个 Publisher 进程的首轮 refresh，不是客户端连接、首次下载，也不是 Docker healthcheck。首轮设置无效或没有客户端需要节点时，不会稍后补抓 startup 来源；修复/启用后重启服务。仅改重命名规则不改变来源身份，下一轮可用已缓存的原始名称重新命名，不需要打开 TAG 开关。

## TAG 操作与恢复

1. 在本地编辑器中保留原 TAG URL 与 rename_rules，加上 startup。curl UA 是显式示例，不保证绕过站点限制，也不能代替打开订阅开关。
2. 先用现有 CLI 菜单 Render，再在 TAG 控制台打开订阅开关；15 分钟窗口内通过菜单 Stop service → Start service 确保进程实际重启。单独 Start service 对已经运行的容器不保证重启。改代码后先 Build service image。
3. 查看 `/healthz` 顶层 sources 中 TAG 的 status/fetched_at：ok 为本轮成功；cached 为正常复用；stale 为最新获取失败但有旧缓存；failed/pending_restart 表示没有可用同源目录。之后客户端刷新并重新应用配置。
4. 首次升级尚无目录缓存且开关关闭，不能从凭空的旧配置恢复原始订阅。打开开关并重启，完成一次成功获取。不会自动登录或操作机场开关。

每个来源的成功目录单独存储在 snapshot 旁的 `snapshot.json.sources.json`（0600，包含节点凭据，属于私有 state，不可提交）。缓存键绑定 name/URL/UA/fetch_method，改 URL 或凭据不借用旧源的数据；不包含命名和获取策略，故改名不需要重新抓取。缓存由核心验证后原子写入，不要求后续整批路由发布也成功。重启时校验 owner/权限/格式；坏缓存拒绝使用。它没有自动过期时间，必须通过当前健康测试才能进入发布配置；缓存时间与 stale 状态均可观察。长期不重启意味着无法发现订阅新增/删除/凭据轮换，这是 startup 的明确取舍。

如果全部 polling 来源都失败，保留已有发布文件；若仍有 startup 缓存或其他有效来源，可以基于它们重测并发布，但健康状态标 degraded。SG 不可用不会偷偷替换国家。源抓取可用与节点健康、用户客户端实际连通是三种不同证据。

## 从旧设置迁移与回退

- 旧 settings 不含顶层 services 时维持原来的整体功能，仍可直接运行。新模板采用组合式模型，不会重写已初始化的私有文件。
- 保留 shared 的订阅/探测/重命名/own_hy2/manual_nodes 等；将 shared.direct → services.bypass.rules，shared.singapore → services.sg-business.rules，shared.dns_hosts → services.resolver.hosts，并删除这三个旧 shared 字段。
- 保留每个 device 的 id/api_key；添加 services/mode/ingress。原来有 WG 的 device 添加 overlay 引用并保留其原 wireguard 对象。没有 WG 的也可以选 ingress=both。
- 用编辑器迁移到 [完整示例](composition.example.json) 的结构，不要覆盖真实 URL、keys 和业务规则。只做私有设置迁移，无公开仓库凭据改动。
- 旧快照 version=2 或无版本不会作为 version=3 复用；保留旧镜像、原设置、原快照。先成功发布新布局再刷新客户端；回退时用这些备份恢复并反向应用同一完整补丁。新 source cache 不向旧版发布器注入配置。

## 验收矩阵与边界

| 维度 | 本地验证方式 | 部署端观察点 |
| --- | --- | --- |
| 正常 | 合成 TAG/AWS、独立计时、16 种基础功能组合、真实核心 check | TAG 开关开启后 sources.ok；客户端实际业务 |
| 切换 | 改引用/命名/URL、独立 TUN/WG、API 能力删除 503 | 新配置应用后仅选择的功能出现 |
| 恢复 | 重启 + 403/空响应 + 0600 同源缓存，重新健康探测 | TAG closed 时 stale 但已有健康节点仍服务 |
| 失败 | 坏/宽权限缓存拒绝、无缓存不重试、SG 健康失败留旧快照 | 无缓存首次升级需重新打开开关并重启 |

真实核心 loopback 用例验证普通代理、SG-only、DNS hosts-only 与直连互不串用；这不替代真实 TAG、Docker 镜像运行、宿主 TUN 权限、WG 握手和用户端网络验收。没有改动线上主备链路，也没有读取真实订阅。
