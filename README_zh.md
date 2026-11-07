# sing-box 配置下发服务

[English](README.md) | 中文

为 sing-box Android 提供带认证的远程配置：从一份 HTTPS 节点订阅生成每台设备的配置，筛选可用的香港和新加坡节点，再供客户端刷新。它不为客户端运行代理，也不配置宿主机的 WireGuard 服务端、反向代理或路由。

## 配置选择

在 sing-box 中新增远程配置时，选择路由模式和配置形态：

| 模式 | 默认选路 |
| --- | --- |
| `global` | 除明确直连和新加坡规则外，其余走香港 |
| `blacklist` | 命中中国 GeoIP/Geosite 的目标直连，其余走香港 |
| `whitelist` | 命中国外 GeoIP/Geosite 的目标走香港，未知目标直连 |

三种模式都由自定义强制直连规则优先于新加坡规则。`full` 包含 TUN 和该设备独立的 WireGuard 连接；`proxyonly` 只提供本地混合代理，不含 TUN/WireGuard，适合尚未分配 WireGuard peer 的设备。

例如，`global` + `full` 的远程配置地址是：

```text
https://<你的配置域名>/api/config-global-full?key=<该设备的API_KEY>
```

可将 `global` 换成 `blacklist` 或 `whitelist`，将 `full` 换成 `proxyonly`。如果公网反代带路径前缀，应放在 `/api/` 之前。旧 `/api/config` 接口已停用。

## 首次使用

服务面向 Linux/amd64 和 Docker Compose。需要可访问的 HTTPS 节点订阅、香港与新加坡节点、自有香港 Hysteria2 备用节点，以及现成的 HTTPS 反向代理。设置期间保留客户端已有的可用配置。

1. 运行 `python3 cli.py` 打开交互菜单。菜单依赖列在 `requirements-menu.txt`，应装入虚拟环境；下面的直接动作只依赖 Python 标准库。
2. 选择 **Initialize private settings template**（或 `python3 cli.py init`），编辑被 Git 忽略的 `private-config/settings.json`：填写订阅、自有备用节点、各设备的 API key 和公网 HTTPS 基础地址。模板默认没有 WireGuard；需要 `full` 的设备各自添加独立的 WireGuard 身份，并在服务端分配 peer。字段结构见[模板](templates/private-config/settings.json)。
3. 选择 **Render private runtime settings**（或 `python3 cli.py render`），再选择 **Build service image**、**Start service**（或依次运行 `python3 cli.py build`、`python3 cli.py up`）。render 只校验和生成私有运行配置，不启动容器。
4. 查看 `/healthz` 是否为 `ready: true`，不能只看 HTTP 200。在客户端**新增**远程配置 URL 并刷新。服务仅监听 `127.0.0.1:8787`，须由已有 HTTPS 反代转发 `/api/`。若反代带路径前缀，`public_base_url` 须填写客户端实际访问的完整基础地址，供 `whitelist` 下载配套规则文件。

状态、日志、诊断和停止服务都可在菜单中操作。不要将私有设置、渲染结果或快照提交到 Git；反代也不应记录或缓存带 key 的配置 URL。

## 域名解析（DoH）

节点域名（`server`）、订阅地址等「隧道建立之前」就要解析的名字，统一走 `bootstrap`
这个解析器，类型是 **DoH over IP**，默认 `https://223.5.5.5/dns-query`：

- 不再用系统解析器，节点域名不会以明文 DNS 泄露给本地网络（DoH 提供方仍能看到查询内容）；
- 必须是 IP 字面量：写域名会变成「用 DNS 解析 DNS」的循环；
- 改法：`SINGBOX_BOOTSTRAP_DOH=https://1.1.1.1/dns-query` 后再 `cli.py up`；
- 业务流量仍走 `dns-hk`（`1.1.1.1` DoH，`detour: hk`），两条链路互不影响。

## 手动域名解析记录

在 `private-config/settings.json` 的 `shared` 对象里添加可选的 `dns_hosts`：

```json
"dns_hosts": {
  "app.example.com": ["192.0.2.10"],
  "dual.example.com": ["192.0.2.20", "2001:db8::20"]
}
```

以上地址仅为文档示例，使用时替换为实际目标地址。实际域名和地址只放私有配置，不要改公开模板或提交到 Git。

- 精确匹配域名，不匹配子域名；支持多条 IPv4（A）/IPv6（AAAA）。大小写和末尾一个点会规范化；国际化域名用 punycode。值必须是非空地址数组，不支持 URL、端口、CIDR、zone、通配符或 CNAME。
- 对所有设备、`global` / `blacklist` / `whitelist`、`full` / `proxyonly` 生效。静态记录优先于 DIRECT、SG 和中国域名 DNS 规则；HTTP/SOCKS 的域名目标也会先解析，避免代理节点重新解析绕过覆盖。**解析记录不指定出站**，实际目标仍按原有路由规则选路；IP 类规则会看到覆盖后的 IP。
- 使用 sing-box 原生 [hosts DNS](https://sing-box.sagernet.org/configuration/dns/server/hosts/)。只配置 A 时 AAAA 返回空结果，不回退公网解析（反之亦然）；其他记录类型由 hosts 返回 NXDOMAIN，不支持 TXT/MX/HTTPS 等记录。
- 仅覆盖进入 sing-box DNS 或以域名进入代理的业务请求。不会修改系统 hosts、上游权威 DNS、订阅拉取、节点/WireGuard 端点的 bootstrap 解析；应用自行使用 DoH、已解析成 IP 或被现有 DIRECT DNS 例外放行的查询不保证经过覆盖。
- 不填字段或设为 `{}` 保持旧行为。最多 10000 个域名，每个最多 64 个地址；规范化后的重复域名、空数组或非法地址会拒绝 Render/刷新，不静默忽略。运行中刷新失败保留上一份有效配置。

**首次启用**：审查应用补丁 → 用 Neovim 编辑私有配置 → 菜单 **Render private runtime settings** → **Build service image** → **Start service** → 日志确认本轮发布成功 → 客户端刷新并重新应用远程配置。必要时重启使用该域名的应用，清除其旧连接/缓存。

**后续增删改**：编辑私有配置后只需 Render，等待下一轮成功发布，再刷新并重新应用客户端配置；仅 Build/Start 不会读取新的私有源文件。删除某个键即恢复该域名的原有解析策略，清空 `{}` 可停用全部覆盖，原有救援配置应继续保留。

## 日志与排障

每轮刷新会为每个地区打一行汇总，默认 INFO 就能看到：

```
region hk: tested=10 google_ok=0 verified=0 retained=0 decisions={'google_failed': 10}
```

`retained=0` 时该行是 WARNING，并紧跟一条 `hk pool empty: tested=10, falling back to own_hy2`，
说明这一轮香港候选全部不可用、配置里只剩自有备用节点。逐节点细节（每个候选的
included/excluded、google 与 cachefly 结果、curl 退出码）用
`SINGBOX_LOG_LEVEL=DEBUG python3 cli.py up` 打开，看完改回 INFO。
订阅拉取最多尝试 3 次（1 秒、3 秒退避），每次失败记 `fetch attempt n/3 failed`。

## 边界与文档

节点测速发生在容器网络中；刷新失败时保留上一组有效配置。服务不能即时切换正在运行的客户端配置，不能保证手机网络到同一节点也可用，也不会在 WireGuard 路径故障时自动切换。没有 WireGuard 的设备可用 `proxyonly`；新加坡没有备用节点。

- [设计与实现边界](docs/design.md)
- [直连规则来源](docs/rule-source.md)
- [本地验证证据与实机验收清单](docs/acceptance.md)

本仓库尚未在用户的服务器或 Android 设备上部署和验收。
