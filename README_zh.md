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

## 边界与文档

节点测速发生在容器网络中；刷新失败时保留上一组有效配置。服务不能即时切换正在运行的客户端配置，不能保证手机网络到同一节点也可用，也不会在 WireGuard 路径故障时自动切换。没有 WireGuard 的设备可用 `proxyonly`；新加坡没有备用节点。

- [设计与实现边界](docs/design.md)
- [直连规则来源](docs/rule-source.md)
- [本地验证证据与实机验收清单](docs/acceptance.md)

本仓库尚未在用户的服务器或 Android 设备上部署和验收。
