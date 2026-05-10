# WOL Manager

Single-file PHP Wake-on-LAN 管理器。

## 功能

- 登录保护与用户管理
- 设备列表管理（名称、MAC、IP、广播地址、端口、备注）
- 发送 Wake-on-LAN 唤醒包
- 设备在线状态检查（ICMP ping + TCP 端口探测）
- 设备数据和用户数据存储到 JSON 文件
- 默认管理员账号：`admin` / `admin`

## 文件说明

- `index.php`：主程序文件，包含前端界面、登录认证、设备管理和唤醒逻辑
- `wol_devices.json`：设备列表存储文件（首次运行时自动创建）
- `wol_users.json`：用户信息存储文件（首次运行时自动创建）

## 环境要求

- PHP 7.4+
- Web 服务器（例如 Apache、Nginx）
- PHP `socket` 扩展可选，用于更可靠地发送唤醒包
- 可写目录权限，用于创建和更新 JSON 数据文件

## 使用方式

1. 将文件部署到 PHP Web 服务器目录
2. 访问 `index.php`
3. 使用默认管理员账号 `admin` / `admin` 登录
4. 添加设备并发送 Wake-on-LAN 唤醒包

如果你对源码做了修改，可运行以下命令重新生成压缩后的 `index.php`：

```bash
php build.php
```

## 安全建议

- 首次登录后请立即修改默认管理员密码
- 部署到可信任网络环境中使用
- 生产环境建议使用 HTTPS
