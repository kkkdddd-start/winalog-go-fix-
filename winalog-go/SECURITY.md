# 安全策略

本文档说明 WinLogAnalyzer-Go 的安全策略、默认配置和最佳实践。

---

## 🛡️ 默认安全配置

### 网络访问

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| **监听地址** | `127.0.0.1` | 仅本地访问，不暴露到公网 |
| **端口** | `8080` | HTTP API 端口 |
| **CORS** | `localhost:8080` | 仅允许本地来源 |
| **认证** | 禁用 | 本地使用无需认证 |

### 数据库安全

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| **连接池** | 10 个连接 | 防止资源耗尽 |
| **空闲连接** | 2 个 | 保持最小连接数 |
| **连接超时** | 1 小时 | 自动清理过期连接 |
| **WAL 模式** | 启用 | 提高并发性能 |

### SQL 注入防护

✅ **已启用的防护措施**:

| 防护类型 | 说明 | 示例 |
|----------|------|------|
| **白名单机制** | 仅允许 SELECT/EXPLAIN/WITH 开头 | `SELECT * FROM...` ✅ |
| **禁止多语句** | 禁止分号 `;` | `SELECT...; DROP...` ❌ |
| **禁止注释** | 禁止 `--`, `/*`, `#` | `SELECT--注释` ❌ |
| **禁止 UNION** | 防止联合查询注入 | `UNION SELECT...` ❌ |
| **禁止文件操作** | 防止文件读写 | `INTO OUTFILE` ❌ |
| **查询超时** | 5 分钟超时保护 | 防止复杂查询卡死 |

### 前端安全

| 防护类型 | 说明 |
|----------|------|
| **CORS** | 仅允许 localhost 访问 API |
| **XSS 防护** | React 自动转义输出 |
| **localStorage** | 隐私模式自动降级到内存存储 |
| **静态资源** | 使用相对路径，支持子目录部署 |

---

## ⚠️ 如需外部访问

### 风险评估

在开放外部访问前，请评估以下风险：

- 🔴 **未授权访问**: 默认无认证，任何人可访问 API
- 🔴 **数据泄露**: 所有日志和告警数据可被读取
- 🔴 **注入攻击**: 尽管有 SQL 防护，仍存在其他攻击面
- 🔴 **中间人攻击**: HTTP 无加密，数据可被截获

### 安全加固步骤

#### 1. 修改监听地址

```yaml
# config.yaml
api:
  host: "0.0.0.0"  # 允许外部访问
  port: 8080
```

#### 2. 配置 CORS

```yaml
api:
  cors:
    allowed_origins:
      - "https://your-domain.com"
      - "https://siem.your-company.com"
    allowed_methods:
      - "GET"
      - "POST"
      - "PUT"
      - "DELETE"
      - "OPTIONS"
    allowed_headers:
      - "Content-Type"
      - "Authorization"
```

#### 3. 添加防火墙规则

**Linux (UFW)**:
```bash
sudo ufw allow from 10.0.0.0/8 to any port 8080 proto tcp
sudo ufw allow from 192.168.0.0/16 to any port 8080 proto tcp
```

**Windows (PowerShell)**:
```powershell
New-NetFirewallRule -DisplayName "WinLogAnalyzer" `
  -Direction Inbound `
  -LocalPort 8080 `
  -Protocol TCP `
  -RemoteAddress 10.0.0.0/8,192.168.0.0/16 `
  -Action Allow
```

#### 4. 使用反向代理 (推荐)

**Nginx 配置**:
```nginx
server {
    listen 443 ssl http2;
    server_name winalog.your-domain.com;

    ssl_certificate /etc/nginx/ssl/winalog.crt;
    ssl_certificate_key /etc/nginx/ssl/winalog.key;
    ssl_protocols TLSv1.2 TLSv1.3;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # 安全头
        add_header X-Frame-Options "SAMEORIGIN" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header X-XSS-Protection "1; mode=block" always;
    }
}
```

**Apache 配置**:
```apache
<VirtualHost *:443>
    ServerName winalog.your-domain.com

    SSLEngine on
    SSLCertificateFile /etc/apache2/ssl/winalog.crt
    SSLCertificateKeyFile /etc/apache2/ssl/winalog.key

    ProxyPreserveHost On
    ProxyPass / http://127.0.0.1:8080/
    ProxyPassReverse / http://127.0.0.1:8080/

    <Location />
        Require ip 10.0.0.0/8 192.168.0.0/16
    </Location>
</VirtualHost>
```

#### 5. 启用认证 (未来版本)

当前版本无内置认证，建议通过网络层控制访问：

- IP 白名单
- VPN 访问
- 反向代理认证 (如 Authelia, Authelia)

---

## 📋 安全最佳实践

### 部署环境

| 实践 | 说明 | 优先级 |
|------|------|--------|
| **内网部署** | 仅在内网环境运行 | 🔴 高 |
| **防火墙隔离** | 限制访问来源 IP | 🔴 高 |
| **HTTPS 代理** | 使用反向代理提供 HTTPS | 🔴 高 |
| **最小权限** | 使用非 root 用户运行 | 🟠 中 |
| **定期更新** | 及时应用安全补丁 | 🟠 中 |
| **日志审计** | 启用审计日志 | 🟡 低 |

### 配置管理

| 实践 | 说明 |
|------|------|
| **配置文件权限** | `chmod 600 config.yaml` |
| **敏感信息** | 不提交配置文件到版本控制 |
| **备份配置** | 定期备份配置和数据库 |
| **环境隔离** | 开发/测试/生产环境分离 |

### 数据保护

| 实践 | 说明 |
|------|------|
| **数据库加密** | 使用文件系统加密 (如 LUKS, BitLocker) |
| **定期清理** | 设置日志保留期限 |
| **导出加密** | 敏感报告加密存储 |
| **访问日志** | 记录所有 API 访问 |

---

## 🔍 安全检查清单

### 部署前检查

- [ ] 确认监听地址为 `127.0.0.1` (如需外部访问则配置防火墙)
- [ ] 配置 CORS 允许列表
- [ ] 设置防火墙规则
- [ ] 配置文件权限设置为 `600`
- [ ] 使用非 root 用户运行
- [ ] 启用数据库 WAL 模式
- [ ] 测试 SQL 注入防护

### 运行中检查

- [ ] 监控异常访问日志
- [ ] 定期检查连接池使用
- [ ] 监控查询超时情况
- [ ] 审计导出操作
- [ ] 检查磁盘空间使用

### 事件响应

如怀疑安全事件：

1. **立即停止服务**:
   ```bash
   systemctl stop winalog
   # 或
   pkill winalog
   ```

2. **保护现场**:
   ```bash
   # 保存日志
   cp -r logs/ /tmp/winalog-logs-$(date +%Y%m%d)
   
   # 保存数据库
   cp winalog.db /tmp/winalog-db-$(date +%Y%m%d)
   ```

3. **分析日志**:
   ```bash
   # 查看最近访问
   grep "ERROR\|WARN" logs/winalog.log | tail -100
   
   # 查看 API 访问
   grep "POST\|DELETE" logs/winalog.log | grep -v "200 OK"
   ```

4. **报告事件**:
   - 记录时间线
   - 保存证据
   - 评估影响范围

---

## 📚 相关文档

- [用户指南 - 安全配置](docs/user/USER_GUIDE.md#安全配置)
- [开发者指南 - 安全开发](docs/developer/SECURITY_GUIDE.md)
- [API 文档 - 错误码](docs/developer/API.md#错误码)

---

## 📞 安全联系

如发现安全漏洞，请：

1. **不要公开报告**
2. 通过 GitHub Private Vulnerability Reporting 报告
3. 或发送邮件到安全联系人

**响应时间**:
- 高危漏洞：24 小时内响应
- 中危漏洞：72 小时内响应
- 低危漏洞：1 周内响应

---

**版本**: v2.5.0  
**最后更新**: 2026-05-09  
**策略状态**: ✅ 已实施
