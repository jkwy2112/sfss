# SFSS 证书配置清单(你来签发,按此放置)

所有路径均为脚本/nginx 配置中**写死的引用位置**。签发后把文件放到对应机器的对应路径、设 `0600`(key)/`0644`(证书),然后重跑或 reload 即可。

## 需要你签发的证书总表

| # | 证书 | 类型 | CN/SAN | 部署机器 | 放置路径 |
|---|---|---|---|---|---|
| 1 | 蓝区服务端证书 | 服务端 | `blue-in-sfss.internal` + `blue-out-sfss.internal`(SAN 两条,或分别签两张) | 蓝区 VM | `/etc/sfss/tls/blue-fullchain.pem` + `blue-key.pem` |
| 2 | 绿区网关客户端证书 | 客户端(mTLS) | **CN 必须精确为** `sfss-green-gateway` | 绿区 VM | `/etc/sfss/tls/green-gateway-client.pem` + `green-gateway-client-key.pem` |
| 3 | 红区网关客户端证书 | 客户端(mTLS) | **CN 必须精确为** `sfss-red-gateway` | 红区 VM | `/etc/sfss/tls/red-gateway-client.pem` + `red-gateway-client-key.pem` |
| 4 | 管理网关客户端证书 | 客户端(mTLS) | **CN 必须精确为** `sfss-admin-gateway` | 管理跳板/蓝区 | `/etc/sfss/tls/admin-gateway-client.pem` + `admin-gateway-client-key.pem` |
| 5 | 网关 CA | CA | 签发 #2/#3/#4 的 CA | 蓝区 VM | `/etc/sfss/tls/zone-gateway-ca.pem` |
| 6 | 蓝区 CA | CA | 签发 #1 的 CA | 绿区/红区 VM | `/etc/sfss/tls/blue-ca.pem` |
| 7 | 试点对外域名证书 | 服务端 | `green-in.<域名>`、`red-in.<域名>`、`red-out.<域名>`、`green-out.<域名>` | 蓝区 VM(试点)或绿/红区 VM(生产) | 见下表 |

### 网关 CA → 蓝区的信任链

- 蓝区 nginx 用 `zone-gateway-ca.pem` 验证来的网关是谁(`CN=sfss-*-gateway` → 推导 zone 头)
- 绿/红区 nginx 用 `blue-ca.pem` 验证上游确实是蓝区(防中间人)
- 生产另需各 CA 的 **CRL**:`zone-gateway-ca.crl.pem`(蓝区)、`blue-ca.crl.pem`(网关),放在对应 CA 同目录

### 试点(pilot)模式可以最小化

试点只需要 **#7 的四张对外域名证书**(如果蓝区 edge.conf 直接对外),mTLS 客户端证书(#2/#3/#4)和 CRL 都可不放——脚本检测到缺失会自动降级为"仅 TLS 不校验",并打印提醒。生产模式缺任何一项脚本会拒绝继续。

## 每台机器的完整文件清单

### 蓝区 VM(`/etc/sfss/tls/`)

```
blue-fullchain.pem              # 生产必需:蓝区 8443 服务端证书(SAN 含两个 SNI 名)
blue-key.pem                    # 0600
zone-gateway-ca.pem             # 生产必需:信任绿/红/管理网关的 CA
zone-gateway-ca.crl.pem         # 生产必需:网关 CA 的 CRL
# 试点 edge.conf 对外时另需四张域名证书:
green-in-fullchain.pem / green-in-key.pem
red-in-fullchain.pem   / red-in-key.pem
red-out-fullchain.pem  / red-out-key.pem
green-out-fullchain.pem/ green-out-key.pem
```

生产还需(LDAP/审批中继,可选):
```
/etc/sfss/pki/ldap-ca.pem               # SFSS_LDAP_CA_FILE
/etc/sfss/pki/approval-relay-ca.pem     # 仅外发系统
```
密钥文件(`/etc/sfss/secrets/manifest-hmac` 等)由 secrets 管理器生成,不是证书。

### 绿区 VM(`/etc/sfss/tls/`)

```
green-inbound-fullchain.pem     # 对外 443: green-in.<域名> 入站上传门户
green-inbound-key.pem           # 0600
green-outbound-fullchain.pem    # 对外 443: green-out.<域名> 外发下载门户(如同一台VM跑两个入口)
green-outbound-key.pem
green-gateway-client.pem        # mTLS:CN=sfss-green-gateway,连蓝区用
green-gateway-client-key.pem    # 0600
blue-ca.pem                     # 验证蓝区上游
blue-ca.crl.pem                 # 生产
```

### 红区 VM(`/etc/sfss/tls/`)

```
red-inbound-fullchain.pem       # red-in.<域名> 入站下载门户
red-inbound-key.pem
red-outbound-fullchain.pem      # red-out.<域名> 外发上传门户
red-outbound-key.pem
red-gateway-client.pem          # CN=sfss-red-gateway
red-gateway-client-key.pem
blue-ca.pem
blue-ca.crl.pem                 # 生产
```

## 三条铁律

1. **客户端证书 CN 是安全边界**:蓝区靠 `CN=sfss-green-gateway` / `sfss-red-gateway` / `sfss-admin-gateway` 判定请求来自哪个区,再覆盖 `X-SFSS-Zone` 头。CN 签错一位,区域识别就错。
2. **两套 CA 分开管**:网关 CA(签网关)与蓝区 CA(签蓝区服务端)建议独立,单 CA 泄露不波及另一侧。
3. **CRL 必须自动化**:生产模板启用 `ssl_crl`/`proxy_ssl_crl`,CRL 过期或缺失会导致 nginx 拒绝启动——请配置 PKI 定期分发 + `nginx -t && nginx -s reload`。

## 签发参考命令(内部 CA 已有时)

```sh
# 例:绿区网关客户端证书(CN 必须精确匹配)
openssl req -new -newkey rsa:2048 -nodes \
  -subj "/CN=sfss-green-gateway/O=SFSS" \
  -keyout green-gateway-client-key.pem -out green-gateway-client.csr
openssl x509 -req -in green-gateway-client.csr \
  -CA zone-gateway-ca.pem -CAkey zone-gateway-ca.key -CAcreateserial \
  -days 90 -out green-gateway-client.pem

# 例:蓝区服务端证书(SAN 两个 SNI 名)
openssl req -new -newkey rsa:2048 -nodes \
  -subj "/CN=blue-in-sfss.internal/O=SFSS" \
  -keyout blue-key.pem -out blue.csr
openssl x509 -req -in blue.csr \
  -CA blue-ca.pem -CAkey blue-ca.key -CAcreateserial -days 365 \
  -extfile <(printf "subjectAltName=DNS:blue-in-sfss.internal,DNS:blue-out-sfss.internal") \
  -out blue-fullchain.pem
```

签好后按上表放置,然后:
- 蓝区:`./deploy/blue-deploy.sh pilot|production`
- 绿区:`./deploy/gateway-install.sh green <蓝区IP> inbound` / `... outbound`
- 红区:`./deploy/gateway-install.sh red <蓝区IP> inbound` / `... outbound`
