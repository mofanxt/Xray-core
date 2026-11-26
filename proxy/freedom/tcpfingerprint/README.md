# Freedom TCP 指纹

Linux 上的 Freedom 出站可以读取受信中继通过 PROXY v2 私有字段 `0xE0` 发送的 IPv4 TCP 指纹。它兼容中继发送的 `v1:` 十六进制格式。VLESS 入站完成认证后，Freedom 按实际套接字来源查验 `trustedPeers`。

入站使用 RAW + TLS 或 REALITY 时，在 `streamSettings.rawSettings` 启用 `acceptProxyProtocol`。接收 PROXY v2 的监听应限制为受信中继。为直接连接的 Freedom 出站添加以下设置。

```json
{
  "protocol": "freedom",
  "settings": {
    "tcpFingerprint": {
      "queue": 19529,
      "trustedPeers": ["192.0.2.10/32", "192.0.2.11/32"]
    }
  }
}
```

每个启用此功能的出站使用独立的 NFQUEUE。运行进程需要 `CAP_NET_ADMIN`、`nft` 和 Linux NFQUEUE 支持。避免让其他服务在同一网络命名空间使用相同队列或高 16 位相同的套接字标记。

仅针对匹配连接的 IPv4 出站 SYN 执行改写。规则保留出口内核的 MSS、与时间戳协商有关的值和 TCP 序列号。缺少指纹、来源不匹配、协商选项不兼容或套接字已有策略标记时，使用内核生成的 SYN。应用数据仍由 Freedom 的原生 TCP 套接字承载，符合 Vision 条件的连接可以使用现有 `splice` 路径。
