# Provider 原生配置与密钥处理

部署时按顺序应用迁移 `001`–`051`。`047_provider_configuration.sql` 扩大 secondary ID/secret、自定义 OAuth URL、Logo 和 receiver 字段；`048_oauth_network_approvals.sql` 新增独立的私网批准记录，现用于可配置 OAuth 与 Custom HTTP 投递；`049_provider_transport.sql` 增加 SMTP `ssl_mode`；`050`、`051` 接入云目录私网审批与受管组台账。数据库迁移和代码应一起部署。OAuth v3 指纹包含认证方法及二级凭据，使旧待完成登录及旧私网审批失效，需重启登录并重新审查批准；内部 Custom HTTP 邮件、短信和通知须先批准，再用于 MFA、找回密码及消息投递。

## 正常读写入口

原生入口为 `POST /api/providers`、`GET/PUT /api/providers/{id}` 和 `GET /api/providers`。创建需填写 `owner`、`name`、`display_name`、`category`、`type`；更新不会改写资源 ID、owner 或 name。现有租户管理员权限和跨租户限制继续生效。兼容的 `get-provider/get-providers/add-provider/update-provider` 使用同一套 Provider 配置校验、投影和密钥合并规则，其字段名沿用 camelCase。

原生接口使用 snake_case，支持以下配置的保存和安全读回：

| 配置 | 字段与用途 |
| --- | --- |
| 主、次身份和凭据 | `client_id`、`client_secret`、`client_id2`、`client_secret2` |
| 自定义 OAuth | `custom_auth_url`、`custom_token_url`、`custom_user_info_url`、`custom_logo`、`scopes`、`user_mapping` |
| 邮件及消息 | `host`、`port`、`disable_ssl`、`receiver`、`title`、`method`、`app_id`、`sign_name`、`template_code` |
| 公共服务配置 | `issuer_url`、`provider_url`、`cert`、`idp`、`enable_sign_authn_request`、`http_headers` |
| 存储及其他原有配置 | `endpoint`、`intranet_endpoint`、`domain`、`bucket`、`path_prefix`、`region_id`、`sub_type`、`content`、`metadata` |

字段能保存不代表任意适配器都会消费它。以实际类型的消费契约为准：例如 Custom HTTP 通知的附加请求头来自 secondary secret 或 metadata 中的 `[name,value]` 数组，不会因为填写通用 `http_headers` 就自动发送这些头。存储字段另见 [云存储指南](cloud-storage.md)。

`user_mapping` 和 `http_headers` 接受 JSON 对象或包含该对象的 JSON 字符串，正常响应返回对象。`metadata` 接受 JSON 值或字符串，正常响应仍是经过安全处理的字符串。已知结构通常是 JSON 字符串；未知、不透明配置显示 `"***"`，不可把它当成一个空对象。

自定义 OAuth 的用户映射仅用于对应的 Generic/Custom/OIDC 路径。支持目标 `id`、`username`、`displayName`、`email`、`emailVerified`、`phone`、`phoneVerified`、`avatarUrl`，来源为点分对象路径，例如 `identity.externalId`；不支持 JSONPath 或数组索引。空对象重置为默认映射。内建适配器不支持非空自定义映射；Steam、Telegram、Lark/Feishu 不接受自定义 scopes。保存这类不支持的配置会被拒绝。

## 哪些值公开，哪些值脱敏

主密钥以及非 Email 类型的 secondary secret 会显示为 `***`。**Email 的 `client_id2` 是 From 地址，`client_secret2` 是公开的 From 显示名**，后者不是密码。SMTP 和 SendGrid 的实际发送会使用这个名称与地址；SMTP 登录用户名仍为 `client_id`，密码为 `client_secret`。显示名为空时，发送接口的 `sender` 作为显示名后备，不会覆盖已配置的 From 地址。邮件地址和显示名不允许 CR/LF 注入。

已有兼容配置可能把真实凭据放在回退字段：SendGrid 缺少主密钥时使用 `client_id` 作为 API key；Telegram 同样可能使用 `client_id` 作为 token。响应会按实际消费分支将这些载体脱敏。Slack、Discord、DingTalk、Lark、Teams 实际选中的 webhook URL 字段也按凭据处理。普通 OAuth client ID 和 Twilio account SID 仍可读。

新配置应优先把密钥放在正确的 `client_secret` 或 `client_secret2`，不要借公开 ID 字段保存新 token。历史兼容回退仍保留，但不会因此将真实 token 原样返回。WeChat 的敏感 `content` 同样脱敏。

## 保留、轮换与清空

| 更新值 | 行为 |
| --- | --- |
| 字段未提供或为 `null` | 保留当前值 |
| 秘密字段为 `"***"` | 保留当前数据库行中的真实原值 |
| 秘密字段为新字符串 | 显式轮换 |
| 文本秘密字段为 `""` | 显式清空 |

`***` 是保留标记，不是合法的新密钥。如果没有对应的已保存原值，创建或更新会失败，不能把标记直接写入数据库。更新在当前行的写锁下合并，所以另一个实例刚轮换的秘密不会被旧的脱敏快照替换。完整的脱敏 GET 响应也可用于同类型更新。

清空凭据可能让对应提供商无法发送或登录。Glory 的普通空密码输入会省略该字段，避免误清；需要清空时使用明确的清空操作。空 `user_mapping` 对象会重置映射；清空整个 `http_headers` 或 metadata 使用空字符串。

以下 HTTP 请求中的值均为占位值，需要管理员令牌和已存在的 Provider UUID：

```http
PUT /api/providers/PROVIDER_UUID
Authorization: Bearer ADMIN_TOKEN
Content-Type: application/json

{"client_secret":"***","display_name":"Updated display name"}
```

轮换时将 `***` 改为新密钥；清空时改为 `""`。不要把真实密钥写入文档、日志或版本库。

## metadata 和请求头

metadata 的公开字段按适配器分类，不会默认公开未知配置。例如 Azure/GCS 的 `storageApiEndpoint` 可读；Stripe 的 webhook secret 和 PayPal webhook ID 只显示脱敏值。Stripe 的 `webhookSecret`、`webhook_secret`、`signingSecret`、`signing_secret` 会归一化为 `webhook_secret`；PayPal 的 `webhookId/webhook_id` 归一化为 `webhook_id`。同一请求包含相互冲突的别名会被拒绝。

同类型 metadata 的对象更新按 key 合并。未知的旧字段不会因没有公开回显而在普通保存时丢失；`{}` 保持已有对象配置，`""` 才明确清空整项。已知密钥的 `***` 按对应 key 保留。未知、不透明 metadata 的整项 `***` 也只能保留已有原值，不能创建一份“内容为星号”的配置。

Custom HTTP 通知的 header 数组按 **header 名称** 匹配脱敏值，忽略名称大小写，不按数组位置保留秘密。因此下面的换序不会把两个 header 的秘密串错：

```json
[["X-Second", "***"], ["X-First", "***"]]
```

header 数组是完整的新列表，省略的 header 会移除；通用 `http_headers` 对象则按名称合并。所有 header 值保守脱敏，非法或重复名称、CR/LF 等非法值会被拒绝。Custom HTTP 通知优先使用 `client_secret2`，再使用 metadata；显式将已有 secondary secret 清为空字符串会禁用该配置，不会自动回退到 metadata。

Custom HTTP 通知的有效目标 URL 也会整体脱敏，因为 webhook 路径和查询可能包含凭据。按实际投递顺序选择第一个非空的 `endpoint`、`provider_url`、`client_id`、`receiver`；`***` 保留该槽位原值。切换 URL 槽位时必须明确替换或清空将变为普通公开字段的旧槽位，不能让旧 webhook 凭据自动公开。此规则同样适用于类别名称的大小写变体。

## 类型切换不允许把旧秘密变成公开字段

把 Notification 改成 Email 时，旧 secondary secret 不能悄悄变成公开 From name；把 WeChat 改成其他类型时，旧秘密 content 也不能变成普通可读 content。若旧秘密将进入公开字段，必须明确提交新的公开值或清空该字段，省略、`null`、`***` 都不能完成这种转换。

非空 metadata 跨 category/type 切换时同样需要明确替换或清空。新类型使用新的合并上下文，不会把旧的不透明秘密按新类型的公开白名单显示出来。切换凭据载体也受同一规则约束，例如新增 SendGrid 主密钥后，不能让原先作为回退 API key 的 `client_id` 自动公开。

## SMTP 的 ssl_mode / sslMode

原生 API 接受 `ssl_mode`，同时接受兼容别名 `sslMode`；兼容 API 读回 `sslMode`。只接受 `Auto`、`Enable`、`Disable`、空字符串及省略/null。未知模式拒绝保存；非 SMTP Provider 的非空模式明确拒绝，而不会保存一个实际未生效的开关。

| 配置 | 实际连接行为 |
| --- | --- |
| 显式 `Enable` | 任意端口均先建立隐式 TLS，证书验证成功后才进行 SMTP |
| 显式 `Disable` | 不使用隐式 TLS；服务端提供 STARTTLS 时必须升级，否则允许明文 |
| 显式 `Auto` | 按上游 gomail：465 隐式 TLS，其他端口机会式 STARTTLS；没有 STARTTLS 时允许明文 |
| 省略/null/`""` 且旧 `disable_ssl=false` | 保留本项目既有安全默认：465 隐式 TLS，其他端口必须 STARTTLS |
| 省略/null/`""` 且旧 `disable_ssl=true` | 保留旧字段兼容行为：机会式 STARTTLS，仅未提供时允许明文 |

新列保持 NULL，不把已有配置回填为 `Auto`，从而不会把未配置的旧记录从“必须 STARTTLS”降为允许明文。`null` 更新表示保留；空字符串显式切回旧布尔兼容策略。显式模式优先于旧布尔值。机会式模式可能遭受 STARTTLS 能力降级，仅应在操作者接受的受控网络选择；所有模式都保留证书校验，TLS 握手失败不会继续发送 AUTH 或邮件。

## Custom HTTP 的 body mapping

OAuth 的 `user_mapping` 仍是八个用户资料目标到远端点分对象路径。Custom HTTP Email 的目标为 `fromAddress/fromName/toAddress/toAddresses/subject/content`，SMS 为 `phoneNumber/content`；这些值表示实际输出字段名，不是 OAuth 对象路径。空对象重置默认映射；未知目标、重复输出名、空名和控制字符会被拒绝。其他投递适配器的非空映射明确拒绝。方法、内容类型、header 冲突规则由实际 HTTP 投递适配器共同校验，不会静默接收后忽略。

## 私有 Provider 地址需要单独批准

保存内部 URL 不会自动授予私网访问。批准是独立的服务端记录，绑定实际 Provider 配置；`owner=admin`、`owner=built-in`、metadata 里的某个标志都不代表已经批准。公开地址仍受检查后的 DNS、禁止跳转等传输规则约束。

仅当前有效的真实全局管理员可以调用以下受保护入口；租户管理员和应用身份不能批准：

```text
GET    /api/providers/{id}/network-approval
POST   /api/providers/{id}/network-approval   body: {"allow_private":true}
DELETE /api/providers/{id}/network-approval
```

适用范围为自定义 OAuth、OIDC issuer discovery、配置了明确 issuer 的 Okta，以及 Custom HTTP 邮件、短信和通知。状态包含 `allow_private`、`stale`、`approved_by`、`approved_at`。相关配置改变后旧批准失效，需管理员重新核对并批准；撤销使用 DELETE。执行时仍通过固定 DNS、超时、禁用重定向等网络检查，批准不是任意地址的通用放行开关。Custom HTTP 每次实际请求都复核当前配置和批准，包括多收件人的后续请求；已在途请求无法撤回。

本指南描述配置与保护规则。本机协议夹具和数据库回归用于验证应用行为；具体结果以当前完成度报告和测试日志为准，不代表真实第三方生产账号已验收。
