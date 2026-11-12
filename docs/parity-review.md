# Casdoor 改写复核（更新至 2026-11-12）

## 基线与结论

参考仓库：`E:/Repos/casdoor`，远端 `https://github.com/casdoor/casdoor.git`。
按用户要求 fetch 后 reset 到 `origin/master` 并 clean 本地文件；参考提交：
`47da539f886d5b09d2c35cf6ae78d8b6b5f30a43`（2026-10-27）。
Casdog 开始复核时已有未提交的兼容层、CAS、MCP、Telegram 和 Stripe 修改，本轮保留并继续完善。

**结论：已有较广的 IAM 骨架和不少真实实现，但不能称为完整 Casdoor 替代品。**
路由存在、编译通过、返回 401/500 均不证明功能等价。旧 `_todos.md` 把上一轮的局部修复扩大为整体完成，本次纠正。

## 第十三阶段提交快照（集成中，2026-11-12）

本次按要求提交当前工作区，包含下述已验收的第十二阶段，以及第十三阶段尚在集成的代码。新增 Active Directory 的 objectGUID 稳定身份和 UAC 状态转换、Azure Blob/GCS 驱动及测试、Kerberos 密钥表验票和共享防重放状态。Kerberos 组织配置使用迁移 045；组织接口对密钥表脱敏，回传 `***` 保留原值，非法配置整体回滚。

第十三阶段尚未完成整体验收：云驱动的正常上传路径、Provider 配置持久化与字段长度迁移、域名路径前缀接线和专用前端仍待完善；新增数据库回归与浏览器端到端回归尚未跑通。独立 Kerby KDC 与 JDK 已实际签发 AES128/AES256 票据，但不能据此宣称 Rust 验票及完整登录流程已验证。以下第十二阶段的 490 次执行和 25 项浏览器结果仅对应其阶段源码，不能直接套用于本提交的第十三阶段增量。

提交前重新执行的后端 `cargo check --offline --locked --tests --jobs 1`、前端 7 项原生测试、WASM 编译检查，以及两个浏览器检查脚本和 Kerberos PowerShell 夹具的语法检查均通过。后端检查仅证明代码及测试可通过类型检查，不代表新增数据库回归已经执行。

## 第十二阶段已验收状态（2026-11-12）

本阶段补齐持久购物车的多件商品统一付款、邀请定价授权、短信 MFA 备份号码兼容和 LDAP 完整分页。部署需顺序应用迁移至 044；应停止旧版本写入并统一升级实例，再开放新的购物车和邀请定价，避免旧程序绕过新订单与授权契约。

最终后端回归通过：37 个测试程序、490 次执行、0 失败、0 忽略；196 个显式 PostgreSQL 测试函数已逐名核对。前端 7 项原生测试、WASM 检查、Trunk release、浏览器夹具及 25 项真实后端浏览器检查全部通过。浏览器测试没有 API 拦截，包含原生 WebAuthn 注册/登录、SCIM 执行、MFA 备份恢复、邀请定价及整车结算。证据与完整范围见 `docs/phase12-gap-assessment.json`；源码摘要与原始日志在 `target/phase12/`。

- 购物车：按当前用户 UUID 持久保存，版本比较防止旧页面覆盖；支持添加、修改数量、逐项移除和清空。失效商品可以逐项移除而不被迫丢弃有效商品。整车按当前价格、币种、库存及邀请权限重新校验，创建一张多行订单、一条付款；同一版本重试返回同一订单。整数前缀分摊优惠，避免多行小额优惠的舍入负数。库存预留、释放和消费、余额扣款、充值及多个计划权益在统一交易内保持单次处理；外部付款沿用持久恢复和幂等流程。
- 兼容读取：接回 `place-order`，并为 `get-order`、订单列表补上 `productInfos/products` 历史快照，包含固化的商品、计划和定价名称；原目录改名不重写历史。普通买家按固定 UUID 读取自身订单及付款，其他账号仍被拒绝。`get-user/update-user` 的当前本人购物车与专用接口共用存储和 CAS；允许回传未变的完整用户对象，同时修改资料与购物车会整体拒绝，避免部分提交。
- 邀请定价：支持真实 `isInviteOnly/users` 的原生与兼容 CRUD。非邀请定价不使用白名单；邀请定价须同租户，空名单允许该租户所有用户，非空名单按当前用户名精确匹配。目录展示、购买、整车报价、首次付款及续费均检查；普通商店响应不暴露白名单。首次付款还检查计划及角色当前可用性，拒绝扣款后无法取得权益的情形；已接受外部付款仍沿用订单快照与既有安全检查。
- MFA 恢复：使用 `phonenumber` 支持上游 national phone 加 ISO countryCode，规范化为投递所需 E.164，覆盖 CN/US/PL。拒绝无效地区、实际无效号码、扩展号与号码地区不匹配；保留应用国家限制及普通上传的 MFA 降级防护。
- LDAP：请求分页并收齐完整结果后再原子同步。遵循 [RFC2696](https://www.rfc-editor.org/rfc/rfc2696.html) 的 opaque cookie 语义，允许相同 cookie 和空中间页；首次成功的完整不分页结果也可接受。估计总数不当作实际条目数。截断、坏控制、后续页缺控制、重复身份和资源超限均整体拒绝，不部分更新或禁用账户。当前边界为请求页大小 500、最多 100 页、10000 条、32 MiB。

整体仍未证明与 Casdoor 功能等价。下一优先级包括 Active Directory 二进制 objectGUID 稳定身份与 UAC 禁用位转换、更多数据库/目录和云存储提供商、Kerberos/协议互操作及更多专用前端。上游 AD 分组函数仍为空实现，不列为已有功能差距；退款仍属于可选扩展。静态声明保持 299/299，不换算为整体完成率。真实生产提供商、集群与可信硬件验收不能由本地模拟服务替代。

## 第十一阶段提交快照（历史，2026-11-12）

本次提交新增只读 SCIM 外部目录同步、Keycloak 原生 Argon 凭据验证及显式 MFA 备份恢复，并包含此前主题和连接池改进。部署需顺序应用迁移至 042。历史阶段记录中的未完成项以本节最新状态为准。

后端全量回归为 35 个测试程序、474 次执行、0 失败、0 忽略；181 个显式 PostgreSQL 测试函数已逐名核对。其中 Syncer 14 项、SCIM 4 项、导入与 MFA 恢复 15 项全部通过。前端 7 项原生测试、WASM 检查、Trunk release 和浏览器夹具通过；提交前再次运行原生测试及最新构建的浏览器夹具均通过。第十阶段真实后端浏览器的 21 项通过记录仍为历史证据；新增流程对应的 23 项端到端回归尚未完整通过，不能计为本阶段验收完成。

SCIM 已覆盖分页完整快照、失败回滚、稳定账号归属、资料映射及令牌脱敏；目前只读。Keycloak 原生 Argon 支持有界参数和明确元数据，拒绝损坏或未知配置。MFA 恢复使用独立管理员接口，验证应用与投递提供商绑定，保留单次消费及防删除后重新导入的凭据收据；不支持的因子明确拒绝。短信恢复目前要求国际 E.164 格式，上游 national phone 加 ISO countryCode 的规范化兼容尚未实现。

重新核对参考 Casdoor 后，未发现退款接口；此前报告将退款与权益冲回误列为上游必需差距，现纠正为可选扩展。后续仍需处理购物车、更多目录和云提供商、Kerberos/协议互操作及专用前端，并补齐新增流程的真实后端浏览器验收；不能把静态路由覆盖或本地模拟服务验证等同整体功能等价。

## 第十阶段状态（历史记录，2026-11-12）

当前实现包含此前认证、同步和商业流程，以及本阶段 Keycloak 凭据闭环、SQLx/Diesel 运行时连接池切换、Marketplace 主题安装恢复和 Glory 实际主题渲染。部署前需顺序应用迁移至 040。

第十阶段最终全量回归通过：34 个测试程序、463 次执行、0 失败、0 忽略；172 个显式 PostgreSQL 测试函数逐名核对成功日志。二进制复用库模块后移除了 38 次重复单测执行，因此不能直接与上一阶段的 492 次比较；本阶段实际增加 9 项测试。前端 7 项原生测试、WASM 检查、Trunk release 和浏览器夹具通过，真实后端浏览器回归扩展至 21 项。详细证据与范围见末尾第十阶段及 phase10-gap-assessment.json；这些结果不代表整体 Casdoor 功能等价。

功能边界仍明确：外部支付续费尚无离线扣款授权；Syncer 双向写回限于满足约束的 PostgreSQL 源，LDAP/Keycloak 写回拒绝，Keycloak 原生 Argon 凭据尚未实现；OTLP 仅支持 HTTP protobuf/gzip。连接池上限分别约束 SQLx、Diesel 的每个世代，旧请求排空期间可能有额外连接；0 最大连接数使用 PostgreSQL 服务器实际容量。主题只接受已声明的静态安全子集，拒绝主动代码及不支持的 CSS/HTML，不等同全部上游 React 主题或动态资源域名策略。上游 Agent 只有管理 CRUD，不包含代理执行协议。

## 可重复的覆盖指标

运行 `python scripts/check-casdoor-parity.py --reference E:/Repos/casdoor --output docs/casdoor-route-inventory.json`。

| 指标 | 复核前 | 第八阶段覆盖快照 | 边界 |
| --- | ---: | ---: | --- |
| 上游显式路由唯一路径 | 336 | 336 | 含协议和非 API 路径 |
| 可比较的扁平 API 路径＋HTTP 方法 | 299 | 299 | 排除嵌套协议和通配方法 |
| 匹配声明 | 227 | 299 | 75.92% → 100%，静态声明覆盖 |
| 缺失声明 | 72 | 0 | 当前范围与边界见 phase5-gap-assessment.json |
| 上游页面组件 | 105 | 105 | `.tsx` 位于 `web/src/pages`，文件数不是流程数 |
| Casdog 前端结构 | 8 独立页面＋29 通用资源配置 | 11 独立页面＋29 通用资源配置 | 通用 CRUD 不能等同专用业务页面 |
| 上游密码格式实现 | 仅 plain 直接匹配，其他有缺失或格式差异 | 8 类实现 | 已有旧 Casdog 格式读取兼容 |

此处不提供虚假的整体完成百分比：尚无逐场景 Casdoor/Casdog 差分测试，所有支付、目录、身份提供商也未用真实服务验证。

第二阶段时静态清单为 235/299，缺少 64 个声明；第四阶段新增 55 项实现后为 290/299，第五阶段补齐剩余 9 项后为 299/299。新增认证流程并不等于新增上游扁平路由，不能将该比例当作整体功能完成度。

## 第一阶段改进

- 密码：实现 plain、salt、sha512-salt、md5-salt、bcrypt、pbkdf2-salt、argon2id、pbkdf2-django；消除 bcrypt/MD5 的 SHA-256 写入替代；导入密码可以校验和修改，修改后算法标记、盐、修改时间同步更新。
- MFA：登录时真实验证已启用的 TOTP、恢复码及绑定账户的邮件/手机验证码；错误二次验证计入锁定；恢复码与验证码原子消费；不能用空值或任意 passcode 换取会话。
- MFA 设置：验证正确 TOTP 后才启用，禁止直接调用 enable 跳过验证或覆盖已启用密钥。前端补完整设置、验证、恢复码显示和删除请求契约；二维码在本地生成。
- 登录前端：统一入口；MFA challenge 不再保存空 token；提交二次验证码；识别 HTTP 200 中的业务错误；密码过期引导账户安全页；退出调用服务器。
- 兼容 API：支持 field/value、sortField/sortOrder、分页边界；保留自定义 JSON 属性键；屏蔽用户密码和 MFA 秘密；补 POST userinfo/run-syncer、验证/MFA/策略兼容路由。
- Kerberos：关闭将服务主体、请求头、query username 当作已认证用户的路径。保留 Negotiate challenge；在接入真正 GSSAPI/keytab 校验前明确拒绝登录。这是安全修复，不算 Kerberos 功能完成。
- 存储：修复全新迁移的 Casbin 空字段和 orders 保留字错误；补迁移按数据库会话时区将旧 naive 时间转换为模型要求的 TIMESTAMPTZ，并修复历史 Casbin NULL 字段。

## 第二阶段实现（历史记录，社交登录限制已由第三阶段更新）

- 授权：挂载统一资源授权过滤器；凭证缺失、身份验证失败、策略或资源解析失败时拒绝请求。租户管理员只能管理本租户，普通用户仅可操作自身允许的资料字段；列表、实际存储行、关联外键及特殊操作分别检查租户边界。全局管理操作保留给内置组织的管理员，不能只凭请求中的 owner 或凭证外形取得权限。
- MCP、SCIM 与消息发送：MCP 应用读写按实际应用和调用者租户定位，并屏蔽客户端秘密；SCIM 列表及单项查询限制在管理员租户或普通用户自身。邮件、短信和通知验证真实身份或客户端凭证，并校验所用提供商归属，禁止借其他租户的提供商发送消息。
- 社交登录：公开的是应用已配置提供商的安全展示信息；服务器生成随机 state，绑定浏览器、应用、组织和提供商配置。回调先单次消费 state，再向提供商兑换授权码和读取稳定 subject；按组织和具体提供商配置绑定账户，不因邮件地址相同自动合并。回调使用短期 HttpOnly 完成凭证，经同源会话接口换取登录结果，JWT 不放入跳转 URL；前端完成接收和跳转。
- 社交登录部署边界：生产环境需设置 `server.public_url` 为实际 HTTPS origin，并在提供商登记一致回调地址；仅本地 loopback 允许 HTTP。第二阶段曾使用进程内 state/完成凭证，并拒绝 MFA 账户从社交入口登录；第三阶段已替换为 PostgreSQL 共享状态和社交 MFA 补验，详见下节。
- 找回密码：新增公开请求和重置接口，前端契约同步。请求绑定组织、规范化邮件和可选应用；无账户、禁用账户与可恢复账户使用同类通用答复。256 位随机证明仅保存 SHA-256 摘要，15 分钟过期；数据库锁保护每来源和每收件人的频率限制，错误证明最多尝试 5 次。通过已配置且租户匹配的邮件提供商后台投递，不在响应或日志中返回证明。
- 密码与会话：重置时再次检查账户及当前组织密码策略，原子更新密码哈希、算法、盐和修改时间，同时消费账户的重置证明并删除既有会话及访问/刷新令牌。JWT 校验结合密码修改时间拒绝旧会话；退出以摘要记录当前 JWT 撤销状态。此机制也应用于已登录的密码修改入口。
- OAuth 令牌接口：补表单和 HTTP Basic 客户端认证契约，授权码与应用、回调及 PKCE 绑定；覆盖授权码单次兑换、刷新轮换和真实访问令牌的 userinfo 查询。

本阶段结果以末尾验证记录为准。社交提供商的令牌与资料端点、恢复邮件投递采用本机模拟服务；没有向真实第三方账号或邮箱发送请求。

### 四个原有数据库场景的重写范围

全部通过 `CASDOG_TEST_DATABASE_URL` 使用已迁移的专用数据库，创建独立 UUID 租户、管理员和应用，向完整路由注入 SQLx 与 Diesel 连接池。移除默认管理员密码依赖以及测试运行中的全局环境变量修改。

1. 扁平表单接口：真实新增、读取、列表、更新、删除，检查兼容响应字段及数据库保存结果。
2. 注册登录：验证 username 与显示名契约，注册、登录、读取自身账户、退出，再以旧 JWT 请求账户并断言拒绝。
3. REST 用户 CRUD：检查返回的用户 ID、租户、资料和列表内容，验证修改落库及软删除后的不可读取状态。
4. OAuth 授权码：通过 camelCase consent 请求取得真实授权码，以表单和 Basic 认证兑换；拒绝错误客户端密码、回调地址、PKCE 及授权码重放；验证刷新令牌轮换、旧令牌拒绝和 userinfo。

## 第二阶段补充修复

- 应用登录权限原实现查询不存在的 `permissions.resource_id/users/roles`；现改用实际资源、动作和角色关联表，隔离租户，检查规则启用状态，拒绝规则优先，并在密码登录、社交登录和授权同意中共用。
- 普通密码修改与找回密码均原子更新凭据、撤销旧令牌/会话；JWT 同时检查活跃用户、密码修改时间、撤销摘要和用户退出时间。模拟登录还检查原管理员及模拟会话，避免恢复已失效的管理员权限。
- 选择性 SSO 退出限定当前用户、租户和实际应用，避免同名应用下其他用户的令牌被删除。ID Token 与 userinfo 使用真实邮箱验证状态，userinfo 按授权 scope 返回资料。
- 通用验证码按当前用户、租户、用途、类型和有效期原子消费；注册证明另有浏览器 Cookie 绑定，联系人修改与证明消费在同一事务中完成。

## 第三阶段：社交登录 MFA、共享状态与账号绑定

- 共享状态：新增迁移 `019_social_auth_state.sql`，OAuth state、浏览器证明和会话完成证明均存储 SHA-256 摘要，应用、租户、提供商、用途及上下文持久化到 PostgreSQL。state 和完成证明均有效 5 分钟；数据库原子消费防重放，MFA 错误次数跨实例累计，过期清理与总量/租户容量限制控制积压。共享同一数据库的实例可继续处理登录，服务重启不再丢失这些证明，不再依赖粘滞路由。
- 社交 MFA：回调后的完成证明仅是短期登录证明，启用 MFA 时不会直接签发 JWT。支持 TOTP、恢复码及绑定联系人的邮件/短信验证码，前端可选择方式、发送代码、提交和取消。恢复码/验证码消费、完成证明消费与登录更新在同一事务中提交；错误预算与账户锁定写入数据库。账户、组织、应用、提供商、权限、身份绑定及凭据/退出时间均在完成时重新检查；损坏的 MFA 配置不会降级成免验证登录。
- 账号绑定：账户页增加应用选择、提供商绑定/列表/解绑。绑定需要最近 5 分钟内的有效登录及同源请求，OAuth flow 明确区分登录与绑定，回调再次验证原会话仍有效。按租户、提供商配置和稳定 subject 加数据库互斥锁；不能抢占另一账户的身份，不能用邮件地址自动合并，导入产生的重复身份会拒绝登录而不是任意挑选账户。
- 解绑：只允许操作自己且应用明确允许解绑的提供商；保留另一已启用的社交登录方式，或者验证当前密码且应用允许密码登录后才能解绑最后一个社交账号。绑定和解绑均拒绝模拟登录会话、跨租户目标、过期/已撤销会话及错误 Origin。
- 集成：静态绑定列表路由优先于公开的动态提供商路由，保留身份验证和授权过滤器；事务内策略查询共用当前连接，避免小连接池下重复申请连接造成阻塞。所有 Cookie 完成/发送/取消请求要求正确 Origin，JWT 不出现在回调 URL。
- 并发边界：绑定在取得用户锁后重新检查 OAuth 与会话的有效期；全局退出、当前会话撤销、令牌/会话删除和退出时间更新在同一用户锁事务中提交，退出时间采用拿锁后的数据库时间。MFA 设置确认统一采用用户行→MFA 行的锁顺序，避免与社交补验互相等待。

以上实现的验证结果见末尾第三阶段记录；真实外部提供商和完整浏览器流程仍是验收缺口。 升级时先应用迁移 019，再部署新版本；多实例需共享 PostgreSQL、JWT 配置和统一的 HTTPS `server.public_url`。正在使用旧内存证明的登录需重新发起，新版本创建的证明由数据库保存。

## 剩余缺口与优先级

| 优先级 | 范围 | 已确认的缺口 |
| --- | --- | --- |
| P0 | 授权与租户隔离 | 第二阶段已实现统一拒绝策略及 REST、SCIM、MCP、消息提供商租户检查，新增正反向数据库回归已通过。后续新增接口仍需显式授权规则；尚未穷举所有资源、业务角色与策略组合。 |
| P0 | 认证协议 | Kerberos 没有真实票据验证；SAML 签名/验证及全部协议仍需标准一致性和部署测试。OAuth state、回调、令牌撤销/退出已有第二阶段实现和回归用例，不能据此宣称所有协议完成。 |
| P1 | 社交登录 | 第三阶段已实现 PostgreSQL 共享 state/完成凭证、MFA 补验、已有账户显式绑定及安全解绑。真实 GitHub/Google 等提供商、真实浏览器和生产集群验收仍未完成；本机独立连接池回归不能代替生产部署验收。 |
| P1 | 找回密码 | 前后端、本机邮件 HTTP 及真实后端浏览器闭环已验证；租户/应用绑定、错误/过期/重放、并发消费与会话撤销已有数据库回归。真实 SMTP/云邮件环境仍需部署验收。 |
| P1 | MFA | 密码、社交、Passkey 和 FaceID 均已接入补验；第六阶段增加 PostgreSQL TOTP 时间步原子消费与 FaceID nonce 原子消费。FaceID 仍是现有 embedding 接口，可信摄像头采集和活体检查未实现；第七阶段已实现邮件/短信 code 和 LDAP 首因子及额外 MFA；生产目录与投递仍需部署验收。 |
| P1 | 兼容业务语义 | 已补专用 XLSX/CSV/JSON 用户导入、密码摘要/type/salt 语义与整批事务，Syncer 的 REST/兼容 CRUD 共用校验；其余资源副作用、复杂分页过滤、MFA enrollment 迁移与完整导出仍需逐场景补齐。 |
| P1 | 上游新模块 | 已补 Agent/Server/Entry/Key 管理、Marketplace 应用/提供商安装页面、OpenClaw 基础图及 Local/S3 transcript；OTLP/HTTP protobuf 已验收，第十阶段新增静态安全主题安装恢复及实际 Glory 渲染。gRPC、OTLP JSON、上游全部主题语法及更多专用页面仍有边界。上游 Agent 仅有管理 CRUD，不包含代理执行协议。 |
| P1 | 商业流程 | 已补计划/充值权益、持久 checkout 恢复、Stripe 对账/远端 expire、PayPal capture、普通用户商店；第九阶段增加明确受益人授权、余额自动续费及后台对账。第十二阶段补齐多件商品整车统一付款及邀请定价；外部离线扣款授权、超出幂等窗口的自动恢复仍缺；未知历史买家须人工审核。退款及权益冲回属于可选扩展，参考上游未发现对应接口。 |
| P2 | 运维功能 | 已补首次管理员密码、Dashboard、Webhook 重放、系统升级、持久设备授权、审计保留及 SQLx/Diesel 运行时连接池世代切换；两驱动各有独立上限，旧代排空可能暂时增加连接。生产集群与真实升级部署仍需验收。 |
| P2 | 提供商 | 存储仍仅 Local/S3，上游列出 11 类；同步器已验证 PostgreSQL 双向、源删除禁用、Values/affiliation、LDAP 单向、Keycloak PBKDF2/原生 Argon 凭据及只读 SCIM 外部目录。第十二阶段补齐 LDAP 分页；Active Directory 二进制 GUID/UAC 转换、更多数据库及云目录仍缺；LDAP/Keycloak 写回明确拒绝。 |
| P2 | 前端 | 105 个上游页面组件无法由 29 个通用 JSON 资源编辑器替代；复杂字段、验证、批量操作、关系选择、主题/i18n、组织应用定制需要逐场景验收。 |

## 验证

第一至第四阶段的历史构建环境使用当时的 D 盘目录。第五阶段遵循当前调用者环境与项目配置，产物和日志位置见末尾；本轮使用专用 PostgreSQL。
测试数据库是专用本地集群，未使用用户已有数据库服务。迁移 015 按会话时区解释历史时间；部署时应使用历史数据实际采用的时区。001/009 修复了无法从零运行的历史 SQL，已部署且使用迁移校验和的数据库需审核这两处历史修正及新迁移后升级。

第一阶段已通过（保留历史基线，不代表第二阶段合并后已重新通过）：

- 全新 PostgreSQL 数据库顺序执行 001–015 迁移（遇错立即停止）。
- 6 个真实数据库认证安全测试：密码迁移、TOTP 登录、错误二次验证锁定、HTTP MFA 设置/删除、恢复码并发消费、邮件码账户绑定/过期/单次消费。
- 现有 API 回归：175 通过，4 个旧数据库场景默认忽略。
- 前端：5 个单元测试、native `cargo check`、`wasm32-unknown-unknown` 检查通过。
- `cargo fmt --all -- --check` 与 `git diff --check` 通过。

- 合并后 `cargo test --workspace --jobs 2 -- --test-threads=1` 全部通过；默认忽略的 6 个认证数据库测试和 1 个 CRUD 数据库测试另行显式执行，全部通过。
- CRUD 数据库测试验证真实列表排序/过滤/分页、密码和 MFA 秘密屏蔽、普通用户仅可读写自身资料、禁止自提权、禁止跨租户修改/删除。
- 第一阶段时，旧 API 测试中的 4 个端到端数据库场景以及 1 个文档示例默认忽略，未计为通过；第二阶段已重写上述 4 个场景，已在第二阶段显式执行并全部通过。
真实第三方提供商/域环境和浏览器端到端测试不在已通过范围。

第二阶段当前验证状态：

- 已通过：在全新的 `casdog_phase2_verify` 数据库顺序执行 001–018 全部迁移；仍使用 D 盘专用 PostgreSQL 集群。
- 已通过：完整前端 6 个单元测试及 `wasm32-unknown-unknown` 编译检查，Cargo metadata 确认 target 为 `D:/BuildCache/casdog-web/target`。
- 已通过：`cargo test --workspace --tests --no-fail-fast --jobs 2 -- --include-ignored --test-threads=1`，11 个测试程序共 322 次测试执行，0 失败、0 忽略。其中 lib/main 分别重复运行相同的 38 项单元测试；该总数不是独立业务场景数。
- 已通过：22 个真实 PostgreSQL 场景（4 API＋6 认证安全＋5 授权＋1 兼容 CRUD＋4 找回密码＋1 社交登录＋1 验证码），均由上述命令显式执行。
- 已通过：原先剩余的 4 个场景：表单完整 CRUD、注册/登录/账户/退出及所有旧 JWT 失效、用户 CRUD、授权同意/真实 code 兑换/PKCE/客户端认证/ID Token 签名与 nonce/刷新轮换/userinfo/选择性退出隔离。
- 最终后端日志：`D:/BuildCache/casdog/phase2-passed-tests.log`；前端日志：`D:/BuildCache/casdog/phase2-web-tests.log`、`phase2-web-wasm.log`。文档中的示例测试未包含在 `--tests` 中。
- 已通过：最终 Rust 格式与 Git 差异空白检查。数据库场景在以下命令中通过 `--include-ignored` 显式执行。

数据库回归可通过显式设置 `CASDOG_TEST_DATABASE_URL`，执行：

```powershell
# 在仓库工作区使用调用者环境及项目正常构建配置
cargo metadata --no-deps --format-version 1
# CASDOG_TEST_DATABASE_URL 必须指向专用、已迁移的测试数据库
cargo test -p casdog --test auth_security_tests -- --ignored --test-threads=1
cargo test -p casdog --test legacy_crud_tests -- --ignored --test-threads=1
cargo test -p casdog --test authorization_tests -- --ignored --test-threads=1
cargo test -p casdog --test social_login_tests -- --ignored --test-threads=1
cargo test -p casdog --test social_state_tests --test social_mfa_tests --test social_link_tests -- --include-ignored --test-threads=1
cargo test -p casdog --test password_reset_tests -- --ignored --test-threads=1
cargo test -p casdog --test api_parity_tests -- --ignored --test-threads=1
```

Windows 本次构建使用已安装 PostgreSQL 18 附带的 OpenSSL 3 头文件/库（`OPENSSL_INCLUDE_DIR`、`OPENSSL_LIB_DIR`），并将 PostgreSQL `bin` 加入 PATH。默认 OpenSSL 自动探测失败后，通过明确指定已有 OpenSSL 3 头文件和库完成构建；未升级或替换系统库。

## 第三阶段验证记录

- 已通过：新建 `casdog_phase3_verify` 数据库，顺序执行 001–019 全部迁移；数据目录仍为 `D:/BuildCache/casdog/postgres`，未使用 Docker。
- 已通过：前端 6 个原生单元测试及 WASM 编译检查；日志为 `D:/BuildCache/casdog-web/logs/phase3-native-tests.log`、`phase3-wasm-check.log`。`phase3-metadata.json` 核实 target 在 D 盘。
- 已通过：`cargo test --workspace --tests --no-fail-fast --jobs 2 -- --include-ignored --test-threads=1`，14 个测试程序共 343 次执行，0 失败、0 忽略；lib/main 各重复执行相同 37 项单元测试，总数不是独立业务场景数。最终日志：`D:/BuildCache/casdog/phase3-passed-tests.log`。
- 已通过：44 个真实 PostgreSQL 场景，包含原有 22 个及本轮新增的 22 个。新增分组为共享状态/原子退出 6 个、社交 MFA 10 个、账号绑定 6 个；原有社交 OAuth HTTP 场景扩展为跨实例发起/回调/完成。原先剩余 4 个 API 数据库场景再次全部通过。
- 已通过：锁等待跨过 OAuth/JWT 有效期时拒绝绑定，退出等待用户锁后原子提交撤销和时间边界，MFA 设置与登录采用一致锁顺序；容量清理、并发单次消费和跨实例尝试预算亦通过。
- 已通过：最终 `cargo fmt --all -- --check` 与 `git diff --check`。Cargo metadata 再次核实 backend target 为 `D:/BuildCache/casdog/target`。
- 验证过程中 D 盘曾耗尽，导致一次 PostgreSQL 容量场景写入失败；使用 Cargo 包级清理释放可重建产物后，以 `CARGO_INCREMENTAL=0` 重新执行上述完整回归并全部通过。构建、缓存、临时文件与测试数据始终位于 D 盘。

共享状态测试使用独立 PostgreSQL 连接池模拟多服务实例及连接池重启；HTTP OAuth 流程在实例 A 发起、实例 B 回调、实例 A 完成，另一个实例拒绝重放。提供商令牌/资料和邮件投递采用本机 HTTP 模拟服务；短信验证测试使用精确绑定到完成证明的数据库记录，没有向真实运营商发送短信。实际 GitHub/Google、SMTP/云消息及完整浏览器验收仍未计为通过。

## 第四阶段：64 个接口与普通密码登录 MFA

本轮在第三阶段固定的 Casdoor 参考提交上继续开发。新增 55 个扁平方法/路径声明，静态匹配从 235/299 增至 290/299，尚缺 9 项；新增声明有具体处理逻辑，但下列高级行为仍不完整，不能将 96.99% 的静态覆盖率作为整体功能完成度。

- 资源与集成：Agent、Entry、Key、Server 的真实持久化 CRUD、租户权限、引用校验、分页/过滤/排序和密钥遮蔽；新增 Integration 目录/详情及应用/提供商模板的安装、卸载事务；Marketplace 目录与 bundle 校验；OpenClaw 基础会话关系图；应用绑定的短期 MCP read token。独立 JSONB 资源表保存经校验的上游字段。
- 商务与运维：优惠券管理、有效期/用户/商品/限额校验、支付订单的优惠预留与核销；普通商品购买与现有 PaymentFlow 对接；订阅续费标志；真实数据库仪表盘聚合、全局设置保存、联系人权限、批量权限更新、域名到期查询，以及 Webhook 事件历史、真实投递和重放状态。
- 系统与首次初始化：全局表单、本人会话重复检测、仅允许已配置 issuer 的 IdP discovery；首次管理员密码仅在 built-in/admin 密码为空、从未登录时开放，要求同源请求，数据库行锁确保只接受第一次设置，已有密码不能通过该接口覆盖。
- 普通密码 MFA：正确密码之后签发 5 分钟浏览器绑定挑战，数据库只保存证明和验证码摘要；邮件/短信只能发到当前已绑定联系人，包含持久化错误预算和发送限速。补验时重新检查账户、组织、应用权限、凭据及退出状态；验证码/恢复码与挑战在同一事务中消费。前端清除已提交密码，支持选择方式、发送、验证和取消。旧的通用邮件/短信验证码不能直接换取密码登录会话。 HTTP 客户端对已启用 MFA 的账户需采用两步契约：`POST /api/login` 获取 Cookie 挑战，再调用 `POST /api/auth/password/session` 提交因子；发码和取消分别使用其 `/send-code`、`/cancel` 子路径。初始登录请求中自带 passcode 不会直接完成登录，前端已同步迁移。

第四阶段仍有的语义边界：Key 管理尚未接入 API credential 身份验证；Agent/MCP 配置管理不包含代理执行、远端 tools 同步和内网扫描；MCP read token不等同于管理员 session JWT。Marketplace 不支持 theme 模板、缓存及备用目录源。OpenClaw 图缺复杂控制流推断和原始 transcript 存储。设置已持久化，但连接池/保留策略仍需运行时配置集成。购买只支持普通商品，未覆盖定价计划、自定义充值；外部异步 checkout 的库存预留仍需完善，autoRenew 标志不代表自动续费调度器已完成。域名 RDAP 和真实第三方目录、支付、邮件/短信环境仍需部署验收。

### 第四阶段剩余的 9 个接口

- `GET /api/get-openclaw-session-transcript`：缺原始 transcript 对象存储与查询。
- `GET /api/get-upgrade-info`、`POST /api/upgrade-system`：缺发布包信任、升级及重启机制。
- `GET /api/scan`、`POST /api/sync-intranet-servers`：缺扫描器与内网发现实现。
- `POST /api/sync-mcp-tool`：缺远端 MCP 协议工具同步。
- `POST /api/cancel-device-auth`、`POST /api/device-auth-complete`：需替换现有不完整的设备授权缓存，完成持久化状态及令牌授予流程。
- `POST /api/verify-identification`：缺真实身份核验提供商。

### 第四阶段验证记录

- 已通过：`cargo test --workspace --tests --no-fail-fast --jobs 2 -- --include-ignored --test-threads=1`，18 个测试程序共 **366 次执行，0 失败、0 忽略**。lib/main 各重复执行相同的 37 项单元测试，执行总数不是独立业务场景数；本命令不含文档示例测试。
- 已通过：**62 个真实 PostgreSQL 场景**。其中本轮新增 18 个：普通密码 MFA 7、资源/Marketplace/MCP 4、商务运维/Webhook 3、系统/首次密码 4；原有 44 个场景和原先剩余的 4 个 API 数据库场景均再次通过。
- 已通过：密码证明后发码、跨实例单次消费、OTP 摘要、发送限速、联系人/应用/权限/密码与退出状态复核；真实本机邮件 HTTP 投递；普通密码 TOTP/恢复码的两步接口契约；MFA 后授权码、回调、grant 和公开客户端 PKCE 校验。
- 已通过：资源持久化、密钥遮蔽/更新保留、跨租户拒绝、Marketplace 安装回滚/卸载及同名重装；MCP 真实 JWT 授权与持行锁后退出时间复核；余额支付/优惠核销/失败释放/末件商品并发，UUID 同名攻击拒绝、分以下金额拒绝；真实本机 Webhook HTTP 500→200 重放与状态记录。
- 已通过：首次密码并发只能一个成功、已有密码不能再次覆盖；本人会话检测、全局表单权限、配置绑定的 IdP discovery 本机 HTTP 查询。首次密码测试仅在专用数据库临时保存并恢复预置管理员记录，不依赖默认管理员密码。
- 已通过：前端 6 个原生测试及 `wasm32-unknown-unknown` 编译检查。日志：`D:/BuildCache/casdog-web/logs/password-mfa-native-tests.log`、`password-mfa-wasm-check.log`，metadata 核实前端 target 在 D 盘。
- 已通过：新建 `casdog_phase4_verify`，执行迁移 001–022；022 的预留/核销历史外键修正已在测试前应用。部署前需应用 020–022。所有构建、临时文件和数据库存储均在 D 盘，未使用 Docker；后端 metadata 核实 target 为 `D:/BuildCache/casdog/target`，最终构建关闭增量缓存。
- 已通过：最终 Rust 格式、Git 差异空白检查和静态清单脚本。后端最终日志：`D:/BuildCache/casdog/phase4-passed-tests.log`；逐接口处理清单：`docs/phase4-gap-assessment.json`。

以上数据库与本机 HTTP 测试没有验证真实 SMTP/短信运营商、支付网关、Marketplace 线上目录、RDAP 公网查询或完整浏览器流程，相关部署验收仍保留。


## Glory / Sapid 前端迁移（2026-11-11）

- 前端使用当日核验的 crates.io 最新稳定版本 Glory 0.7.0 和 Sapid 0.7.1，最低 Rust 1.95。依赖、组件、启动入口和构建配置已迁移，移除 Dioxus 依赖与配置。
- 使用 Trunk 生成 `web/dist`，后端构建脚本从此目录嵌入静态资源。开发服务器代理 `/api/` 至端口 8000，开发及验证命令见 README。
- 迁移覆盖登录、注册、找回密码、账户、OAuth 授权、同意管理、设备授权和结果页，以及原有 29 项通用资源配置。表单使用 Sapid 控件，二维码本地生成，资源结构化表单保留自定义 JSON 字段。
- 已验证 6 项原生单元测试、WASM 编译检查、Trunk release 构建及后端资源目录选择。浏览器回归运行编译后的 WASM，覆盖密码登录 MFA 的错误与成功路径、社交登录 MFA、绑定与解绑、注册、资源增删改与自定义字段保留、整数端口和含空格枚举值、联系信息验证码、TOTP 设置、同意授予与撤销、设备批准、找回密码和退出。
- 浏览器回归采用 API 夹具，检查运行时错误和 1440px / 390px 布局。产物位于当前工作区正常目录 `web/target/browser-check/`，日志位于 `web/target/`。数据库和真实外部身份提供商联调需按原有回归流程单独验收。
- 此次框架迁移验收时 WebAuthn 页面只提供凭据列表、删除与注册初始化；浏览器凭据创建及提交注册完成步骤已在第五阶段补齐。通用资源编辑器与上游专用业务页面之间的流程差距继续按 P2 前端项验收。


## 第五阶段 WebAuthn 与剩余接口（2026-11-11）

- WebAuthn 使用真实 `navigator.credentials.create/get`，完成注册、列表刷新、删除、登录、取消及页面离开时中止。注册与登录挑战保存到 PostgreSQL，绑定用户、租户、Origin、会话或浏览器 Cookie，5 分钟过期、单次消费并限制待处理数量。RP 与 Origin 使用配置的 `server.public_url`，开发使用 `localhost`；注册复核近期会话、撤销和密码变更。已启用额外 MFA 的 Passkey 登录继续走原有补验接口，补验前返回空 token。
- 剩余 9 项声明已补齐。设备授权增加数据库状态、浏览器审批、RFC 8628 轮询与 `slow_down`、机密客户端验证、JWT/刷新令牌签发、单次完成和取消证明；审批及兑换复核应用、租户和审批会话的撤销状态。`verification_uri_complete` 可直接打开设备页。
- 原始会话记录通过现有 Provider/Entry API 和 `upload-resource` 的 `entryId`、`tag=openclawTranscript`、Local provider 上传，自动关联真实对象与资源记录，再按 Entry 查询最多 2 MiB 预览，原文上传限制为 32 MiB。MCP 同步执行真实 HTTP 协议初始化、会话头、JSON/SSE 响应及工具分页，失败保留既有工具及权限。
- 升级要求运维固定 manifest 摘要、同源包摘要/大小/平台、安装路径和重启程序；文件替换前持久化 journal，失败补偿，启动时确认新镜像或恢复旧包。hook 接受重启请求后记录 `restart_requested`，`installed` 由新进程镜像哈希与编译版本确认。
- 扫描执行实际 HTTP 指纹探测并保存结果，内网发现限全局管理员和有界私有 IPv4 范围，MCP 发现结果事务性同步 Server。身份核验通过应用明确允许的 HTTP/Generic 提供商执行，成功保存状态和身份摘要审计；身份字段改变由数据库触发器撤销验证。Provider REST 与前端表单可保存 `content`、`scopes` 等配置。
- 补齐存储 SQL 的 `user_id` 映射，并统一上传、下载、删除及会话预览的 Local 根边界。租户可配置的目录限定于运维 `CASDOG_LOCAL_STORAGE_ROOT` 下以精确 owner 的 SHA-256 命名的目录，默认运维根为服务工作目录 `./uploads`。原有目录在新边界外时需要运维迁移。MCP 和文件 S3 请求固定已检查的 DNS 地址，租户请求拒绝私网目标并禁用代理及重定向。

### 第五阶段验证

- 已通过全新专用 PostgreSQL 数据库按顺序执行迁移 001–026。026 将 Local bucket 路径与资源对象键扩为 TEXT，并保留业务长度校验，覆盖较长工作目录及 SHA-256 租户目录。
- 已通过 `cargo test --workspace --tests --no-fail-fast --jobs 2 -- --include-ignored --test-threads=1`。21 个测试程序共 **387 次执行，0 失败、0 忽略**；lib/main 各运行相同 37 项单元测试，执行总数包含这部分重复。
- 已通过 **81 个真实 PostgreSQL 场景**，包含原有 62 个和本轮 19 个，原先 4 个数据库端到端场景再次通过。新增分组为 WebAuthn 5、设备/MCP/文件与会话记录 9、系统运维 5。另有目录大小写隔离与 HTTP 权限测试。
- 已验证跨实例挑战与并发单次消费、过期/撤销/跨账户拒绝、密码与 Passkey 的额外 MFA；设备审批及兑换复核；真实 multipart 上传→原文预览、普通文件上传→下载→删除；任意 Local 根拒绝、Org/org 命名空间隔离、租户私网 MCP 拒绝；MCP HTTP/SSE 分页及权限保留；升级摘要、并发、持久化阶段故障、补偿、旧镜像恢复和真实子进程新镜像确认；IDV 提供商与主体绑定和身份改变撤销。
- 已通过前端 6 项原生单元测试、WASM 检查、Trunk release 构建及 API 夹具浏览器回归。Provider 前端新增配置字段的真实表单输入与序列化也已覆盖。
- 已通过 **10 项真实后端浏览器检查**，执行编译后的 Glory/Sapid WASM、实际服务器及专用 PostgreSQL，未拦截 API。覆盖注册/密码登录、资料持久化、原生 Passkey 注册取消与重试、密码学注册/登录验证、Passkey 登录强制额外 MFA、凭据删除、设备浏览器批准与真实 grant/完成/取消、TOTP 错误与成功路径、本机 HTTP 邮件找回密码。使用虚拟认证器及本机邮件提供商，截图已检查。
- 本轮所有构建使用调用者环境和项目正常配置，Cargo metadata 确认 backend target 为 `D:/Works/taidge/casdog/target`，frontend target 为 `D:/Works/taidge/casdog/web/target`。专用 PostgreSQL 数据保存在前者的 `phase5/postgres`，未使用 Docker。Windows 链接复用现有 PostgreSQL 18 OpenSSL 头文件和库。
- 后端最终日志为 `target/phase5/backend-tests-final.log`，浏览器日志与结果为 `target/phase5/browser-e2e-final.log`、`target/phase5/browser-e2e/results.json`。前端日志为 `web/target/phase5-native-tests.log`、`phase5-wasm-check.log`、`phase5-trunk-build.log`、`phase5-browser-fixtures.log`。逐接口范围和逐测试程序结果见 `phase5-gap-assessment.json`。验证完成后已停止本轮专用 PostgreSQL，数据与日志保留。
- 总回归中发现的旧 Webhook fixture 分包问题已修复，测试服务读取完整 Content-Length 请求体后再返回真实 HTTP 500→200，保留原业务断言。最终 `cargo check --offline -p casdog --tests --jobs 2`、Git 差异及新增文件空白检查通过。

### 第五阶段部署契约与剩余边界

先应用迁移 023–026。配置环境键采用双下划线，例如 `CASDOG__SERVER__PUBLIC_URL`、`CASDOG__DATABASE__URL`。WebAuthn 使用 HTTPS 域名，开发可使用同源 `http://localhost:<port>`。真实浏览器回归由 Playwright 驱动已安装 Edge，并通过 CDP 虚拟认证器生成真实凭据和断言，再由服务端密码学验证。[Playwright CDPSession](https://playwright.dev/docs/api/class-cdpsession)、[CDP WebAuthn](https://chromedevtools.github.io/devtools-protocol/tot/WebAuthn/)

升级 manifest 为 `{version,url,sha256,size,target}`，`target` 如 `windows-x86_64`。运维通过 `CASDOG_UPGRADE_MANIFEST_URL`、`CASDOG_UPGRADE_MANIFEST_SHA256`、`CASDOG_UPGRADE_INSTALL_PATH`、`CASDOG_UPGRADE_RESTART_PROGRAM` 和可选 JSON 数组 `CASDOG_UPGRADE_RESTART_ARGS` 配置部署；多主机可设置 `CASDOG_UPGRADE_INSTANCE_ID` 区分机器。旧 journal 的安装路径变更需要运维恢复对应配置后处理。回归仅操作专用测试文件及本机子进程。

身份核验 HTTP 适配器向提供商 POST `{idCardType,idCard,realName}`，可使用提供商 secret 作 Bearer 凭据，要求成功响应 `verified=true`；提供商必须在用户注册应用允许的名单中。各云厂商专属签名协议仍需适配。会话原文上传与预览当前支持 Local，S3 预览及真实云存储验收保留。MCP 同步支持 Streamable HTTP；stdio 和旧版 HTTP+SSE 传输仍待实现。指纹扫描会明确列出未评估的复杂 CVE 版本规则。真实硬件、其他浏览器、真实 GitHub/Google、云邮件短信、生产升级与集群切换仍需部署验收；前述协议、提供商、商业流程和专用页面差距继续保留。当前 299/299 只表示本次静态比较范围的路由声明覆盖。

## 第六阶段：认证重放、S3 与异步支付（2026-11-12）

- 认证：迁移 027 保存按账号和 authenticator secret 摘要区分的已消费时间步，使用数据库时间和原子条件更新防止 TOTP 跨 setup、legacy、密码和社交挑战重放，支持调用方事务回滚。FaceID 在账号锁内消费 nonce，复核组织、账号、应用权限和 enrollment 摘要，再进入已有 MFA 流程；失败匹配也消费该次 nonce。保留 FaceID 旧响应契约及管理员 impersonation 语义。
- 存储：S3 从 Basic 认证改为 AWS SigV4，覆盖 PUT/GET/DELETE、UTF-8 对象键编码与签名 Range。正常 `upload-resource`、resource 和 transcript API 已支持 S3，继续使用租户检查及 DNS 固定。预览最多保存 2 MiB，覆盖服务器忽略 Range、chunked 未知长度及异常响应；未知总长时 `fileSize` 返回 null，保留 `loadedSize`、`truncated`。修复 multipart 默认 64 KiB 解析限制，保留单文件 32 MiB 上限；上传失败不会替换原有资源版本。
- 支付：订单行锁串行创建 checkout，先持久保存付款和库存预留，再调用远端；同一订单复用同一付款。验签通知和管理员手工通知共用履约事务，库存、优惠券和账单只处理一次，终态不可逆。数据库约束阻止 REST/通用兼容 CRUD 修改 checkout 金额、归属和生命周期，冲突返回 409。买家可操作自己的付款/取消入口，同租户其他用户及跨租户请求仍拒绝。
- 回调：三个通知入口允许实际网关无 JWT 回调，但要求提供商验签、付款引用、金额和币种匹配；手工修改状态必须是对应租户管理员。Stripe、PayPal 缺少验签配置时拒绝结算。Stripe 的事件 ID 不再被误用为付款 ID；PayPal approval 仅记待处理，只有 capture 已付款事件才可能结算。
- 取消：尚未确认远端 void 的待支付订单返回 409，保留库存等待已验签的成功/过期结果，避免本地取消后用户仍能付款却丢失履约。远端 void/refund、PayPal capture 发起与超时/crash 后自动恢复 checkout 仍是缺口。
- Marketplace：新增提供商 client ID/secret 和可选应用关联输入；切换预览清除旧凭据。应用与提供商安装、关联及卸载已通过实际后端浏览器流程；目录由本机 HTTP 提供，服务端仍校验 bundle 摘要。390px 页面布局与凭据清除另有浏览器夹具检查。

### 第六阶段验证

- 全新专用 PostgreSQL 已顺序执行 001–028。迁移 028 在单条 DO 语句内锁定订单、付款和商品，验证并原子回填历史待支付库存；有限库存按聚合需求扣减，无限库存、sold 和终态历史保持。缺货、无效数量、缺商品、缺失/删除/跨租户付款、分以下金额、金额或币种不匹配均整份回滚，真实隔离 schema 回归检查 DDL、库存和订单无漂移。
- `cargo test --workspace --tests --no-fail-fast --jobs 2 -- --include-ignored --test-threads=1` 已通过：**24 个测试程序，409 次执行，0 失败、0 忽略**。lib/main 各运行相同 38 项单元测试；执行数不是独立业务场景数。
- **97 个真实 PostgreSQL 测试场景通过**，比第五阶段增加 16 个：认证 7、S3 正常 API 2、商业流程与迁移 7。迁移失败测试函数内还包含 9 类异常数据子场景。原先 4 个数据库端到端场景仍全部通过。S3 另外 3 个非数据库真实 HTTP 测试与 AWS 已发布签名向量单元测试通过。
- 前端 6 个原生测试、WASM 编译、Trunk release、API 夹具浏览器回归通过。**11 项真实后端浏览器检查通过**，使用全新专用数据库及编译后的 Glory/Sapid WASM，未拦截 API；新增 Marketplace 应用/提供商安装、持久关联与卸载，保留 WebAuthn、设备授权、MFA、注册和找回密码。TOTP 设置后使用不同恢复码登录，符合新增重放限制。桌面与 Marketplace 移动截图已检查。
- 本机后端 `cargo check --offline -p casdog --tests --jobs 2`、Rust 格式检查及 Git/新增文件空白检查通过；未运行远端 CI 或严格 Clippy。构建遵循正常配置，backend target 为 `D:/Works/taidge/casdog/target`，frontend target 为 `D:/Works/taidge/casdog/web/target`，数据库仍使用项目内 PostgreSQL 集群，未使用 Docker。
- 完整后端日志：`target/phase6/backend-tests-final.log`；浏览器日志及结果：`target/phase6/browser-e2e-final.log`、`target/phase6/browser-e2e/results.json`；前端日志：`web/target/phase6-native-tests.log`、`phase6-wasm-check.log`、`phase6-trunk-build.log`、`phase6-browser-fixtures.log`。逐程序统计、部署契约与缺口见 [phase6-gap-assessment.json](phase6-gap-assessment.json)。

### 第六阶段部署与剩余工作

先停止旧版本写入，再应用迁移 027、028 并启动新版本；旧代码没有 checkout 事务标记，不能在迁移后继续处理付款写入。028 会锁相关表；历史待付款的库存或关联数据有问题时明确失败，需先对账再重试，不会静默丢弃待支付订单。TOTP 设置时使用的验证码不能在同一已接受时间步内再次用于登录，可使用后续时间步或独立恢复码。真实支付通知需要配置 Stripe webhook secret 或 PayPal verification webhook ID。

整体功能尚未达到 Casdoor 等价：LDAP/验证码首因子、真实 Kerberos、SAML 互操作、Key API 凭证与应用虚拟身份、Agent 代理执行、完整 OpenClaw/OTLP、计划购买/充值/自动续费/购物车、远端退款和支付恢复、专用导入语义、运行时设置、更多云提供商及专用前端仍需开发。FaceID embedding 比对不代表可信采集或活体检测；S3 本轮仅验证静态密钥签名，不含 STS、预签名 URL、Azure/GCS 或真实云验收。Marketplace theme、缓存和备用源仍缺。静态路由复核仍为 299/299，不能换算为整体完成率。


## 第七阶段：首因子登录、API 凭证与购买权益（2026-11-12）

- 新增邮件/短信验证码首因子与真实 LDAP service bind、搜索和 user bind，复用既有额外 MFA 及 OAuth 完成流程。验证码挑战保存摘要、绑定浏览器 cookie 和登录上下文，限制尝试与重发；全局密码/验证码开关优先于 signin_methods，验证码首因子不能再次充当同渠道第二因子。
- Key 支持实际 Basic/query 凭证认证与即时状态复核；用户与应用使用内部类型标记区分。静态应用凭证的组织管理权限要求服务端来源记录或真实管理员显式审核，动态注册应用不可升级为可信静态来源；历史应用默认为未审核。新增 API keys 管理及审核页面。
- 计划购买按权威价格生成不可变权益快照，付款后按日历月份/年份延长订阅；有效付费角色即时参与应用、角色及 Casbin 授权，不写永久 user_roles 或临时 Casbin 分组。授权决策重新读取数据库策略，跨实例撤销立即生效。充值按原始用户 UUID 一次入账，保留归档商品与付款历史，覆盖单连接池事务。
- Stripe 区分零小数币种及 ISK/UGX 特殊计量，使用真实 HTTP checkout 与签名回调回归；内部账本仍为两位小数，三位小数币种明确拒绝。自动续费调度、远端 void/refund、PayPal capture 发起及未知支付结果自动恢复仍保留为缺口。
- 修复审计表 actor 列映射、长应用主体与时间类型兼容；HTTP 请求日志只记录路径，避免 query 凭证泄漏。前端新增验证码/LDAP 登录，修正商品、计划与定价表单的实际字段和序列化契约。

部署前应用迁移 029–032（此前版本也需先完成 027–028 的停写与对账要求）。历史应用凭证在显式审核前不会自动获得组织管理员权限。测试使用本机 LDAP、邮件、Stripe/S3 协议服务；生产目录、支付及云提供商仍需真实部署验收。整体 Casdoor 等价仍未完成，299/299 静态路由覆盖不代表业务完成率。


### 第七阶段验证

- 全量后端回归执行 27 个测试程序：438 通过、1 失败、0 忽略；套件包含 121 个显式启用的 PostgreSQL 测试函数。该失败暴露应用消息身份丢失提供商白名单；已修复并将旧夹具补齐真实组织及静态应用信任，授权 7 项与 Key 7 项定向复跑全部通过。最后这处局部修复后没有重复全量命令，保留原始失败日志而不替换记录。
- 前端 6 项原生测试、WASM 检查、Trunk release 及浏览器夹具通过。15 项真实后端浏览器检查通过，使用新数据库、迁移 001–032 和实际 Glory/Sapid WASM，没有拦截 API。新增验证码、真实 LDAP、Key 管理与即时撤销、静态应用审核；保留 WebAuthn、设备、MFA、注册和找回密码。此浏览器执行早于最终消息处理局部修复，该修复由授权和 Key 定向回归覆盖。
- Rust 格式检查和 Git 空白检查通过，未运行远端 CI 或严格 Clippy。原始日志与执行边界见 [phase7-gap-assessment.json](phase7-gap-assessment.json)。浏览器服务启动另报告既有 syncer 查询缺少 user 列，调度器 schema 修复保留为待办。


## 第八阶段：同步调度、支付恢复、用户导入与商店（2026-11-12）

- Syncer：迁移 033 修正 user/database/table 实际列名与 FromRow 映射，REST 和兼容 CRUD 共用配置验证、组织检查、密码掩码及 masked 更新保留。运行状态、租约、下次时间与失败退避持久保存；独立连接池争抢同一任务只执行一次，过期租约可恢复。单次本地写入在有界事务中提交，失败整批回滚；稳定源键保留账户 ID，未映射密码不再被随机替换，相同明文重复同步不反复撤销会话。
- 目录边界：验证真实独立 PostgreSQL 源库及 LDAP bind/search 单向新增更新。isReadOnly=false 的结果明确提示 import only，未实现外部反向写回；源删除自动禁用、affiliation 外表与 values 转换继续列为缺口，values 非空明确拒绝。
- 支付：迁移 034 在远端请求前保存原始 checkout 请求、凭据摘要、重试截止及租约，恢复复用同一个 payment 和幂等键。新增 reconcile-order 与 orders/{id}/reconcile；Stripe 查询权威 session 状态，PayPal 已批准订单发起持久幂等 capture，只有精确金额/币种且完成的 capture 才入账。Stripe 未付款取消先确认远端 session expire；无法确认时保留库存，避免假取消。
- 买家身份：迁移 035 为所有普通、计划和充值订单固定 buyer_id，新订单忽略客户端伪造买家字段；改名或名字复用不能改变付款、履约、取消及查询归属。历史回填只采用权益、已付款账本或明确 payment UUID 证据，无法证明的历史姓名保持未解析，不按当前同名用户猜测。用户兼容列表以 UUID 隔离，管理员仍可用当前姓名、UUID 或 owner/name 查询。
- 用户导入：upload-users 保留真实 multipart XLSX 首 sheet 契约，另支持明确的 JSON/CSV/TSV；限制压缩展开、行列、XML 结构与实体，拒绝公式、外部引用和损坏文件。真实当前管理员、组织与 LDAP 绑定均复核，预验证后事务整批插入。上游 password+passwordType/passwordSalt 保存为已声明的摘要，plain 转安全哈希；masked 备份和危险 KDF 参数拒绝。旧摘要在完成真实密码认证后可 CAS 升级，master password 不替换用户凭据；MFA enrollment 迁移仍需单独实现，相关导入明确拒绝。
- 前端：新增普通用户商店，展示本租户安全目录和自身钱包/购买/订阅，支持计划周期、优惠码、预设或自定义充值、继续付款、对账及取消。钱包币种沿用余额币种→旧 currency→USD 的真实规则；目录不返回提供商秘密。同步器配置表单修正 user 字段并提供 SSL 与映射输入。手机布局已检查。

部署前停止旧版本写入并顺序执行 033–035，再运行新版本。035 会锁订单、用户、付款、账本与权益表；先备份并检查历史归属，对 buyer_id 为 NULL 的旧单保留管理员人工审核，不把该订单自动绑定给当前同名账号。没有订单归属证明且只保存旧姓名的独立付款不会出现在普通用户列表中，管理员仍可核查原始记录。支付请求超过保守幂等重试期限、提供商凭据变更、退款与权益冲回、真实生产网关/目录/云服务验收继续保留。


### 第八阶段验证

- 全新最终后端库和浏览器库均顺序执行迁移 001–035；同步源使用另一独立 PostgreSQL 数据库。本轮不使用 Docker，不重定向 Cargo/TEMP 或任何全局缓存。
- 最终完整命令 `cargo test --workspace --tests --no-fail-fast --jobs 2 -- --include-ignored --test-threads=1` 已通过：**30 个测试程序，462 次执行，0 失败、0 忽略**。lib/main 各运行相同的 38 项单元测试，次数不等于独立业务场景数。
- **140 个显式启用的 PostgreSQL 测试函数全部通过**，比第七阶段增加 19：商业恢复及买家迁移 7、导入 5、商店/兼容列表 3、同步器 4。逐个将源码 ignore 函数名与最终成功日志核对，无缺失；保留原先 4 个数据库端到端场景。
- 前端 **7 项原生测试**、WASM 检查、Trunk release 和 API 夹具浏览器回归通过。新增商店购买、计划价格周期、充值限制、付款刷新及同步器表单序列化；**17 项真实后端浏览器检查通过**，使用新数据库和实际编译 WASM，未拦截 API。浏览器充值为开发支付提供商加已授权管理员履约；Stripe/PayPal 由真实本机 HTTP 协议夹具验证，不冒充生产资金验收。
- 最终后端日志 `target/phase8/backend-tests-final.log`；浏览器日志/结果 `target/phase8/browser-e2e-final.log`、`target/phase8/browser-e2e/results.json`；前端日志 `web/target/phase8-*`。格式与 Git 空白检查通过；未运行远端 CI 或严格 Clippy。逐测试程序统计及剩余范围见 [phase8-gap-assessment.json](phase8-gap-assessment.json)。最终浏览器启动不再出现原有 Syncer 缺列错误。

最终 `cargo check --offline -p casdog --tests --jobs 2` 通过，日志为 `target/phase8/final-check.log`。

第八阶段结束时，退款及权益冲回、自动续费和后台对账、Syncer 双向与删除语义、OTLP、Kerberos/SAML 互操作及更多专用前端仍有缺口；第九阶段的实际进展与边界见下节。上游 Agent 只有管理 CRUD，不存在此前报告假设的代理执行协议。

## 第九阶段：订阅续费、双向同步、OTLP 与审计保留（2026-11-12）

- 订阅：迁移 036 将受益人的明确续费授权与已付权益、商品、提供商配置、周期、币种和金额上限绑定。客户端显示的报价由服务器在授权事务内重验，不能利用并发涨价扩大授权；管理员可以停用他人的续费，不能替他人授权支出。到期任务按订阅和周期唯一，持久租约及单一订单支持重试，余额不足后仍复用原单；实际余额扣款事务重验授权、组织、用户和价格，组织删除或禁止登录时不扣款。精确延长目标订阅，不误改同一用户的其他订阅。
- 支付后台：独立任务恢复已接受的远端付款，继续使用原幂等键、提供商凭据摘要与租约；错误金额或币种不能触发入账。组织被禁用后，已接受的外部真实付款仍会记账，不能简单丢弃资金事实。余额续费可以自动完成；Stripe/PayPal 尚无离线扣款授权，后台只生成需要用户主动支付的订单，不暗中占库存或创建远端付款。
- Syncer：迁移 037 保存本地/源三方基线、配置摘要、冲突与持久出站操作。PostgreSQL 源写回在唯一源键行锁下比较预期值；外部提交但本地确认失败时，重试识别已提交结果，不重复写回。源完整快照消失只禁用本同步器管理的账户，失败或不完整读取不触发删除；恢复时保护后续人工改动。新增显式可逆 Values 与 affiliation 外表映射，凭据仅比较带域分隔的 HMAC 指纹；密码算法无法在源中正确表达时进入冲突，不能把升级后的 Argon2 写成 bcrypt。未变化的凭据列不出现在出站 UPDATE 中。
- 同步边界：双向写回要求 PostgreSQL 单列唯一键和可逆映射；LDAP/Keycloak 写回明确拒绝，空源字段暂保留本地值。MySQL、SQL Server、Active Directory、SCIM 及更多上游来源仍未实现。只读复核还发现已开放 Keycloak 的凭据拼装不符合真实 Base64/算法元数据契约，当前回归不覆盖 Keycloak，下一阶段需优先修复，不能把 PostgreSQL/LDAP 通过扩大成全目录覆盖。
- OTLP：迁移 038 为租户管理员批准的 OpenClaw Log/Agent 提供商及实际应用建立接收器。支持 `/api/v1/{traces,metrics,logs}` 和 `/v1/*` 的 HTTP protobuf 与 gzip，三类信号均持久化原始数据和可由正常 Entry API 读取的记录；解析前限制结构及消息数，原始/解压后各 4 MiB、Entry JSON 2 MiB。随机 Bearer 密钥只显示一次，摘要保存，轮换或撤销立即生效；直接来源 IP 必须显式批准，不信任转发头，错误 Bearer 不回退 IP。共享数据库配额、事务写入和 protobuf 错误响应已加入验证。尚无 gRPC 或 OTLP JSON。
- 审计与前端：迁移 039 增加组织级保留天数，0 继承全局，全局 0 永久保存。后台批量清理使用共享锁、当前策略与事务，拒绝损坏策略。全局站点设置、接收器批准/轮换/撤销及用户续费授权已加入 Glory/Sapid 页面。SQLx 和 Diesel 连接池设置目前仅保存，运行时切换尚未实现，API 与页面明确显示未应用；不把最大空闲连接数错误映射为最小连接数。接收器撤销后的列表与编辑状态更新也加入浏览器断言。
- 导入补强：普通 Casdoor 用户 API 会隐藏 MFA 密钥但保留 preferredMfaType。导入现拒绝该非空标记（含未知类型或空白）、Radius/Push 等启用标记和非法类型，整批不写入，避免管理员补回密码后产生无 MFA 账户。专用 enrollment 恢复尚未实现；本轮仅防止静默降级。

### 第九阶段验证

- 最终独立后端库及浏览器库均执行全新迁移 001–039，同步源使用另一 PostgreSQL 数据库。无 Docker 构建，无 Cargo/TEMP 或全局缓存重定向。
- 最终命令 `cargo test --offline --locked --workspace --tests --no-fail-fast --jobs 1 -- --include-ignored --test-threads=1` 通过：**33 个测试程序，492 次执行，0 失败、0 忽略**。lib/main 各运行相同 38 项单元测试，执行次数不是独立业务场景数。
- **165 个显式 PostgreSQL 测试函数全部通过**，逐个将源码 ignore 函数名与相应测试程序的成功日志匹配，比第八阶段增加 25 项：续费 8、双向同步 5、OTLP/接收器/Agent 8、审计保留 3、导入 MFA 标记 1。保留原有四个数据库端到端场景。审计夹具原先缺 records 必填字段，补齐后 4 项测试全部通过；导入最终回归包含空白 preferredMfaType 和整批零写入断言。
- 前端 **7 项原生测试**、WASM 检查、Trunk release 及增强的浏览器夹具通过；最终二进制配合实际 Glory/Sapid WASM 的 **20 项真实后端浏览器检查通过**，未拦截 API。新增站点策略保存、真实 OTLP 入库及密钥轮换/撤销、明确续费报价授权；撤销后的 Disabled 列表与编辑状态已断言，相关截图已检查。
- 首次全量已通过；最后重编遇到 rustc 内存分配失败，保留 `target/phase9/backend-build-crash.log`，以单任务重新构建并执行上述最终完整命令成功，不把编译器崩溃记作业务测试通过。最终日志为 `target/phase9/backend-tests-final.log`，逐程序及逐 PostgreSQL 函数证据为 `target/phase9/test-summary.json`；浏览器日志/结果为 `target/phase9/browser-e2e-final.log`、`target/phase9/browser-e2e/results.json`。未运行远端 CI 或严格 Clippy，真实支付、云目录和集群部署验收仍保留。详见 [phase9-gap-assessment.json](phase9-gap-assessment.json)。

## 第十阶段：Keycloak 凭据、连接池运行时设置与应用主题（2026-11-12）

- Keycloak：不再把 Base64 密码与盐拼成内部 hex/文本盐格式。新增有界 PBKDF2-SHA256/SHA512 表示与恒时校验，保留真实二进制盐、派生长度和轮数。同一源库 repeatable-read 事务读取用户、credential、群组和联邦身份，限定配置 schema；损坏 JSON、未知算法、缺字段、KDF 超限或群组读取失败整批回滚。没有密码的账户仅在明确联邦绑定时允许导入资料，新账户使用不可知随机密码；正常登录升级 Argon 后，未变化的源凭据不覆盖升级结果。原生 Keycloak Argon 仍明确拒绝，不冒充已支持。
- 连接池：运行时设置现在真实影响主 SQLx 和 Diesel 池。每个请求捕获同一世代的两套池和 Casbin，事务持续使用原连接；新请求与后台任务获取新世代，旧连接正常排空。启动加载持久设置，多实例每 5 秒读取共享设置；候选池验证和最终设置行锁复核后发布，失败保留旧代并报告未应用。最大空闲连接数是上限；生命周期在获取连接时也强制检查，不能继续借出超龄 idle 连接。
- 零设置与容量：0 最大连接数读取 PostgreSQL `max_connections`，0 最大空闲连接保留 2 个并按最大连接数收敛，0 寿命不限年龄。初版把 0 映射 `u32::MAX` 导致 SQLx 预分配约 206 GB 队列，已由真实默认启动用例修复并验收。上限分别约束每个世代的 SQLx、Diesel，不能当作两套驱动和全部旧代合计的进程硬上限；服务器角色、预留连接和全局限制仍适用。外部同步源池不随主池设置改变。
- 主题：迁移 040 补应用缺失字段并以资源 UUID 限制每应用一个已安装主题。安装在事务中备份完整八字段，含 SQL NULL themeData，卸载精确恢复；当前管理员、租户、并发安装和同名重装绑定均检查。公开 `/api/auth/branding` 只返回白名单资料，重新检查应用、组织及主题安全策略。全局管理员批准的额外静态资产 URL 与主题指纹绑定，不能在后来修改字段时借用旧批准。
- Glory/Sapid：Marketplace 增加目标应用选择，登录、注册、授权实际消费 themeData、桌面/移动 CSS、背景及 formOffset 的上游枚举布局。CSS 限于认证容器，字体导入仅限已批准分发源；侧栏和页脚为无脚本/同源/表单权限的 sandbox iframe，实际文字渲染有浏览器断言。应用切换、离页和慢请求均清理旧主题，卸载后恢复原值。主题 HTML/CSS 是明确静态安全子集，不执行主动代码、不支持全部旧 React 类名或动态 Storage domain/formCssAllowedUrls 扩展。
- 构建入口复用现有库模块，避免 lib/bin 重复编译全部服务。38 项库单测保留，二进制不再重复执行；不能用原始执行次数的变化推断覆盖下降。

### 第十阶段验证

- 全新最终后端库及浏览器库顺序执行 001–040，同步源使用另一专用 PostgreSQL 数据库。
- 最终完整命令 `cargo test --offline --locked --workspace --tests --no-fail-fast --jobs 1 -- --include-ignored --test-threads=1`：**34 个测试程序，463 次执行，0 失败、0 忽略**。172 个显式 PostgreSQL 测试函数逐个核对成功日志；比第九阶段新增 7 个 PG 函数：Keycloak 2、主题 3、运行时池 2，另增 2 个非 PG 向量/安全单测。原四个数据库端到端场景仍全部通过。
- 前端 **7 项原生测试**、WASM 检查、Trunk release 与增强夹具通过；**21 项真实后端浏览器检查通过**，未拦截 API。新增主题安装→实际桌面/移动登录/注册/授权渲染→隔离 HTML 文本→卸载完整恢复，站点设置检查实际世代变化、连接数及空闲上限。
- 真实专项发现并修复超龄连接借出和默认零配置内存分配问题；保留 `runtime-targeted.log`、`backend-tests-initial.log`、`browser-startup-allocator.log`。最终池专项 6 项全过；主题和 Keycloak 的最终结果以完整回归为准。浏览器脚本补等待异步主题预览，防测试输入被默认名称覆盖，并等待 iframe 中实际文字渲染后截图。
- 最后浏览器复跑还发现资料初始查询覆盖已输入编辑值的竞态，已让资料表单在初始数据到达后才开放编辑。此处仅改前端；后端源码保持全量回归时的版本，随后重新执行前端 7 项原生测试、WASM、Trunk、可控延迟夹具以及全新数据库上的 21 项真实浏览器检查，全部通过，保留原始 `browser-profile-load-race.log`。
- 最终日志/逐函数证据：`target/phase10/backend-tests-final.log`、`target/phase10/test-summary.json`；浏览器日志/结果：`target/phase10/browser-e2e-final.log`、`target/phase10/browser-e2e/results.json`。后端检查、格式与空白检查通过，未运行远端 CI 或严格 Clippy。完整范围见 [phase10-gap-assessment.json](phase10-gap-assessment.json)。

整体目标仍在推进。下一优先级为 MFA enrollment 专用恢复、退款与权益冲回、更多目录来源和 Keycloak Argon，以及 Kerberos/协议互操作；生产提供商、集群与可信硬件验收继续保留，不能由本地模拟服务结果替代。
