# Casdoor 改写复核（更新至 2026-11-12）

## 基线与结论

参考仓库：`E:/Repos/casdoor`，远端 `https://github.com/casdoor/casdoor.git`。
按用户要求 fetch 后 reset 到 `origin/master` 并 clean 本地文件；参考提交：
`47da539f886d5b09d2c35cf6ae78d8b6b5f30a43`（2026-10-27）。
Casdog 开始复核时已有未提交的兼容层、CAS、MCP、Telegram 和 Stripe 修改，本轮保留并继续完善。

**结论：已有较广的 IAM 骨架和不少真实实现，但不能称为完整 Casdoor 替代品。**
路由存在、编译通过、返回 401/500 均不证明功能等价。旧 `_todos.md` 把上一轮的局部修复扩大为整体完成，本次纠正。

## 第九阶段提交状态（2026-11-12）

本次提交包含第八阶段已验证成果，以及第九阶段新增的订阅续费授权和后台对账、PostgreSQL Syncer 双向同步、OTLP/HTTP protobuf 接收、审计记录保留策略与对应 Glory/Sapid 页面。部署前需应用迁移 033–039。

第八阶段完整后端回归为 462 次执行通过，其中 140 个显式 PostgreSQL 测试函数实际执行；真实后端浏览器回归为 17 项通过。第九阶段前端 7 个原生测试、WASM 检查、Trunk release 构建与浏览器夹具已通过；新增后端专项和扩展后的真实后端浏览器端到端回归尚未执行完成，不能沿用第八阶段结果作为新功能验收结论。

新增功能仍有明确边界：外部支付自动续费尚无离线扣款授权，只创建待用户主动支付的订单；Syncer 双向写回目前限于满足键约束和可逆映射的 PostgreSQL 源，LDAP/Keycloak 写回拒绝；OTLP 仅支持 HTTP protobuf，可接收 gzip，不包含 gRPC 或 JSON；连接池设置保存后尚未应用到运行中的连接池，审计保留策略独立生效。复核上游 Agent 只有管理 CRUD，没有此前报告假设的代理执行协议，因此不再把代理执行列为上游缺口。

## 可重复的覆盖指标

运行 `python scripts/check-casdoor-parity.py --reference E:/Repos/casdoor --output docs/casdoor-route-inventory.json`。

| 指标 | 复核前 | 当前（第八阶段） | 边界 |
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
| P1 | 上游新模块 | 已补 Agent/Server/Entry/Key 管理、Marketplace 应用/提供商安装页面、OpenClaw 基础图及 Local/S3 transcript；Key API 凭证与应用虚拟身份已在第七阶段实现；第九阶段新增 OTLP/HTTP protobuf，专项验收仍待完成，theme 集成及更多专用页面仍有缺口。上游 Agent 仅有管理 CRUD，不包含代理执行协议。 |
| P1 | 商业流程 | 普通商品购买已增加异步持久库存预留、通知验签/终态/幂等、管理员手工履约及 CRUD 约束。第七阶段已补计划/充值权益，第八阶段增加持久 checkout 恢复、Stripe 对账/远端 expire、PayPal capture 和普通用户商店。自动续费调度、购物车、完整退款及权益冲回、超出幂等窗口的自动恢复仍缺；未知历史买家须人工审核。 |
| P2 | 运维功能 | 第四阶段已补首次管理员密码、设置保存、Dashboard 热图/MFA/提供商与 Webhook 历史/重放；设置运行时应用仍缺；第五阶段已补配置化系统升级与持久化设备授权流程，部署验收边界见末尾。 |
| P2 | 提供商 | 当前存储工厂仅 Local/S3，上游列出 11 类；同步器本轮验证 PostgreSQL/LDAP 单向新增更新与持久互斥调度；外部写回、源删除禁用、affiliation 外表和 values 转换仍缺。上游大量云目录、支付和消息提供商未覆盖。 |
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

整体功能仍未达到 Casdoor 等价。下一优先级为退款及权益冲回、真正自动续费和后台对账、Syncer 双向与删除语义、Agent 执行/OTLP、Kerberos/SAML 互操作及更多专用前端。新增 API、真实本机协议回归和数据库状态证明本轮闭环，不能代替生产服务及硬件验收。
