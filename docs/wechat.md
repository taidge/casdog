# 微信网页登录

部署数据库迁移到当前版本后，在正常 Provider 页面选择 `OAuth` / `WeChat`。`client_id`、`client_secret` 填网站应用凭据；`client_id2`、`client_secret2` 填公众号凭据。二级 secret 与主 secret 一样脱敏，普通编辑保留掩码；轮换后应重新发起登录。无需新增微信数据库列。

服务端在发起授权时读取 User-Agent：包含区分大小写的 `MicroMessenger` 使用公众号凭据和 `https://open.weixin.qq.com/connect/oauth2/authorize`，scope 为 `snsapi_userinfo`；其他浏览器使用网站应用凭据、`/connect/qrconnect` 和默认 `snsapi_login`。网站应用保留显式 scope 配置；公众号流程使用其固定用户信息授权 scope。微信内缺少二级凭据时拒绝发起，不偷偷回退扫码。

选择结果与配置摘要保存在 PostgreSQL 的一次性浏览器绑定状态中。回调从该状态读取变体，不按回调 User-Agent 重新选择凭据。应用、组织、Provider、有效期、浏览器绑定、配置与网络审批的原有检查继续生效；账户绑定和 MFA 也走同一证明链。仅知道 state、变更 UA 或重复回调不能获得会话。改凭据后需重启待处理登录，MFA 阶段也会重新校验配置。

生产请求固定发送到微信官方 `https://api.weixin.qq.com/sns/oauth2/access_token` 和 `/sns/userinfo`，使用现有 DNS 检查、超时和禁止重定向的客户端。Provider 的自定义 endpoint 字段不能替换微信接口。HTTP 错误与微信错误不会把远端响应或带 secret 的 URL 返回给调用者；响应体上限 64 KiB。

token 与 userinfo 的 `openid` 必须完全一致；token 返回 `unionid` 时，userinfo 也必须返回相同值。有效 UnionID 沿用跨网站/公众号的同一身份；没有 UnionID 时，旧桌面 OpenID 身份保持兼容，新增公众号身份使用 `openid:<appid>:<openid>`，避免两套应用下的 OpenID 碰撞。身份仍受当前 Provider 配置及租户限制，不按邮箱或昵称合并。历史无 UnionID 账号后来获得 UnionID 时不会自动迁移绑定，需在已认证账户中明确管理绑定；更换公众号 AppID 同样会改变无 UnionID 的身份。

本机测试通过类型化的服务端 `WeChatTestTransport` 注入模拟微信 HTTP 服务，只接受字面 loopback origin，不能由 Provider、浏览器请求或状态 JSON 创建。它用于协议与共享数据库回归，不代表真实微信云端验收。仍需在实际微信开放平台/公众号中配置回调域名并验证账号权限。

完整浏览器夹具位于 `examples/wechat_browser_fixture.rs`，仅开发时显式构建运行。`scripts/wechat-browser.cjs` 导出 `runWechatBrowser({browser,database,artifacts,fixtureExecutable})`，创建独立 localhost 服务、临时配置文件和浏览器上下文；通过正常 API 配置 Provider/应用，实际导航授权页并兑换 code，测试桌面、微信内 MFA 和已登录账户绑定。临时文件通过 `--config FILE` 传递，配置及凭据不写入证据文件，测试结束删除临时文件并停止服务。生产主程序既不读取此文件，也没有微信端点环境变量开关。

上游参考：`object/provider.go` 的 MicroMessenger 凭据选择、`web/src/auth/Provider.ts` 的桌面/公众号授权入口、`idp/wechat.go` 的 token 与用户信息协议。官方说明见[网站应用微信登录](https://developers.weixin.qq.com/doc/oplatform/Website_App/WeChat_Login/Wechat_Login.html)及[公众号网页授权](https://developers.weixin.qq.com/doc/offiaccount/OA_Web_Apps/Wechat_webpage_authorization.html)。本轮未实现上游另有的公众号二维码事件 ticket 流程。
