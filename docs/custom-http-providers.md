# Custom HTTP 投递

Provider 的 `method` 为空时保留已有 POST/JSON 协议。配置显式方法后进入下表所列协议；不要只保存一个未被运行时消费的 method、mapping 或 header。

| 类型 | 显式方法 | 参数与编码 |
| --- | --- | --- |
| Custom HTTP Email | GET / POST / PUT / DELETE | `fromAddress/fromName/toAddress/toAddresses/subject/content`；GET 放 query，其他方法使用 form 或 JSON |
| Custom HTTP SMS，兼容 HTTP/Generic SMS | GET / POST / PUT / DELETE | `phoneNumber`、正文参数；GET 放 query，其他方法使用 form 或 JSON |
| Custom HTTP Notification | GET / POST | `title` 指定正文参数名；可选 `recipient`；GET query 或 POST form |

邮件与短信的 `issuer_url` 在本协议中表示 Content-Type，支持 `application/json` 或 `application/x-www-form-urlencoded`（可带 UTF-8 charset）。未设置时采用 `http_headers` 中的 Content-Type，再未设置时默认 form。两处配置矛盾、其他媒体类型、非 UTF-8 编码会被拒绝。显式通知 POST 固定 form。

`user_mapping` 是输出字段重命名，不是 OAuth 点分路径。邮件允许映射六个标准字段；短信允许 `phoneNumber/content`。有效字段名包括未改动的默认字段，彼此不能冲突。单收件人使用 `toAddress`；多个收件人在一次请求中使用 `toAddresses`（JSON 数组或重复 form/query 参数）。邮件 From 地址使用 `client_id2`，为空时回退 `client_id`；显示名使用 Email 的公开 `client_secret2`，为空时可采用请求中的 sender。

短信正文参数名优先 `title`，其次 `user_mapping.content`，需明确配置。`template_code` 为空时为 `%s`，非空时必须含一个 `%s`，输入内容作为该参数格式化一次。验证码服务会传入原始 code，避免重复套模板。短信 endpoint 可在 path/query 使用 `{mobile}`、`{code}`，会进行 URL 编码。GET 包含任一占位符时不再追加自动生成的参数，保留已有 query。

通知优先使用 `endpoint`、`provider_url`、旧 `client_id` 作为投递地址；这些都为空时按上游使用 `receiver` 作为目标 URL。后一种情况下 receiver 不再兼任默认收件人；请求中的显式 recipients 仍可发送为 `recipient`。显式通知要求 `title` 为非空正文参数名，不能与 `recipient` 冲突。

## 请求头和旧协议

`http_headers` 是实际发送的 header map。通知原有的 `client_secret2` / metadata header-pairs 仍支持；先读取这些旧字段，再由通用 header map 按名称覆盖。header 名称不区分大小写。配置了非空 `client_secret` 时可自动添加 Bearer Authorization；与显式 Authorization 不同的配置会被拒绝，避免静默丢弃凭据。Host、Content-Length、Transfer-Encoding、Connection、Proxy-Authorization 等控制性 header 不允许由 Provider 覆盖。

method 为空时：邮件保持 `to/subject/body/timestamp`，短信保持 `to/from/body`，通知保持 `title/content/receiver/timestamp` 的 POST/JSON 结构。新增 header 配置会生效；body mapping、非 JSON 编码或通知正文参数名需要先选择显式 method，否则拒绝配置。旧邮件协议保持逐收件人请求；显式邮件协议支持单次批量请求。

## 网络批准与失败

私有地址的投递需要真实全局管理员通过 `POST /api/providers/{id}/network-approval`（`{"allow_private":true}`）持久批准。租户 owner 名字、调用者声称是管理员、metadata 标志都不等于批准。Provider 配置改变后原批准失效；撤销使用 DELETE。读取旧 Provider 快照进行投递也会被拒绝，需重新解析当前配置。

每个实际 HTTP 请求都会重新核对当前 Provider 配置和批准，包含多收件人投递中的后续请求；检查后释放数据库锁，不在外部网络等待期间占住数据库连接。请求会固定已检查的 DNS 地址、不使用系统代理、不跟随重定向，并限制连接与响应时间。成功响应最多读取 64 KiB，非成功响应不回显远端正文、请求 URL 或凭据。显式上游协议要求 HTTP 200；旧 JSON 协议保留接受 2xx 的行为。远端失败后不会伪称成功；已经开始的外部请求无法靠随后撤销批准来撤回。

普通入口是 Provider CRUD 与 `send-email/send-sms/send-notification`，无需新增测试专用公网接口。配置和 Bearer 凭据的清空、掩码保留及类型切换规则见 [Provider 配置指南](provider-configuration.md)。本机协议夹具的结果不代表实际短信或邮件服务商生产账户验收。
