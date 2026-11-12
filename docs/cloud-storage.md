# 云存储配置与资源访问

部署前按顺序应用数据库迁移 `001`–`046`。`046_cloud_storage.sql` 将服务账号凭据、桶名、路径前缀和资源 URL 列扩为 `TEXT`；接口仍校验对象 key、凭据和配置长度。

## 提供商配置

租户管理员可通过正常 `POST /api/providers` 创建本租户提供商，随后通过 `PUT /api/providers/{id}` 修改。全局管理员也可管理其他租户。提供商必须使用 `category: "Storage"`。

| 字段 | Azure Blob | Google Cloud Storage |
| --- | --- | --- |
| `type` | `Azure Blob` | `Google Cloud Storage` |
| `client_id` | Azure 存储账户名 | 无需填写 |
| `client_secret` | 账户密钥的 Base64 字符串 | 完整 `service_account` JSON，作为 JSON 字符串存入此字段 |
| `bucket` | 已存在的容器名 | 已存在的桶名 |
| `domain` / `endpoint` | 可选的公开/CDN 展示地址 | 可选的公开/CDN 展示地址 |
| `path_prefix` | 可选的对象 key 前缀 | 可选的对象 key 前缀 |

本实现使用 Azure 原生 Shared Key REST API，以及 GCS 原生 JSON API、服务账号 RS256 JWT/OAuth。GCS JSON 应包含 `type`、`client_email`、`private_key`，可包含 `private_key_id` 和 `token_uri`；缺省令牌地址为 `https://oauth2.googleapis.com/token`。它不会从 `content` 字段读取服务账号，也不会自动发现机器上的默认 Google 凭据。

签名格式参考 [Azure service SAS 规范](https://learn.microsoft.com/en-us/rest/api/storageservices/create-service-sas)和 [GCS V4 签名规范](https://docs.cloud.google.com/storage/docs/access-control/signing-urls-manually)。本地回归检查签名及协议交互；生产云账号验收仍需使用实际部署配置。

默认 Azure API 为 `https://{account}.blob.core.windows.net`，默认 GCS API 为 `https://storage.googleapis.com`。**Azure/GCS 的 `endpoint` 和 `domain` 是公开地址，不是上传 API 地址。** `domain` 非空时优先；未带协议的 `domain` 会补 `https://`。配置公开地址表示操作者已在云端或 CDN 配好公开读取；上传不会自动公开容器、桶或对象，也不保证一个任意 CDN 能访问私有源站。

Azure 账户密钥必须有相应对象写入、读取、删除权限；GCS 服务账号也需要桶中对应对象权限。提供商响应不返回 `client_secret`。响应包含 `bucket`、`path_prefix`、`region_id`，以及经过白名单筛选的 `metadata.storageApiEndpoint`；其他任意 metadata 不回显。修改时不传 `client_secret` 可保留现有凭据，轮换时再显式提交新值。

### 公开路径与实际对象 key

正常上传会将解码后的公开地址路径、`path_prefix` 和新对象文件名合并并保存为实际对象 key。例如：

```text
domain      = https://cdn.example.test/assets%20base
bucket      = documents
path_prefix = tenant-files
上传 key    = assets base/tenant-files/{generated-uuid}.txt
公开 URL    = https://cdn.example.test/documents/assets%20base/tenant-files/{generated-uuid}.txt
```

不是 `domain/path/bucket/key` 的排列。未设置 `domain` 时，`endpoint` 的路径采用相同规则。路径穿越、反斜线和非法 key 会被拒绝。此路径规则也用于 OpenClaw transcript 上传。`path_prefix` 的这一实现范围是 Azure/GCS；现有 S3/MinIO 上传不使用此字段。

### API 地址扩展与网络边界

主权云、兼容服务或本机协议夹具可以显式设置 `metadata`，其值是一个 **JSON 字符串**：

```json
{"storageApiEndpoint":"https://storage-api.example.test"}
```

该扩展改变实际对象 API 地址，不改变公开/CDN 地址语义。生产使用 HTTPS；明文 HTTP 仅允许 loopback 模拟服务。应用会分别检查并固定实际 API 和 GCS `token_uri` 的 DNS 地址，禁止跟随重定向。普通租户不能借配置访问私有网络；本机夹具需要全局管理员权限。不要把公开 CDN 当成带凭据的 API。

`AWS S3`、`s3` 和 `MinIO` 使用原生 S3 SigV4 兼容适配器。它们的现有 `endpoint` 是 S3 API 地址，与上述 Azure/GCS 公开地址语义不同。`Local File System` / `local` 保持本地租户目录隔离。

## 使用正常 CRUD 配置

以下 PowerShell 示例使用环境变量中的管理员令牌；替换组织名，并从受保护文件读取真实凭据。不要提交凭据文件或把它们放入 `content`、URL、日志。

```powershell
$base = 'https://identity.example.test'
$body = @{
    owner = 'my-org'; name = 'cloud-storage'; display_name = 'Cloud files'
    category = 'Storage'; type = 'Google Cloud Storage'; bucket = 'my-existing-bucket'
    client_secret = Get-Content 'C:/secure/service-account.json' -Raw
    # 不设置 domain/endpoint：使用私有对象的短期签名链接。
} | ConvertTo-Json -Depth 10
$body | curl.exe -sS -X POST "$base/api/providers" `
    -H "Authorization: Bearer $env:CASDOG_ADMIN_TOKEN" `
    -H 'Content-Type: application/json' --data-binary '@-'
```

Azure 使用同样入口，将 `type` 改为 `Azure Blob`，`client_id` 设为账户名，`client_secret` 设为账户密钥，`bucket` 设为已有容器名。需要公开读取时，再配置正确的 `domain` 或 `endpoint`；仅填写展示地址不会修改云端 ACL。

## 普通用户上传、刷新与下载

`POST /api/upload-resource` 返回 `{id, name, url, size, file_type}`。`id` 是资源 UUID，普通上传者无需访问管理员资源列表就能继续操作。以下示例改用本人的普通用户令牌：

```powershell
$uploaded = (curl.exe -sS -X POST "$base/api/upload-resource" `
    -H "Authorization: Bearer $env:CASDOG_USER_TOKEN" `
    -F 'owner=my-org' -F 'provider=cloud-storage' -F 'file=@./sample.txt') | ConvertFrom-Json
$resourceId = $uploaded.id
$fresh = (curl.exe -sS "$base/api/resource-url/$resourceId" `
    -H "Authorization: Bearer $env:CASDOG_USER_TOKEN") | ConvertFrom-Json

# 始终可以经应用认证下载；此请求不要把令牌转发至云端或 CDN。
curl.exe -sS "$base/api/download-resource/$resourceId" `
    -H "Authorization: Bearer $env:CASDOG_USER_TOKEN" -o './downloaded.txt'

# 删除会先删除实际对象，成功或对象已不存在后才删除资源记录。
curl.exe -sS -X POST "$base/api/delete-resource/$resourceId" `
    -H "Authorization: Bearer $env:CASDOG_USER_TOKEN"
```

调用前检查 HTTP 状态；失败响应没有可使用的资源 ID。上传远端失败不会发布资源记录，数据库创建失败会尝试清理刚上传的对象。

刷新接口 `GET /api/resource-url/{id}` 受认证保护，并返回 `Cache-Control: no-store`：

| `access` | `url` | `expires_at` |
| --- | --- | --- |
| `signed` | Azure 只读 SAS 或 GCS V4 签名 URL | 约 15 分钟后 |
| `public` | 当前配置的公开/CDN URL | `null` |
| `proxy` | `/api/download-resource/{id}` | `null` |

未配置公开地址的 Azure/GCS 使用 `signed`；local、S3/MinIO 使用应用认证下载 `proxy`。本地上传响应也直接返回代理地址，不返回 `file://` 路径。浏览器获取代理文件时须带 Bearer 令牌 fetch 为 Blob，不能假设直接打开链接具有 cookie 登录权限。访问公开或签名云 URL 时，不要附带应用的 Bearer 令牌。签名 URL 本身是临时访问凭证，避免记录或公开分享。

## 轮换、权限和旧对象

每次刷新、下载和删除都会复核保存的资源归属与当前提供商配置。普通用户仅能访问绑定其稳定用户 ID 的资源；同租户管理员可管理租户资源，全局管理员可跨租户管理。资源只保存旧用户名而没有稳定用户 ID 时，普通用户访问会被拒绝，需管理员处理；复用同名账号不会自动获得这些文件。

资源保存的是上传时的实际 key。之后修改 `domain` 的路径或 `path_prefix` 只影响新上传，不会移动旧对象，也不会在读取旧 key 时再次追加前缀。修改桶名、账户或实际 API 地址会使旧资源按**当前**位置读取；若没有迁移对象，它们可能无法访问。保留旧提供商并新建一个提供商通常更便于保留历史对象引用。

GCS 令牌缓存按完整凭据和令牌地址隔离，提前于到期时间刷新，收到 401 后使被拒令牌失效并最多重试一次。换服务账号或密钥不会复用旧缓存。Azure 密钥轮换后，刷新会使用当前密钥。已经发出的签名链接不经应用认证，仍受云端签名验证与到期时间约束；禁用应用账号不等于立即撤销所有已发出的云签名 URL。

本机 HTTP 夹具和数据库回归用于验证协议与应用边界，不等同于 Azure/GCS 生产账号、实际 IAM、CDN 或主权云环境验收。部署后仍需使用自己的测试桶核对权限与网络配置。
