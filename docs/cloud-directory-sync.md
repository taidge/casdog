# Cloud directory Syncers

`Azure AD` and `Google Workspace` are read-only directory sources available through the normal Syncer create, edit, run and scheduler APIs. They share the existing persistent execution lease, tenant checks and user-link ledger. There is no separate import endpoint and no cloud writeback; `isReadOnly=false` is rejected.

## Configuration

| Field | Azure AD | Google Workspace |
| --- | --- | --- |
| Type | `Azure AD` | `Google Workspace` |
| Host | Tenant ID or tenant domain | Delegated administrator email |
| User | Application/client ID | Service account email; may be empty, otherwise must match the JSON |
| Password | Client secret | Complete `service_account` JSON containing `client_email` and RSA `private_key` |
| Database | Optional public options JSON | Optional public options JSON |
| Read only | Required | Required |

Do not put credentials in Host, User or Database. Password is masked as `***` on native and legacy reads; updating with `***` keeps the saved value. A new Syncer requires a real secret. The Google JSON can contain `private_key_id` and `token_uri`; the RSA key must be 2048–8192 bits. It needs Google domain-wide delegation for both of these exact scopes:

```
https://www.googleapis.com/auth/admin.directory.user.readonly
https://www.googleapis.com/auth/admin.directory.group.readonly
```

Azure uses the client-credentials grant, with scope `https://graph.microsoft.com/.default`. Its default token endpoint is `https://login.microsoftonline.com/<Host>/oauth2/v2.0/token` and Graph API base is `https://graph.microsoft.com/v1.0`. Grant the application the Graph permissions needed to read the selected user properties, including `accountEnabled`, and obtain administrator consent in the external tenant.

Google signs a fresh RS256 JWT assertion with the delegated administrator as `sub`, service-account email as `iss`, token URL as `aud`, and a one-hour expiry. The default token endpoint is `https://oauth2.googleapis.com/token`; the API base is `https://admin.googleapis.com/admin/directory/v1`.

Database is either empty or an object encoded as a JSON string. Its only accepted keys are:

| Option | Meaning |
| --- | --- |
| `api_base` | Absolute directory API base. The connector appends `users`, `groups` and `groups/<immutable ID>/members` as appropriate. |
| `token_endpoint` | Azure token endpoint override. Google uses secret JSON `token_uri` instead. |
| `customer` | Google customer identifier, default `my_customer`; unsupported for Azure. |

SQL database type, table, affiliation table and LDAP SSL options are explicitly unsupported. Unknown options are rejected. Endpoints require HTTPS, except loopback HTTP used with explicit private-network approval. URLs cannot contain userinfo, a query or a fragment.

## Network review

Private networks are denied by default for both sources. A real global administrator can approve the current saved configuration using the Syncer UI or `POST /api/syncers/{id}/network-approval` with `{"allow_private":true}`. `GET` returns the status and `DELETE` revokes it. A tenant named `admin` or `built-in`, application credentials and request-supplied flags do not confer this authority.

Approval is bound by a keyed configuration digest that includes the secret. Changing the source configuration makes it stale; approve the reviewed configuration again. Each snapshot pins its initial approval generation (including no approval), and every token request, page and final apply boundary must still see that same generation and current record. Revoking or reapproving a configuration does not wait for the running Syncer's row lock. Even revoking and immediately reapproving the same unchanged configuration invalidates the old run; it rolls back instead of importing its buffered snapshot. Start a new run under the new approval. The existing pinned-DNS, no-proxy and no-redirect HTTP client is used for every request. Errors do not include remote bodies, access tokens, assertions or client secrets.

## Users and stable identity

Remote immutable user IDs are stored as `external_id` and in the Syncer user-link ledger. Local UUIDs remain local UUIDs. Renaming a UPN, email or display name updates the linked account rather than creating a new one. Usernames pass through the existing local username sanitizer and collision handling. Azure mail falls back to UPN; an absent display name falls back to first and last name.

Azure imports the upstream profile fields: display/first/last name, email, mobile phone, title, office location and language. Its explicit boolean `accountEnabled` is inverted into local forbidden status; a missing or malformed value aborts the snapshot. Google imports name, email, avatar and creation time. A supplied `suspended` boolean controls forbidden status; an absent value preserves an existing local status. Google `isAdmin` is kept only as `properties.cloud_directory.remote_is_admin` and never grants local administrative authority.

Existing local password hashes, password metadata, MFA factors, recovery codes, provider bindings and unrelated properties remain intact. Imported users without a local account receive an unusable random local password according to the existing import policy. The external account's cloud password is never obtained. Missing source users are forbidden only through this Syncer's existing link ledger, after a complete successful snapshot. A failed page does not imply deletion.

Default Table Columns cover the supported profile fields. Custom mappings can select a subset of those fixed source/target pairs, but must retain immutable `id` → `Id` as the sole key and `userName` → `Name`. Password, admin, tenant, provider-binding fields and value conversions are rejected. Moving a Syncer to another tenant/source after it has linked accounts requires a new Syncer; existing bindings are not silently reused.

## Google groups

The connector obtains all groups and their complete direct membership snapshots before changing users or groups locally. Each remote group ID gets its own local UUID and an unguessable name prefixed `cloud-<syncer prefix>-`. Local same-name or same-email groups are never adopted. Group display name and contact email follow remote changes; local UUID and namespaced name remain stable.

Concrete `USER` members are resolved by immutable user ID within this complete users snapshot. Nested `GROUP`, `CUSTOMER`, `EXTERNAL`, and external `USER` entries are not recursively expanded or assigned to another local identity. Unknown member kinds, invalid IDs and malformed pages fail the batch. Azure groups remain the upstream TODO and are not synthesized.

Managed edges are mirrored in `user_groups` and qualified `organization/groupName` values in `users.groups`. A persistent ledger records precisely which rows and JSON values the Syncer owns. Removing source memberships or groups retracts only its owned edges. Preexisting manual memberships, explicit manual additions, replaced membership rows and other Syncers' authority are preserved. Manual add and reconciliation use the same user → ledger lock order, so an administrator's committed manual addition cannot be removed using an earlier flag snapshot.

Deleting a Syncer retracts its managed membership authority before deleting its ledger. Group records remain, preserving possible local policy references and manual members. A successful run of a source without cloud groups also detaches any previous managed group authority; a failed run leaves it unchanged.

## Completeness and operational limits

Azure follows opaque Graph `@odata.nextLink` values only on the original users endpoint and origin. Google follows opaque `nextPageToken` values for users, groups and each group's members. Repeating a token is not by itself an error; duplicate immutable entries and finite page/request limits prevent unbounded loops. Non-200 responses, partial responses, invalid JSON, invalid credentials, duplicate identities and group-query failures abort the entire import transaction.

Graph requests up to 999 users per page. Google uses 500 users and 200 groups/members per page, according to the [Directory users API](https://developers.google.com/workspace/admin/directory/reference/rest/v1/users/list), [groups API](https://developers.google.com/workspace/admin/directory/reference/rest/v1/groups/list) and [members API](https://developers.google.com/workspace/admin/directory/reference/rest/v1/members/list). Graph selection follows the [Microsoft Graph users API](https://learn.microsoft.com/en-us/graph/api/user-list?view=graph-rest-1.0).

Connector safety bounds are 100,000 users, 10,000 groups, 200,000 memberships, 200 pages per list, 4,096 HTTP requests, 8 MiB per response and 64 MiB total response data. Options are limited to 16 KiB and secret JSON to 64 KiB. These are rejection boundaries, not verified enterprise-scale throughput claims. The existing Executor still imposes a 60-second whole-run deadline and a 90-second lease. Slow or very large directories can exceed that deadline and will roll back; durable staged snapshots and long-running directory imports remain future work. This change does not widen those existing timeout or lease guarantees.

The cloud-directory regression target uses real local HTTP protocol servers and PostgreSQL: Azure form credentials, cryptographically verified Google JWT delegation, complete user/group/member pagination, immutable-ID rename, suspension, credential preservation, tenant isolation, manual-membership retention, Syncer deletion, private-grant revocation during a run and a one-connection pool. These fixtures do not claim authentication against live customer Microsoft or Google tenants.
