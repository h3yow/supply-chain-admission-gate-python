# Supply-Chain Admission Gate（本地制品签名与准入校验）

一个完全本地可运行的供应链准入网关：用本地 JSON 存储模拟制品/签名/策略数据，用本地随机
密钥 + HMAC-SHA256 模拟签名体系。所有准入结论 **确定、可解释、可追溯**，支持密钥轮换、
签名时效、策略版本回退、并发幂等提交与崩溃恢复。同一制品可登记 **多个不同签名方** 的
独立签名，策略可要求"至少 N 个不同签名方的签名同时有效"（多人签名门槛）才放行。

- 框架：FastAPI（`uv run uvicorn main:app`）
- 存储：数据目录下的追加式审计日志 `audit.log`（事实源）+ 原子快照 `state.json`
- 密钥：`secrets` 随机十六进制密钥，HMAC-SHA256 常量时间验签（仅用于本地模拟，非生产 KMS）

---

## 1. 快速开始（本地验证）

```bash
uv sync                                  # 安装依赖
uv run pytest -q                         # 运行全部 36 个测试（含多签/并发/跨进程/回退/恢复）
uv run python demo.py                    # 不启服务，直接走一遍完整故事线
uv run uvicorn main:app --reload         # 启动 HTTP 服务，默认 http://127.0.0.1:8000/docs
```

数据目录由环境变量 `ADMISSION_DATA_DIR` 控制，默认 `./.admission-data`（已在
`.gitignore` 中忽略）。删除该目录即可重置全部本地数据。

### 1.1 调用方身份模拟

本地没有真实身份提供方，调用方身份通过请求头声明，授权仍以服务端登记的授权表为准：

| 请求头 | 含义 |
| --- | --- |
| `X-Caller-Id` | 调用方唯一标识（管理类/评估类接口必填） |
| `X-Caller-Roles` | 逗号分隔角色，如 `signer,deployer` |
| `X-Caller-Key-Grants` | 逗号分隔的可使用密钥 id（调用方声明，需与服务端授权一致） |

内置三类角色：`key_admin`（密钥与授权管理）、`policy_admin`（策略管理）、`signer`（签名）。
准入规则还可以自定义 `roles_allowed`（如 `deployer`）。

### 1.2 一条完整的 HTTP 调用链

```bash
ADMIN=(-H "X-Caller-Id: alice" -H "X-Caller-Roles: key_admin,policy_admin")
CI=(-H "X-Caller-Id: ci-bot" -H "X-Caller-Roles: signer,deployer" -H "X-Caller-Key-Grants: k1")
BASE=http://127.0.0.1:8000

# 1) 生成密钥并授权签名方
curl -s "${ADMIN[@]}" -X POST $BASE/admin/keys \
  -H 'Content-Type: application/json' -d '{"key_id":"k1","ttl_days":null}'
curl -s "${ADMIN[@]}" -X POST $BASE/admin/keys/k1/grants \
  -H 'Content-Type: application/json' -d '{"signer_id":"ci-bot"}'

# 2) 发布 v1 策略：容器镜像需要有效签名 + deployer 角色
curl -s "${ADMIN[@]}" -X POST $BASE/admin/policies -H 'Content-Type: application/json' -d '{
  "expected_version": 0, "request_id": "p1",
  "rules": [{"id":"signed-images","action":"pass","match_types":["container-image"],
             "require_signature": true, "roles_allowed": ["deployer"]}]}'

# 3) 未签名评估 -> deny/signature_missing
curl -s "${CI[@]}" -X POST $BASE/admission/evaluate -H 'Content-Type: application/json' -d '{
  "artifact_digest":"sha256:abc","artifact_type":"container-image","request_id":"e1"}'

# 4) 签名（带幂等 request_id），再次评估 -> pass
curl -s "${CI[@]}" -X POST $BASE/signatures -H 'Content-Type: application/json' -d '{
  "artifact_digest":"sha256:abc","artifact_type":"container-image",
  "key_id":"k1","request_id":"s1","ttl_days":7}'
curl -s "${CI[@]}" -X POST $BASE/admission/evaluate -H 'Content-Type: application/json' -d '{
  "artifact_digest":"sha256:abc","artifact_type":"container-image","request_id":"e2"}'

# 5) 回溯审计流水 / 按 request_id 重放历史结论
curl -s "$BASE/audit?event_type=admission_evaluated"
curl -s "$BASE/admission/replay/e2"
```

多人签名门槛：策略规则加 `"min_signatures": 2`，再用不同的 `X-Caller-Id`
（各自有服务端授权的密钥）分别 `POST /signatures` 登记签名；只有第一个人签时评估得
`deny / signature_quorum_not_met`（`signature_report.missing=1`），第二个不同签名方
签完后评估得 `pass`。

---

## 2. 策略模型与结论语义

### 2.1 策略版本（PolicyVersion）

- 策略由有序的 `PolicyRule` 列表构成；评估时 **第一个匹配制品类型的规则生效**
  （`match_types` 为空元组表示匹配所有类型）。
- 每次变更都产生 **不可变新版本**，版本号严格递增；回退不是改写旧版本，而是
  **追加一个规则集等于目标版本的新版本**，因此任何历史版本永不丢失、可随时复现。
- 创建策略时可传 `expected_version` 做乐观并发控制：当前版本不匹配则返回
  `409 policy_version_conflict`，避免并发写入互相覆盖。

### 2.2 准入结论（Decision）与原因（Reason）

评估按固定顺序过 5 道闸，第一道失败的闸决定 `reason`，保证结论稳定且可解释：

| 顺序 | 闸 | 失败结论 | reason |
| --- | --- | --- | --- |
| 1 | 调用方身份必须存在 | `deny` | `identity_unknown` |
| 2 | 策略存在且有规则覆盖该制品类型 | `manual_review` | `policy_not_covered` |
| 3 | 调用方具备规则要求的角色 | `deny` | `permission_denied` |
| 4 | 若规则 `require_signature`，有效签名方数须达到 `min_signatures` | `deny` | 见 §3.2 的签名原因 |
| 5 | 规则动作 | `pass` / `deny` / `manual_review` | `ok` / `policy_explicit_deny` / `ok` |

三类"不通过"被刻意区分：

- **身份权限不足** → `identity_unknown` / `permission_denied`
- **策略未覆盖** → `policy_not_covered`（结论是 `manual_review` 而非 deny）
- **策略明确禁止** → `policy_explicit_deny`

签名相关的"不通过"同样可区分：**完全没签名** → `signature_missing`；
**签了但不够数** → `signature_quorum_not_met`；**签了但全部失效** → 具体的
`signature_expired` / `signature_key_rotated` / `signature_key_revoked` 等原因。

每个结论都携带：`decision`、`reason`、`policy_version`、`rule_id`、`evaluated_at`、
调用方与制品摘要、签名状态、人类可读 `rationale` 以及分级判定依据数组 `basis`。
当命中规则要求签名时，结论还携带 `signature_report`：

```json
{
  "required": 2, "counted": 1, "missing": 1,
  "entries": [
    {"signature": {"signed_by": "alice", "key_id": "k1", "...": "..."},
     "status": "valid", "reason": null, "counted": true,
     "not_counted_reason": null},
    {"signature": {"signed_by": "bob", "key_id": "k2", "...": "..."},
     "status": "rotated", "reason": "signature_key_rotated",
     "counted": false, "not_counted_reason": "signature_key_rotated"}
  ]
}
```

即：要求几个（`required`）、实际算数几个（`counted`）、还缺几个（`missing`），
以及每条签名各自的状态与未计入原因（`duplicate_signer` / `duplicate_key` /
具体的失效原因），判定依据同时逐条写入 `basis` 与运行日志。

### 2.3 稳定性承诺

- 判定引擎是 **纯函数**：相同调用方 + 制品 + 指定策略版本 + 事实快照 ⇒ 字节级一致结果。
- 相同 `request_id` 的重复评估返回首次持久化的原始结论（响应中 `dedup: true`），
  即使之后签名过期、策略升级，该历史结论也不变。
- 使用新 `request_id` 才会按"当前事实"重新判定；也可显式传 `policy_version`
  按指定历史版本评估。

---

## 3. 签名与密钥轮换规则

### 3.1 密钥生命周期

| 操作 | 接口 | 语义 |
| --- | --- | --- |
| 生成 | `POST /admin/keys` | 随机密钥，可设 TTL（密钥本身过期时间） |
| 授权 | `POST /admin/keys/{id}/grants` | 登记允许使用该密钥的调用方（服务端授权表） |
| 轮换 | `POST /admin/keys/{id}/rotate` | 旧钥标记 `rotated_at/rotated_to` 并生成新活跃钥，旧记录不删除 |
| 吊销 | `POST /admin/keys/{id}/revoke` | 立即失效，且对已有签名 **追溯生效** |
| 撤销授权 | `DELETE /admin/keys/{id}/grants/{caller}` | 调用方失去该钥后，其既有签名变为未授权 |

### 3.2 多签模型：一个制品，多份独立签名

同一制品允许登记来自 **多个不同签名方** 的签名，每条记录以
`(artifact_digest, signed_by, key_id)` 唯一标识，各自携带 `signed_at` / `expires_at`
可追溯来源与时效：

- **同一签名方 + 同一把密钥 + 同一制品**：重复提交、重试或并发提交都只会留下
  一条记录，后续请求原样返回首次结果（`dedup: true`，审计记 `signature_dedup_hit`），
  绝不重复计数。相同 `request_id` 的重试同样命中该记录。
- **不同签名方、或同一签名方换一把密钥**：是相互独立的新签名，正常登记，
  不会因为"这个制品已经有别人的签名"而被拒。
- 历史签名记录永久保留可查（`GET /signatures/{digest}` 返回该制品全部签名），
  新旧记录互不覆盖，判定只按规则计数，不会出现前后结论自相矛盾。

### 3.3 签名状态（固定判定顺序）

签名载荷为带版本前缀的规范字节串：
`admission-signature/v1\n{artifact_type}\n{artifact_digest}`，HMAC-SHA256。
每条签名独立判定状态：

| 状态 | 含义 | 对应 deny reason |
| --- | --- | --- |
| `invalid` | HMAC 不匹配（载荷被篡改/密钥不符） | `signature_invalid` |
| `unauthorized_caller` | 签名方不在该密钥的服务端授权表中 | `signature_unauthorized_caller` |
| `revoked` | 签名密钥已被吊销（追溯） | `signature_key_revoked` |
| `rotated` | 签名密钥已被轮换（该钥所有签名都不再算数） | `signature_key_rotated` |
| `expired` | 超过签名 TTL | `signature_expired` |
| `valid` | 全部检查通过，可计入门槛 | — |

制品级聚合状态额外有两态：

| 聚合状态 | 含义 | 对应 deny reason |
| --- | --- | --- |
| `missing` | 该制品一条签名都没有 | `signature_missing` |
| `quorum_not_met` | 有有效签名但不同签名方数量不够门槛 | `signature_quorum_not_met` |

### 3.4 门槛计数规则（quorum）

策略规则的 `min_signatures`（默认 1）表示"至少几个 **不同签名方** 的签名同时有效"。
判定时：

- 只有当前状态为 `valid` 的签名参与计数；过期、被轮换、被吊销、签名方被取消授权、
  被篡改的签名都在 `entries` 里列明原因但不计入。
- 同一签名方用多把密钥签多份，只算 **1** 个（其余记 `duplicate_signer`）；
  同一把密钥被多个签名方使用，也只算 **1** 个（其余记 `duplicate_key`）。
- 计数不足时结论为 `deny / signature_quorum_not_met`，`signature_report` 给出
  `required` / `counted` / `missing` 与每条签名未计入的原因。
- `min_signatures=1`（默认值）与旧版"有有效签名即通过"语义 **完全一致**：
  旧策略不填该字段、旧快照里存的规则没有该字段，都按 1 处理。

### 3.5 密钥轮换 / 吊销 / 取消授权对已登记签名的影响

- **轮换**：密钥一旦轮换，用它签的 **所有** 签名（包括轮换前签的）立即不再计入，
  状态为 `rotated`；记录保留可查。签名方可改用轮换后的活跃密钥对同一制品 **补签**
  （同一签名方 + 新密钥 = 独立新记录），把门槛重新凑齐。轮换后试图用旧钥登记新签名
  会在事务内直接被拒（`409 key_rotated`）。
- **吊销**：立即失效且追溯生效（`revoked`），同样可用其他活跃密钥补签。
- **取消授权**：签名方被移出授权表后，其既有签名变为 `unauthorized_caller` 不再计入；
  重新授权后无需重签即恢复计入。
- 签名登记接口幂等：相同 `request_id` 重试、或同一签名方同钥重复提交，都返回首次
  记录（审计记 `signature_dedup_hit`），从根上杜绝重复计数。

---

## 4. 审计追溯与一致性保证

### 4.1 审计流水

所有写操作与每次评估都以追加事件写入 `audit.log`（JSON Lines），带全局递增 `seq`、
`occurred_at`、`actor`、`request_id` 和事件 `payload`。查询接口：

- `GET /audit`（可带 `event_type` / `request_id` / `start` / `end` 做时间范围回溯）
- `GET /admission/replay/{request_id}`：逐字复现历史准入结论（含记录时的策略版本与依据）

### 4.2 并发与崩溃一致性

- 事实源是只追加、逐条 fsync 的审计日志；`state.json` 只是日志前缀的纯投影快照
  （唯一写入方式 = 提交时把暂存事件折叠进状态）。
- 事务持有"进程内全局锁 + `fcntl.flock` 文件锁"，跨线程、跨进程均串行单写；
  快照写临时文件（pid/线程/随机名）+ fsync + `os.replace` 原子替换。
- 进程启动时若快照缺失、落后于日志或损坏，则从日志整体重放重建；日志末行半写入
  （崩溃在追加中途）会被安全截断，已提交事件不丢。
- 事务体内抛异常会回滚内存状态（暂存事件与 seq 自增都不落盘），因此
  **并发写入或中途失败不会留下重复记录、丢失记录或不完整状态**。
- 测试 `tests/test_concurrency*.py` 用 16 线程与 4 进程验证：同 request_id 只登记一次、
  同一签名方同钥的并发重复提交全部去重为一条记录、策略版本号连续不重复；
  `tests/test_multi_signature.py` 验证多个不同签名方并发登记互不丢失、各自计一次。

---

## 5. HTTP 接口一览

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/health` | 当前策略版本与审计事件数 |
| POST | `/admin/keys` | 生成密钥 |
| GET | `/admin/keys` | 列出密钥与授权表 |
| POST | `/admin/keys/{id}/rotate` | 轮换密钥 |
| POST | `/admin/keys/{id}/revoke` | 吊销密钥 |
| POST | `/admin/keys/{id}/grants` | 授权签名方 |
| DELETE | `/admin/keys/{id}/grants/{caller}` | 撤销授权 |
| POST | `/signatures` | 幂等登记制品签名（同一制品可有多签名方各自登记） |
| GET | `/signatures/{digest}` | 查询该制品的全部签名记录 |
| POST | `/admin/policies` | 创建策略版本（支持乐观锁） |
| POST | `/admin/policies/rollback` | 回退到历史版本（追加新版本） |
| GET | `/admin/policies` / `/admin/policies/{v}` | 版本列表 / 指定版本 |
| POST | `/admission/evaluate` | 发起准入评估（可钉住 `policy_version`） |
| GET | `/admission/replay/{request_id}` | 重放历史结论 |
| GET | `/audit` | 按类型/请求/时间范围查询审计 |

错误统一返回 `{"error", "message", "details"}`，`error` 为稳定错误码，HTTP 语义：
`401 caller_required`、`403 permission_denied`、`404 *_not_found / nothing_to_replay`、
`409 key_exists/key_rotated/key_revoked/policy_version_conflict/idempotency_conflict`。

---

## 6. 代码结构

```
admission/
  models.py    枚举、数据类型、错误码与异常（无 I/O）
  clock.py     可注入时钟（FixedClock 保证测试确定性）
  crypto.py    规范载荷、随机密钥、HMAC 签名/常量时间验签
  storage.py   文件锁、原子写、事务、快照与日志读写
  replay.py    审计事件 -> 状态快照的折叠（崩溃恢复事实依据）
  keys.py      密钥生成/轮换/吊销/授权
  signing.py   多签登记（按签名方+密钥去重）与法定人数（quorum）判定
  policy.py    策略版本、乐观锁、回退
  engine.py    纯判定函数 + 评估编排（幂等/重放/审计）
  audit.py     审计查询
  app.py       FastAPI 路由与错误归类
tests/         稳定性、轮换/过期、线程与进程并发、回退、崩溃恢复、HTTP 全链路
demo.py        本地故事线演示（不启服务）
```
