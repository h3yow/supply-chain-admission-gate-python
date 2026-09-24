# Supply-Chain Admission Gate（本地制品签名与准入校验）

一个完全本地可运行的供应链准入网关：用本地 JSON 存储模拟制品/签名/策略数据，用本地随机
密钥 + HMAC-SHA256 模拟签名体系。所有准入结论 **确定、可解释、可追溯**，支持密钥轮换、
签名时效、策略版本回退、并发幂等提交与崩溃恢复。

- 框架：FastAPI（`uv run uvicorn main:app`）
- 存储：数据目录下的追加式审计日志 `audit.log`（事实源）+ 原子快照 `state.json`
- 密钥：`secrets` 随机十六进制密钥，HMAC-SHA256 常量时间验签（仅用于本地模拟，非生产 KMS）

---

## 1. 快速开始（本地验证）

```bash
uv sync                                  # 安装依赖
uv run pytest -q                         # 运行全部 26 个测试（含并发/跨进程/回退/恢复）
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
| 4 | 若规则 `require_signature`，签名状态须为 `valid` | `deny` | 见 §3.2 的签名原因 |
| 5 | 规则动作 | `pass` / `deny` / `manual_review` | `ok` / `policy_explicit_deny` / `ok` |

三类"不通过"被刻意区分：

- **身份权限不足** → `identity_unknown` / `permission_denied`
- **策略未覆盖** → `policy_not_covered`（结论是 `manual_review` 而非 deny）
- **策略明确禁止** → `policy_explicit_deny`

每个结论都携带：`decision`、`reason`、`policy_version`、`rule_id`、`evaluated_at`、
调用方与制品摘要、签名状态、人类可读 `rationale` 以及分级判定依据数组 `basis`。

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

### 3.2 签名状态（固定判定顺序）

签名载荷为带版本前缀的规范字节串：
`admission-signature/v1\n{artifact_type}\n{artifact_digest}`，HMAC-SHA256。

| 状态 | 含义 | 对应 deny reason |
| --- | --- | --- |
| `missing` | 该制品未登记签名 | `signature_missing` |
| `invalid` | HMAC 不匹配（载荷被篡改/密钥不符） | `signature_invalid` |
| `unauthorized_caller` | 签名方不在该密钥的服务端授权表中 | `signature_unauthorized_caller` |
| `revoked` | 签名密钥已被吊销（追溯） | `signature_key_revoked` |
| `rotated` | 轮换发生 **之后** 仍用旧钥签的名 | `signature_key_rotated` |
| `expired` | 超过签名 TTL | `signature_expired` |
| `valid` | 全部检查通过 | — |

关键边界：

- **轮换前** 用旧钥签的名仍然有效（不视为 rotated，也不因轮换本身过期）；轮换后试图用旧钥
  登记新签名会在事务内直接被拒（`409 key_rotated`），因此不会出现"轮换后旧钥新签名"。
- 吊销立即且追溯生效；授权被撤销同样会让既有签名变为 `unauthorized_caller`，重新授权后
  无需重签即可恢复。
- 签名登记接口幂等：相同 `request_id` 重试返回同一记录（审计记 `signature_dedup_hit`）；
- 不同 `request_id` 对同一制品重复签名返回 `409 idempotency_conflict`，
  从根上杜绝同一制品出现互相矛盾的多条签名。

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
  不同 request_id 抢同一制品仅一个成功、策略版本号连续不重复。

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
| POST | `/signatures` | 幂等登记制品签名 |
| GET | `/signatures/{digest}` | 查询签名 |
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
  signing.py   幂等签名登记与七态签名校验
  policy.py    策略版本、乐观锁、回退
  engine.py    纯判定函数 + 评估编排（幂等/重放/审计）
  audit.py     审计查询
  app.py       FastAPI 路由与错误归类
tests/         稳定性、轮换/过期、线程与进程并发、回退、崩溃恢复、HTTP 全链路
demo.py        本地故事线演示（不启服务）
```
