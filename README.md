# Supply-Chain Admission Gate（本地版）

一个可在本地直接运行的制品签名与供应链准入校验服务：用**本地内存存储 + 本地 HMAC 密钥**
模拟制品、签名和策略数据，提供准入评估、密钥轮换、签名时效、策略版本管理与审计流水能力。

- 框架：FastAPI（无外部数据库 / KMS 依赖）
- 并发：所有变更路径在同一把进程内 `RLock` 下原子完成
- 存储：进程内本地存储（重启即重置），审计流水仅追加

---

## 1. 策略模型与结论语义

策略由一组**有序规则**组成，按顺序匹配，**第一条命中的规则**决定结论：

| 规则字段 | 含义 |
| --- | --- |
| `name` | 规则名，审计中作为 `matched_rule` 留痕 |
| `artifact_kinds` | 匹配的制品类型，`*` 表示任意 |
| `property_match` | 制品 `properties` 必须包含且相等的键值对 |
| `require_roles` | 调用方至少拥有其中一个角色；为空表示任意已认证调用方 |
| `require_signature` | 命中时要求存在一个**当前有效**的签名 |
| `effect` | `allow` / `deny` / `review` |

三类准入结论：

- `allow`：命中 `allow` 规则，角色与签名要求均满足。
- `deny`：明确禁止或资格/签名不满足，`reason` 给出可区分的原因码。
- `manual_review`：命中 `review` 规则，或没有任何规则覆盖（由策略的
  `on_unmatched` 决定，默认转人工复核）。

**拒绝原因码（刻意区分，绝不混为一谈）：**

| reason | 含义 |
| --- | --- |
| `unauthorized_caller` | 策略覆盖该制品，但调用方身份/角色不足 |
| `policy_not_covered` | 生效策略中没有任何规则覆盖该制品 |
| `policy_denied` | 命中规则显式禁止 |
| `signature_invalid` | 无签名 / 签名内容不匹配 / 使用轮换前旧密钥签名 |
| `signature_expired` | 签名超过有效期 |
| `key_revoked` | 签名密钥已被吊销 |
| `key_unknown` | 签名引用的密钥不存在 |

判定检查顺序固定（先角色、再签名、最后效果），因此同一输入的原因稳定。

### 结论稳定性与可复现

每次评估都会生成确定性的 `evaluation_id = sha256(policy版本 + 制品digest + 调用方身份)`。
在**同一策略版本**下，对同一制品由同一调用方重复评估：

- 结论、原因、命中规则与 `evaluation_id` 完全一致；
- 每次评估仍单独追加一条审计事件，便于追溯"何时判定过几次"。

指定历史 `policy_version` 可**重放**旧版本评估，历史结论可复现。

---

## 2. 签名与密钥轮换规则

- 密钥为本地生成的 HMAC-SHA256 对称密钥（`gate/keystore.py`），签名绑定
  制品规范 JSON（含 digest/name/kind/properties）与签名者身份。
- **授权签名方**：只有持有 `signer` 角色的调用方可登记签名；其他调用方的请求
  以 `unauthorized_caller`（HTTP 403）拒绝，不写入签名，只追加 `signature.rejected` 审计。
- **幂等登记**：同一制品 digest 至多一条签名。重试 / 并发重复提交返回既有记录
  （`created=false`），绝不重复登记；轮换后再签同名制品会报签名冲突，旧签名不会被静默覆盖。
- **签名时效**：签名带 `signed_at` 与 `expires_at`（默认 TTL 1 小时，可配置），
  过期验签抛 `signature_expired`。
- **密钥轮换**：`/keys/rotate` 生成新的活动密钥，旧密钥**保留不删除**（历史仍可解释），
  但旧密钥下的签名不再通过准入（`signature_invalid`，理由含 "rotated-out"）。
- **密钥吊销**：`/keys/revoke` 将密钥标记吊销，其名下签名立即失效（`key_revoked`）。
- **防篡改**：制品内容（name/kind/properties）与签名时不一致则 HMAC 校验失败。

---

## 3. 策略版本管理与审计追溯

- 每次发布产生不可变、单调递增的新版本号；旧版本永不删除，可列出、可按版本取。
- **回退**：`/policy/rollback` 把旧版本规则**重新发布为一个新版本**（版本链始终
  仅追加且完整），并记录 `policy.rolled_back {from_version, new_version}`。
- **审计流水**（仅追加，按时间有序），与对应状态变更在同一临界区内写入，
  中途失败不会留下"状态改了没日志"或"有日志没状态"：

| 事件类型 | 触发点 |
| --- | --- |
| `key.generated` / `key.rotated` / `key.revoked` | 密钥生命周期 |
| `signature.submitted` / `signature.rejected` | 签名登记（含 `created` 幂等标记）或被拒 |
| `policy.published` / `policy.rolled_back` | 策略变更 |
| `admission.evaluated` | 每次准入评估，含输入摘要、结论、原因、命中规则、判定依据 |

可按事件类型（`GET /audit?event_type=...`）或时间范围（服务内
`audit.events(since=, until=)`）回溯；历史评估可用 `policy_version` + 评估时间复现。

### 并发 / 失败一致性

- 全部写操作与评估都在单把存储锁内完成；并发签名只有 1 次 `created=true`，
  并发发布得到唯一连续版本号，不会出现重复 / 丢失 / 不完整记录。

---

## 4. 本地验证步骤

前置：Python 3.14、[uv](https://docs.astral.sh/uv/)。

```bash
# 安装依赖
uv sync

# 运行全部单测（-s 可查看"输入摘要 + 判定依据"日志）
uv run pytest -q
uv run pytest -s            # 查看 gate | admission eval ... 判定日志

# 启动本地服务（自带演示密钥与种子策略）
uv run uvicorn main:app --reload
```

### curl 演示

```bash
BASE=http://127.0.0.1:8000

# 1) 未签名制品评估 -> deny / signature_invalid
curl -s $BASE/admission/evaluate -H 'Content-Type: application/json' -d '{
  "artifact": {"digest": "sha256:abc", "name": "app:1",
               "kind": "container-image", "properties": {}},
  "caller": {"identity": "deployer-1", "roles": ["deployer"]}
}'

# 2) 授权签名方登记签名；重试返回 created=false
curl -s $BASE/artifacts/sign -H 'Content-Type: application/json' -d '{
  "artifact": {"digest": "sha256:abc", "name": "app:1",
               "kind": "container-image", "properties": {}},
  "caller": {"identity": "signer-1", "roles": ["signer"]}
}'

# 3) 再次评估 -> allow
curl -s $BASE/admission/evaluate -H 'Content-Type: application/json' -d '{
  "artifact": {"digest": "sha256:abc", "name": "app:1",
               "kind": "container-image", "properties": {}},
  "caller": {"identity": "deployer-1", "roles": ["deployer"]}
}'

# 4) 管理员轮换密钥 -> 旧签名失效（signature_invalid）
curl -s $BASE/keys/rotate -H 'Content-Type: application/json' -d '{
  "caller": {"identity": "root", "roles": ["admin"]}
}'

# 5) 查看审计流水
curl -s "$BASE/audit" | python -m json.tool
curl -s "$BASE/audit?event_type=admission.evaluated" | python -m json.tool
```

### 主要端点

| 方法 / 路径 | 说明 |
| --- | --- |
| `GET /health` | 当前活动密钥与策略版本 |
| `POST /artifacts/sign` | 登记签名（需 `signer` 角色，幂等） |
| `POST /admission/evaluate` | 准入评估（可带 `policy_version` 重放） |
| `POST /keys/rotate` / `POST /keys/revoke` | 密钥轮换 / 吊销（需 `admin`） |
| `POST /policy/publish` / `POST /policy/rollback` | 发布 / 回退策略（需 `admin`） |
| `GET /policy/versions` | 列出全部策略版本 |
| `GET /audit` | 审计流水，支持 `event_type` 过滤 |

> 注：调用方身份与角色直接放在请求体的 `caller` 字段中，以保证服务零外部依赖、
> 完全本地可运行；真实环境应由认证层注入。

---

## 代码结构

```
gate/
  models.py     # 领域模型：制品/调用方/密钥/签名/规则/策略版本/结论/审计事件
  errors.py     # 按原因分类的错误类型
  storage.py    # 带锁本地存储
  keystore.py   # 密钥生成、轮换、吊销
  signing.py    # HMAC 签名/验签、时效、幂等登记
  policy.py     # 策略版本管理 + 评估器（确定性 evaluation_id）
  audit.py      # 仅追加审计流水
  service.py    # 编排层（原子审计 + 输入摘要/判定依据日志）
  api.py        # FastAPI 路由与错误码 -> HTTP 状态码映射
tests/          # 准入/签名/并发/版本回退/HTTP 边界测试
main.py         # ASGI 入口
```
