# 多 agent 权限判断核心 — 设计文档

日期:2026-09-20
状态:待评审
适用仓库:`claude-permission-hook`(`secure_handler.py`,当前 297 行)

---

## 1. 背景与动机

现有脚本只服务 Claude Code。目标是让同一套判断逻辑能被 **Codex / Pi / opencode** 复用,
并把远程判断后端换成 **TypeSafe**(结构化判断 API),同时保留旧 gateway。

### 1.1 调查中被推翻的三个前提(重要)

设计过程中对审计日志的实测推翻了几个原有假设,记录在此以免后人重蹈:

1. **`decision: ask` ≠ 用户被弹窗。**
   `outside_cwd` 分支只写审计、不输出决定(`main()` 内),hook 静默退出后由 agent 自己的
   allow 规则决定结果。实测:读取 `/tmp/allow_rule_probe.txt` 记录了 `ask`,但未产生任何弹窗。
   因此历史上一切"弹窗率"统计(含 `analyze_audit.py`)都是**上界,不是实际值**。

2. **allow 规则是生效的。** 基于第 1 点的误读,曾一度判断规则失效,属错误结论。

3. **AI 兜底层的价值远高于短窗口估计。** 按月统计:健康月份(2026-05~07)放行率 38%~48%,
   每月自动放行约 1000 条;而 2026-09 骤降至 8%。全历史错误率 24%(2026-03/04 近乎全挂)。

### 1.2 本次重构的驱动力

**驱动力是可移植性(多 agent),不是提升通过率。**
提升通过率的最大 headroom 经实测在文件操作的 allow 规则配置上(约 600 次/30 天可由三条规则消除),
与本重构无关,另行处理。

---

## 2. 目标与非目标

### 目标
- 判断逻辑与具体 agent 解耦,新增一个 agent 的成本 = 新增一对 parse/emit 函数
- 远程判断后端可插拔(TypeSafe / 旧 anthropic gateway / 关闭)
- 判断逻辑可单元测试
- 引入"绝对红线":无论任何模型判定,都不自动放行
- 修复审计日志语义,使"到底省了多少、拦了多少"第一次可被回答

### 非目标(本轮明确不做)
- 不做敏感数据脱敏。理由:整个会话的命令、文件内容与输出本就全量发往主 gateway,
  判断请求是其严格子集,在此层拦截意义不大(由 owner 决策)。
- 不做决策缓存(YAGNI,等确有延迟痛点再说)
- 不做常驻 daemon
- 本轮只实现 Claude Code 适配器;Codex / Pi / opencode 留接缝,不实现
- 不改 allow 规则配置(独立工作项)

---

## 3. 重构视角:真正的问题

现有 `main()` 中,以下模式重复 8 次:

```python
write_audit(file_path, tool, 'allow', 'rule', 'within_cwd')   # 审计
print(json.dumps(allow_response('within cwd')))               # 输出
sys.exit(0)                                                   # 控制流
```

**判断、审计、输出格式三者焊死在一起。** 这是根因;"多 agent"与"可插拔后端"做不到,
都是这个耦合的后果。

重构由三个动作构成:

| # | 动作 | 解锁 |
|---|---|---|
| 1 | 判断与副作用分离:`judge()` 纯函数返回 `Verdict`;`main()` 末尾统一审计+输出 | 可测试、可换 adapter、后端被隔离 |
| 2 | 入口归一化:`parse_X(data) -> Request`,agent 数据形状不渗入逻辑 | 多 agent |
| 3 | 层级改为有序序列,取代嵌套 if 与散落的 `sys.exit()` | 加红线 = 插一个元素 |

**这三个动作即使 TypeSafe 永不上线也独立成立。** 据此分两阶段实施(见 §9)。

---

## 4. 目标结构(方案 A:单文件,约 550 行)

保持单文件 `secure_handler.py`,安装仍为拷贝一个文件、零 pip 依赖。

```
secure_handler.py
├─ 配置 / 审计
│
├─ ══ CORE(与 agent 无关) ══
│   Request(kind, payload, cwd)
│   Verdict(decision, reason, layer)
│   check_redlines()          第1层
│   local_rules()             第2层  within_cwd / git_metadata
│   dippy_analyze()           第3层  (现有)
│   backend_typesafe() / backend_anthropic()   第4层
│   judge(Request) -> Verdict  唯一出口
│
└─ ══ ADAPTERS(每 agent 一对函数) ══
    parse_claude_code(dict) -> Request
    emit_claude_code(Verdict) -> str | None
    ADAPTERS = {'claude-code': (parse, emit)}
```

### 4.1 核心契约

```python
Request = namedtuple('Request', 'kind payload cwd')
#   kind:    'command' | 'file_read' | 'file_write'
#   payload: 命令字符串 或 文件路径

Verdict  = namedtuple('Verdict', 'decision reason layer')
#   decision: 'allow' | 'ask' | 'no_opinion'
```

**边界判准:adapter 只翻译、不判断;core 只判断、不知道任何 agent 存在。**

`Edit` / `Write` / `NotebookEdit` 统一归一为 `file_write`(现有逻辑对三者处理完全相同)。
代价:失去区分 Edit 与 Write 的能力——若将来需要差异化策略,需在此处扩展。

### 4.2 入口分发

```bash
python3 secure_handler.py --agent=claude-code     # 默认值
```

默认 `claude-code`,现有 hook 命令无需任何改动即可升级。

---

## 5. 判断链与不变量

```python
def judge(req: Request) -> Verdict:
    # 第1层:红线(所有 kind 都适用,纯本地)
    if hit := check_redlines(req):
        return Verdict('ask', hit, 'redline')

    # 第2层:本地规则
    if v := local_rules(req):            # within_cwd / git_metadata
        return v

    # 文件操作到此为止 —— 不进入 dippy,也不出网(与现有行为一致)
    if req.kind in ('file_read', 'file_write'):
        return Verdict('no_opinion', 'outside_cwd', 'rule')

    # 以下仅 kind == 'command'
    if dippy_says_allow(req):
        return Verdict('allow', ..., 'dippy')
    return remote_judge(req)
```

**路由按 `kind` 分流,这是既有行为,不可在阶段一改变:**

| kind | 经过的层 | 落空时 |
|---|---|---|
| `file_read` / `file_write` | 红线 → 本地规则 | `no_opinion`(静默,交回 agent) |
| `command` | 红线 → 本地规则 → dippy → 远程后端 | `ask` |

若将来希望文件操作也接受远程判断,属**新增能力**,需单独提案并默认关闭。

### 不变量(不可让步)

| 不变量 | 说明 |
|---|---|
| **一切异常收敛到 `ask`** | 网络错、解析错、超时、后端全挂——一律 ask,永不 allow |
| **后端二选一,不做链式降级** | 选中的后端失败(连不上/超时/返回垃圾)或判危,一律 `ask`,绝不改问另一个后端。"这家不行就问下一家"等同于货比三家找一个肯说 yes 的 |
| **红线最先且纯本地** | 不依赖 dippy(dippy 可能挂),红线不能有空窗 |

---

## 6. 红线(owner 选定三类)

纯正则匹配,不依赖 dippy。

```python
REDLINES = {
 'prod_infra':  r'\bkubectl\b.*\b(apply|delete|exec|patch|edit|scale|rollout|replace|cp|'
                r'drain|cordon|label|annotate|set|run|taint|debug|proxy|port-forward)\b',
 'credentials': r'\bcoffer\b|/\.ssh/|/\.aws/|\b(secret|token|password|credential|private[_-]?key)\b',
 'destructive': r'\brm\s+-[rf]|\bgit\s+push\b.*--force|--force\b.*\bgit\s+push|'
                r'\bdrop\s+(table|database)\b|\btruncate\b|\bdd\s+if=|\bmkfs\b',
}
```

**刻意做宽。** 误报代价 = 多弹一次窗;漏报代价 = 危险命令被自动放行。两者不对称,故宁宽勿窄。
owner 已确认接受误报(如 `grep secret` 会被拦)。

`kubectl get/describe/logs` 等只读操作**不在红线内**,与 owner 的 CLAUDE.md 写操作清单一致。

**注意:数据外发 / 远程推送未被列为红线**(owner 决定),交由后端判断,
使 `git push` 等日常操作仍可能被放行。

---

## 7. 远程后端

### 7.1 TypeSafe 请求形状

```json
{"state": "cwd: <dir>\ncommand: <命令原文>", "model": "jev-latest", "questions": {
  "irreversible":  {"type":"noul","instructions":"不可逆地删除或覆盖数据"},
  "outside_proj":  {"type":"noul","instructions":"修改当前项目目录之外的文件"},
  "exfiltration":  {"type":"noul","instructions":"把本地数据发送到外部网络(推送到已知 git remote 不算)"},
  "untrusted_exec":{"type":"noul","instructions":"下载并执行未经审查的代码,如 curl | sh"},
  "sys_config":    {"type":"noul","instructions":"修改系统级配置或已安装软件"}
}}
```

`noul` 返回 0.0–1.0 连续值。判定:**`allow` 当且仅当 `max(所有维度) < 阈值`**。

**阈值是本设计唯一的"通过率 vs 安全"旋钮。** 现有 haiku 后端只返回 `SAFE`/`UNSAFE`
两个字,无此旋钮——这正是 2026-09 放行率从 38% 崩到 8% 时 owner 无法补偿的原因。

> ⚠️ **默认值 0.15 是未经验证的猜测。** `jev` 模型的校准特性未知。
> 上线前必须用历史命令标定实际分数分布,再确定切线。

### 7.2 配置(沿用 `SECURE_HANDLER_` 前缀,不改名)

| env | 默认 | 说明 |
|---|---|---|
| `SECURE_HANDLER_BACKEND` | `anthropic` | `typesafe` \| `anthropic` \| `off` |
| `SECURE_HANDLER_TYPESAFE_KEY` | — | 经 coffer 注入 |
| `SECURE_HANDLER_TYPESAFE_URL` | `https://api.typesafe.ai/v1/systemone` | |
| `SECURE_HANDLER_TYPESAFE_MODEL` | `jev-latest` | |
| `SECURE_HANDLER_THRESHOLD` | `0.15` | 待标定 |
| `SECURE_HANDLER_AI_BASE_URL` | 回落 `ANTHROPIC_BASE_URL` | **新增,解耦用** |
| `SECURE_HANDLER_AI_KEY` | 回落 `ANTHROPIC_AUTH_TOKEN` | **新增,解耦用** |

**`SECURE_HANDLER_AI_BASE_URL` / `_KEY` 是必须的架构修复:**
现有代码直接读 `ANTHROPIC_BASE_URL`,与 Claude Code 主对话共用同一变量,
导致无法只更换 hook 的后端而不影响主对话。

**默认 `anthropic` ⇒ 升级后行为与当前完全一致**,需显式切换才启用 TypeSafe。

### 7.3 key 经 coffer 注入

coffer 按**原名**注入,故 secret 名必须与 env 名一致:

```bash
coffer secret add SECURE_HANDLER_TYPESAFE_KEY --global
```

hook 命令包一层(实测开销 17ms,相对约 1s 的网络调用可忽略):

```bash
coffer run --global /usr/local/bin/python3.12 ~/.claude/hooks/secure_handler.py
```

⚠️ **不可使用 `--` 分隔符**,实测报错 `exec: "--": executable file not found in $PATH`。

### 7.4 后端选择与超时

**后端是二选一,不是降级链**(owner 决定,取代原稿的链式降级设计):

```
SECURE_HANDLER_BACKEND
  ├─ anthropic(默认) → haiku (15s) --错误/超时--> ask
  ├─ typesafe        → TypeSafe (6s) --错误/超时/判危--> ask
  └─ off             → 不联网,直接 no_opinion
```

**选了谁就用谁,失败就 ask,不去问另一家。** 最坏 6s(typesafe)或 15s(anthropic)。
**不做重试** —— 在抖动网关上重试只是把延迟翻倍。

原稿设计的是 `TypeSafe → 旧 gateway → ask` 的降级链,并配一条「降级只因错误,不因否定」的
规则来防止「货比三家找一个肯说 yes 的」。二选一把这个模糊地带整个删掉:不存在"下一家",
也就不需要那条规则,最坏延迟还从 6+4=10s 降到 6s。

`typesafe_neterror:*`(连不上)与 `typesafe_badresp:*`(返回了垃圾)的区分**保留**,
但只作为审计里的诊断信号,不再影响控制流。

### 7.5 回滚

```bash
SECURE_HANDLER_BACKEND=anthropic   # 回到当前行为
SECURE_HANDLER_BACKEND=off         # 纯 dippy,完全不联网
```

---

## 8. 审计日志语义修复

现状:`outside_cwd` 分支写入 `decision: ask` 但不输出任何决定,导致日志"说谎"。

**此静默行为必须保留。** 若改为真的输出 `ask`,将反过来覆盖 agent 自身的 allow 规则,
导致弹窗**增多**。因此只改日志语义,不改行为:

| `decision` | 含义 |
|---|---|
| `allow` | hook 主动放行(真实节省) |
| `ask` | hook **主动要求**弹窗(红线 / 后端判危) |
| `no_opinion`(新增) | hook 静默,交回 agent 自身规则与权限模式 |

额外记录字段:后端名、各维度分数、耗时,以支持阈值标定。

`analyze_audit.py` 的统计缺陷随之修复(它当前把 `ask` 当作弹窗计数)。

---

## 9. 实施阶段

### 阶段一:纯重构,零行为变更
1. 用**当前行为**构建测试表(输入 → 期望 verdict),作为回归基线
2. 抽出 `Request` / `Verdict` / `judge()`,`main()` 只保留 parse → judge → audit → emit
3. 抽出 `parse_claude_code` / `emit_claude_code`,建立 `ADAPTERS` 表
4. 验收:测试表全绿,审计日志输出与重构前逐条一致

### 阶段二:新增能力(均可由 env 关闭)
5. 加入红线层
6. 加入 `no_opinion` 日志值与扩展字段
7. 加入 `SECURE_HANDLER_AI_BASE_URL` / `_KEY` 解耦
8. 加入 TypeSafe 后端(默认关闭)
9. 用历史命令标定阈值,再决定是否切换默认后端

---

## 10. 测试策略

`judge()` 为纯函数,可直接 `import secure_handler` 后以表驱动测试:

- **红线表**:每类红线的正例与反例(尤其 `kubectl get` 必须**不**命中)
- **不变量表**:后端抛异常 / 超时 / 返回畸形 JSON → 必须得到 `ask`
- **回归表**:阶段一基线,确保重构未改变任何既有行为
- **适配器表**:Claude Code 的输入 JSON → 期望 Request;Verdict → 期望输出 JSON

---

## 11. 未决问题与风险

| # | 项 | 说明 |
|---|---|---|
| 1 | **`hookEventName` 硬编码疑似 bug** | `_pre_tool_response()` 恒返回 `'PreToolUse'`,但脚本同时注册在 `PermissionRequest` 下(Bash 走该路径)。事件名不匹配,**Bash 的 allow 可能一直未真正生效**。实施阶段必须验证。 |
| 2 | **阈值 0.15 未标定** | 见 §7.1。上线前必须用真实数据确定。 |
| 3 | **TypeSafe 真实推理延迟未知** | 实测 401(未推理)即需 1.09–1.32s,而旧 gateway 完整推理仅 0.93–1.18s。真实延迟可能更差。需拿 key 实测。 |
| 4 | **TypeSafe 定价 / 限流 / SLA 未知** | quickstart 未记载。 |
| 5 | **Bash 的 `ask` 是否为真弹窗未验证** | Bash 走 `PermissionRequest` 且代码确实输出 `ask`,但其后仍有 auto 分类器。影响对收益的估计。 |
| 6 | **2026-09 放行率骤降至 8% 原因不明** | 与本重构无关,建议独立排查。 |

---

## 12. 附:被本设计取代的想法

- **脱敏层**:曾设计对出网内容改写 AWS 资源 ID / 路径 / context。
  实测 135 条出网命令中 66% 含敏感标识。由 owner 决定不做(理由见 §2 非目标)。
- **常驻 daemon**:其主要收益(缓存)用文件缓存即可获得约 80%,不值得引入生命周期复杂度。
- **小型包结构**:边界更清晰,但破坏"拷贝单个文件即安装"的分发模型。owner 选择轻量方案 A。
