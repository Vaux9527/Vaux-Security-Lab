# MiniSec Project Context（项目上下文）

> 本文件是 MiniSec 的权威项目说明。进入本项目的任何对话，先以本文件为准；
> 代码与本文件不一致时，以代码为准，并回来更新本文件。
>
> 最后更新：2026-09-19（**七个实验、十个关卡全部完成，没有任何「开发中」**：SQL 3 关 + XSS 2 关 + 文件上传 + SSRF + 命令注入 + 越权访问 + CSRF；新增通关进度记录、关卡目录单一数据源、逐关独立靶子库/靶子目录、关卡页公共基模板；回归测试 166 项）

---

# 一、项目名称与定位

**MiniSec Vulnerability Lab** / 中文名：**MiniSec 网络安全漏洞实验平台**

面向网络空间安全学习者的 Web 漏洞教学靶场。模拟真实漏洞学习流程：

```
漏洞原理学习 → 实验环境操作 → 漏洞利用验证 → 攻击过程分析 → 安全修复学习
```

定位类似 DVWA / WebGoat / HTB Academy，差异化在于：
**中文教学 + 可视化分析（把实际执行的 SQL 展示出来）+ 渐进式关卡**。

---

# 二、实现目的 Goals

## 2.1 学习目的

理解 Web 应用的运行机制、常见漏洞的成因与利用方式，并掌握正确的修复做法。
每关都必须走完教学五段式：Background 原理 → Laboratory 操作 → Analysis 分析 →
Vulnerability 成因 → Fix 修复。

## 2.2 作品目的（这个项目要成为"能拿出来给人看"的作品）

以下 7 条是明确的交付目标，不只是"顺手做的"：

1. **真的上线**：对外可访问的网址 + GitHub 源码链接（招聘方真的会点开看）
2. **写像样的设计文档**：README / 本文件讲清楚设计理念——为什么是五步学习法、
   为什么"可视化生成的 SQL"对教学重要
3. **测试成体系**：10 个关卡共 **166 项**自动化回归测试（`smoke_test.py`），覆盖通关判定、分库隔离、靶子目录与安全基线
4. **记录技术决策与取舍**：例如"为什么靶子库要和平台库分家"、"为什么选 PythonAnywhere"
   （见第十一章"技术决策记录"），这些是面试时最有价值的谈资
5. **真实用户反馈**：找同学试用（目标 10 人），收集意见并据此迭代
6. **往深度升级**：后续加一关"SQL 注入的绕过与防御对抗"；或写一个自动化漏洞扫描脚本，
   把 MiniSec 当作被测目标——这样项目就从"教学平台"升级成"安全工具的开发底座"
7. **简历表达具体化**：不用"开发了 Web 安全靶场平台"这种空话，而要写清数量、动作与安全思维

> 简历写法参考：
> 设计并实现 Web 安全教学靶场 MiniSec，覆盖 N 类漏洞共 M 个关卡，
> 含"SQL 语句可视化"教学模块与自动化回归测试；部署于公网（XX 平台），
> 并完成生产环境安全加固（调试模式关闭、密钥外置、密码哈希、实验靶子数据隔离）。

---

# 三、上线形态（已决定：路线 C）

```
   门面站（GitHub Pages，静态）              真靶场（PythonAnywhere，Flask）
   ┌──────────────────────────┐   点击    ┌────────────────────────────┐
   │ 项目介绍 / 学习路线        │ ───────→ │ 真实的 Flask 应用 + SQLite  │
   │ 每关原理讲解（图文）        │  跳转    │ 真实注入、真实数据库结果     │
   │ 纯前端"注入演示"（JS 动画） │          │ /labs/sql/level1 ...        │
   │ 免责声明 / 在线实例按钮     │ ←─────── │ "返回讲解"链接              │
   └──────────────────────────┘   链接    └────────────────────────────┘
```

**关键结论（2026-09 查证）**

- **GitHub Pages 只能托管静态文件**，不能运行 Python/Flask/数据库。
  所以"把现在的 Flask 代码直接放上 GitHub Pages"是不可行的。
- 真靶场需要能跑 Python 的平台。免费方案里 **PythonAnywhere 免费版**最合适：
  1 个站点、**512MB 持久磁盘（SQLite 能活下来）**、100 CPU 秒/天、
  无 SSH、无定时任务、免费永久、不需信用卡。Render 免费版虽然免费，
  但 15 分钟无访问会睡眠、磁盘是一次性的（数据库会丢），不适合做靶场。
- **不需要 ICP 备案**：备案的判断标准是"服务器是否在中国大陆境内"，
  GitHub Pages（美国机房）与 PythonAnywhere（境外）都不需要。
  代价是国内访问速度一般，可用 Cloudflare 给门面站加速（同样不需备案）。
  若将来想国内高速访问 → 服务器搬回国内 → 那时必须备案，且个人备案对内容有限制。
- 门面站与靶场之间**用按钮跳转，不要用 iframe 内嵌**（浏览器 Cookie 策略会拦 iframe 里的登录态）。

**100 CPU 秒/天意味着**：必须做限速 + `robots.txt` + 禁止收录，
否则被自动扫描器刷几分钟，当天网站就打不开了。

---

# 四、技术栈与运行方式

| 层 | 技术 |
|---|---|
| 后端 | Python 3.10 + Flask 3.1.3 |
| 前端 | HTML + Jinja2 + CSS（不用 JS 框架） |
| 数据库 | SQLite（**平台库 platform.db + 靶子库 lab_sql.db**） |
| 测试 | Flask test client（`smoke_test.py`） |

```powershell
cd MiniSec
.\venv\Scripts\python.exe init_db.py     # 首次：一键建库（幂等）
.\venv\Scripts\python.exe app.py         # 启动 → http://127.0.0.1:5001
.\venv\Scripts\python.exe smoke_test.py  # 回归测试，166 项应全部 PASS
```

演示账号：`admin / 123456`（存在平台库 `users` 表，密码是哈希值）。

**可用的环境变量**（见 `config.py`）：

| 变量 | 作用 |
|---|---|
| `MINISEC_SECRET_KEY` | 会话签名密钥，**公网部署必须设置** |
| `MINISEC_DEBUG` | `1`（默认）= 本地调试；公网部署设 `0` |
| `MINISEC_PORT` | 本地端口，默认 5001 |
| `MINISEC_PLATFORM_DB` / `MINISEC_LAB_SQL_DB` | 覆盖数据库文件位置 |
| `MINISEC_RATE_LIMIT` | `0` = 关闭限速（本地想随便刷新时用） |
| `MINISEC_RATE_LIMIT_GLOBAL` / `_LOGIN` / `_LAB_QUERY` / `_LAB_RESET` | 各类请求每分钟上限 |
| `MINISEC_TRUST_PROXY` | `1` = 信任 `X-Forwarded-For` 取真实 IP（**只有确实在可信代理后面才开**） |

---

# 五、项目结构（当前）

```
MiniSec
├── app.py                  # 入口：首页 / 登录 / 退出 / robots.txt / 内部接口 / 错误页
├── config.py               # 配置中心：密钥、库路径、靶子目录、关卡参数（读环境变量）
├── curriculum.py           # ⭐ 实验与关卡目录（单一数据源，别处都 import 它）
├── progress.py             # ⭐ 通关进度记录（平台数据，不是靶子数据）
├── database.py             # 分库连接：get_platform_db() / get_lab_db(name)
├── auth.py                 # login_required 装饰器
├── security.py             # ⭐ CSRF 表单令牌防护（不依赖第三方库）
├── ratelimit.py            # ⭐ 每 IP 限速防刷
├── init_db.py              # ⭐ 数据库 / 靶子目录一键幂等重建（--reset / --show）
├── smoke_test.py           # ⭐ 回归冒烟测试（166 项检查）
├── verify_levels.py        # ⭐ 逐关验收脚本（每关一个正例 + 一个反例）
├── wsgi.py                 # ⭐ 公网部署入口：强制关 debug、无密钥拒绝启动
├── requirements.txt        # ⭐ 依赖清单（venv 不进库，部署靠它重建环境）
├── deploy/
│   ├── DEPLOY.md           # 上线部署指南（已决定不做，方案保留备用）
│   └── pythonanywhere_wsgi.py   # PythonAnywhere 的 WSGI 配置模板
├── routes/
│   ├── __init__.py
│   ├── labs.py             # /labs 列表 + 实验详情（有分关的渲染关卡列表）
│   ├── sql_lab.py          # SQL Lab：Level 1 查询注入 / 2 登录绕过 / 3 UNION
│   ├── xss_lab.py          # XSS Lab：Level 1 反射型 / 2 存储型
│   ├── upload_lab.py       # 文件上传 Lab
│   ├── ssrf_lab.py         # SSRF Lab
│   ├── cmdi_lab.py         # 命令注入 Lab
│   ├── idor_lab.py         # 越权访问 Lab（水平越权 / IDOR）
│   └── csrf_lab.py         # CSRF Lab（含模拟的攻击者页面）
├── templates/
│   ├── base.html           # 导航 + 页脚免责声明 + robots noindex
│   ├── index.html          # 首页（学习路线、总进度、平台介绍）
│   ├── login.html          # 登录页（表单带 CSRF 令牌）
│   ├── labs.html           # 实验列表（双语 + 状态徽标 + 进度）
│   ├── levels.html         # ⭐ 通用关卡列表页（各实验共用）
│   ├── lab_base.html       # ⭐ 关卡页基模板（五段式骨架，新关卡都继承它）
│   ├── lab.html            # 通用实验详情页（未分关的实验，无死链）
│   ├── sql_level1.html     # Level 1（独立页面，先于基模板写成）
│   ├── sql_level2.html     # Level 2（独立页面）
│   ├── sql_level3.html     # Level 3（继承 lab_base.html）
│   ├── xss_level1.html     # XSS Level 1（继承 lab_base.html）
│   ├── xss_level2.html     # XSS Level 2（继承 lab_base.html）
│   ├── upload_level1.html  # 文件上传（继承 lab_base.html）
│   ├── ssrf_level1.html    # SSRF（继承 lab_base.html）
│   ├── cmdi_level1.html    # 命令注入（继承 lab_base.html）
│   ├── idor_level1.html    # 越权访问（继承 lab_base.html）
│   ├── _xss_cheatsheet.html # XSS 两关共用的「可执行结构速查表」
│   ├── csrf_level1.html    # CSRF 关卡页（继承 lab_base.html）
│   └── csrf_attacker.html  # ⭐ 模拟的攻击者页面（故意不继承 base.html）
│   └── error.html          # ⭐ 双语错误页（400 / 404 / 429 / 500）
├── static/
│   ├── style.css           # 深色主题 + 代码块 / 表格 / 徽标 / 留言板 / 终端样式
│   └── uploads/            # 【生成物·不进 git】文件上传关的靶子目录（故意可被访问）
├── lab_sandbox/            # 【生成物·不进 git】命令注入关的工作目录（含 secret.txt）
├── platform.db             # 【生成物·不进 git】平台库
├── lab_sql.db              # 【生成物·不进 git】Level 1 靶子库
├── lab_login.db            # 【生成物·不进 git】Level 2 靶子库
├── lab_union.db            # 【生成物·不进 git】Level 3 靶子库
├── lab_xss.db              # 【生成物·不进 git】XSS 靶子库
├── lab_upload.db           # 【生成物·不进 git】文件上传账本
├── lab_cmd.db              # 【生成物·不进 git】命令注入执行历史
└── PROJECT_CONTEXT.md      # 本文件
```

已删除（被 `init_db.py` 取代）：
`create_db.py`、`add_user.py`、`add_data.py`、`add_sql_users.py`、`check_db.py`、`minisec.db`。
这些一次性脚本每个只干一小块，且重复运行会插入重复数据。

---

# 六、数据库设计：平台库与靶子库必须分家

```
platform.db（平台库 —— 不能被拿走的数据）
  users(id, username, password, role)       ← 平台登录账号，password 存哈希
  labs(id, name, title, title_en, description, description_en, status, entry_url)
  progress(lab, level, cleared_at)          ← 通关进度（平台数据，进靶子无关）

靶子数据库 —— 一关一库，注定会被打穿，可随时删除重建：

  lab_sql.db     sql_users(id, username, password, role)        4 个假用户
  lab_login.db   login_users(id, username, password, role)      4 个假账号
  lab_union.db   union_users(id, username, password, role)      4 个会员
                 secret_notes(id, title, content)               3 条内部备忘（含 flag）
  lab_xss.db     xss_guestbook(id, author, content, created_at) 留言板
  lab_upload.db  uploaded_files(id, original_name, saved_name, size, content_type, uploaded_at)
  lab_cmd.db     command_runs(id, raw_input, executed_command, exit_code, output, ran_at)
  lab_idor.db    idor_users(id, username, display_name, role)              4 个用户
                 idor_notes(id, owner_id, title, content, is_private)     7 条笔记（含 flag）
  lab_csrf.db    csrf_users(id, username, email, display_name)             2 个靶子账号

靶子目录 —— 不是所有靶子都是数据库：

  static/uploads/   文件上传关的上传位置（故意放在 web 可直接访问的目录下）
  lab_sandbox/      命令注入关的工作目录（里面放着本关的目标文件 secret.txt）

以上全部是假数据：弱口令、明文密码、假 flag、假配置。
它们的共同点是"故意不安全"，因为教学需要你看清漏洞的全貌。
```

## 为什么必须分家（重要）

1. **Level 3 的教学目标就是"读别的表"**。UNION 注入只需要**一条语句**就能把
   `users` 表整个读出来：`' UNION SELECT id, username, password, role FROM users --`。
   如果靶子和平台账号同库，公网上任何访客都能拿走你的账号数据。
2. **权限最小化原则**：故意不安全的靶子组件，不该握着平台账号这种要害数据。
   真实企业的做法就是把"暴露在外、能被攻击的部分"隔离到独立的库/容器里。
3. **可重置**：靶子被搞乱后，删掉 `lab_sql.db` 重新生成即可，碰不到平台数据。
4. **别依赖巧合**：Python 的 `sqlite3` 默认一次只能执行一条语句，
   这挡住了 `; DROP TABLE users;` 这类堆叠注入——但这是驱动的默认行为，
   不是你的安全设计，而 UNION 读取根本不受影响。

## 一键重建

```powershell
python init_db.py            # 建库；已存在则保持不变（幂等）
python init_db.py --reset    # 删掉重建，靶子数据恢复出厂状态
python init_db.py --show     # 打印两个库的内容
```

`database.py` 在数据库文件缺失时会自动调用建库逻辑，
所以全新克隆下来直接启动网站也不会因为缺数据库而报错。

---

# 七、页面路由总览

| 路由 | 页面 | 登录要求 | 状态 |
|---|---|---|---|
| `/` | 首页（含总进度） | 否 | ✅ |
| `/login` `/logout` | 登录 / 退出 | 否 | ✅ |
| `/labs` | 实验列表（读 labs 表 + 进度） | 是 | ✅ |
| `/labs/<lab_name>` | 实验详情：有分关的渲染关卡列表，否则通用占位页 | 是 | ✅ |
| `/labs/sql/level1` | SQL Level 1 基础查询注入（GET/POST） | 是 | ✅ 封版 |
| `/labs/sql/level2` | SQL Level 2 登录绕过（GET/POST） | 是 | ✅ |
| `/labs/sql/level3` | SQL Level 3 UNION 查询（GET/POST） | 是 | ✅ |
| `/labs/xss/level1` | XSS Level 1 反射型（GET，`?q=`） | 是 | ✅ |
| `/labs/xss/level2` | XSS Level 2 存储型留言板（GET/POST） | 是 | ✅ |
| `/labs/upload/level1` | 文件上传（POST，multipart） | 是 | ✅ |
| `/labs/ssrf/level1` | SSRF（GET/POST） | 是 | ✅ |
| `/labs/cmdi/level1` | 命令注入（GET/POST） | 是 | ✅ |
| `/labs/sql/reset` | 重置 Level 1 靶子（POST） | 是 | ✅ |
| `/labs/sql/level2/reset` | 重置 Level 2 靶子（POST） | 是 | ✅ |
| `/labs/sql/level3/reset` | 重置 Level 3 靶子（POST） | 是 | ✅ |
| `/labs/xss/level2/reset` | 清空留言板（POST） | 是 | ✅ |
| `/labs/upload/level1/reset` | 清空上传目录（POST） | 是 | ✅ |
| `/labs/cmdi/level1/reset` | 重建沙箱并清空执行历史（POST） | 是 | ✅ |
| `/internal/admin-config` | 内部接口（**故意不鉴权**，SSRF 靶子） | 否 | ✅ |
| `/internal/status` | 内部探针页（同上） | 否 | ✅ |
| `/labs/idor/level1` | 越权访问 Level 1 水平越权（GET，`?as=` `?note_id=`） | 是 | ✅ |
| `/labs/idor/level1/reset` | 重置用户与笔记（POST） | 是 | ✅ |
| `/labs/csrf/level1` | CSRF Level 1 跨站请求伪造（GET） | 是 | ✅ |
| `/labs/csrf/level1/profile` | 改邮箱接口（**故意豁免 CSRF 校验**，靶子） | 是 | ✅ |
| `/labs/csrf/attacker` | 模拟的攻击者页面（自动提交表单） | 是 | ✅ |
| `/labs/csrf/level1/reset` | 重置靶子账号邮箱（POST，照常校验令牌） | 是 | ✅ |

---

# 八、SQL Injection Lab 进度

## Level 1 基础查询注入 Basic Query Injection —— ✅ 已封版

**目标**：让查询条件永远成立，一次返回全部用户。

**漏洞代码（故意保留，不要"修好"它）**：

```python
generated_sql = f"""
SELECT id, username, password, role
FROM sql_users
WHERE username = '{username}'
"""
cursor.execute(generated_sql)
```

**通关判定**：一次查询返回行数 > 1（`EXPECTED_ROWS = 1`）。
只把目标换成别人（`bob' --`）也算注入，但本关要求拿到全部用户——
这条规则已写在页面上，避免学习者困惑。

**Attack Analysis 四个分支**：SQL 语法错误 / 多行返回（通关）/ 命中特征但未通关 / 正常或空结果。

**封版已完成的内容**：

- ✅ 通关前可展开的**分层提示**（3 级，不直接给答案）
- ✅ 通关后的 **Vulnerability & Fix**（坏代码 vs 参数化查询对照）
- ✅ 通关后的**实验总结 Summary**（成因 / 手法 / 危害 / 修复 四条 + 一句话口诀 + 下一关预告）
- ✅ 结果改为**表格**并高亮"多出来"的用户（红色行），保留原始元组输出做对照
- ✅ 全站**双语**（分析文字、提示、总结全部中英成对）
- ✅ 页面写明通关判定规则与实验目标

**Level 1 标准 payload**：`admin' OR '1'='1' --`
（单引号闭合字符串 → 恒真条件让 WHERE 失效 → `--` 注释掉多余部分 → 返回 4 行）

## Level 2 登录绕过 Login Bypass —— ✅ 已完成

**目标**：不使用管理员密码，却以 admin 身份进入系统。

**独立靶子库** `lab_login.db` / `login_users`（4 个假账号，弱口令 + 明文，教学性故意）。
一关一库：练登录绕过不会搞乱 Level 1 的数据，恢复出厂也各管各的。

**漏洞代码（故意保留，不要“修好”它）**：

```python
generated_sql = f"""
SELECT id, username, role
FROM login_users
WHERE username = '{username}' AND password = '{password}'
"""

cursor.execute(generated_sql)
row = cursor.fetchone()

if row:
    session["username"] = row[1]   # 查到记录就认为登录成功
```

**通关判定**：登录语句返回了 `admin` 这一行，**并且**本次提交的账号密码
在数据库里**不是一组合法凭据**（即：你是绕过了密码，而不是知道密码）。
所以直接输入 `admin / admin123` 属于正常登录，**不判通关**。

**标准 payload**：用户名 `admin' --`，密码随便填。
原理：单引号提前结束字符串，`--` 把 `AND password='...'` 整段注释掉，
WHERE 只剩 `username='admin'` 一个条件。

**Attack Analysis 分支**：SQL 语法错误 / 绕过成功（通关）/ 绕过了但进的是别人 /
正常登录 / 用户名或密码错误。

**页面内容**：五段式齐全（背景 / 操作 / 分析 / 成因 / 修复）、3 级分层提示、
通关后展示漏洞代码与参数化修复对照、实验总结与口诀、独立的“恢复出厂”按钮，
并明确说明**本关不会改变平台登录状态**（靶子库与平台库分离）。

**测试**：`smoke_test.py` 新增“Level 2 行为”整组（13 项），覆盖正常登录不判完成、
错误密码、`admin' --` 通关、恒真条件通关、绕过了但非 admin、SQL 错误、回显转义、
独立恢复出厂且不影响 Level 1。

## Level 3 UNION 查询 UNION Based Injection —— ✅ 已完成

**目标**：在一次「查会员」的请求里，读到前台本不该暴露的内部表 `secret_notes`。

**独立靶子库** `lab_union.db`：`union_users`（4 个会员）+ `secret_notes`
（3 条内部备忘，其中一条的内容就是本关的 flag）。

**漏洞代码（故意保留）**：

```python
generated_sql = f"""
SELECT id, username, password, role
FROM union_users
WHERE username = '{username}'
"""
cursor.execute(generated_sql)
```

**通关判定**：查询结果里出现了 `secret_notes` 的内容（`flag{...}`）。
判定看的是"结果里到底有没有它"，而不是"输入里有没有 UNION"。

**标准 payload**：`' UNION SELECT id, title, content, 'x' FROM secret_notes --`
（原查询 4 列，`secret_notes` 只有 3 列，所以要补一个字面量）

**教学点**：页面会显示"本次查询返回几列"，并专门识别
"UNION 两侧列数不一致"这类报错，把 `ORDER BY` 探列数的思路讲清楚。
结果表的表头刻意写成「列1 / 列2 / 列3 / 列4」——
UNION 是按<b>位置</b>映射的，字段名对不上不重要。

---

# 八之二、XSS 实验（2 关，已完成）

## Level 1 反射型 XSS Reflected XSS —— ✅ 已完成

**载体**：站内搜索（`GET /labs/xss/level1?q=`），输入被回显到页面上。

**这一关不做任何过滤**：输入被原样拼进页面，目的是让"输入变成了代码"
这个最基本的因果关系毫无干扰地显现出来。（过滤与绕过放到 Level 2。）

**通关判定**：过滤之后真正进入页面的 HTML 里，仍然存在**可执行结构**
（脚本标签 / 事件属性 / 可嵌入标签 / `javascript:` 伪协议之一）。
判定看的是"页面里变成了什么"，不是"输入里有没有关键词"。

**标准 payload**：`<script>alert(1)</script>`

**页面特色**：
- 把"渲染进页面的 HTML"单独显示出来（像 SQL Level 1 的 Generated SQL 一样，
  把看不见的东西变成看得见的）；
- 靶场不禁用 JS，所以注入成功会**真的弹窗**；
- 页面上有一张折叠的**「可执行结构速查表」**（两关共用）：
  列出五类能执行 JavaScript 的写法、各自的原理、以及什么时候用得上。
  它给的是"招式表"而不是答案 —— 哪一招在这关能生效、为什么，仍然要学习者自己判断。
  加这张表的直接原因：原来从"想想还有什么标签能执行代码"直接跳到具体 payload，
  中间缺了"HTML 里到底有哪几类写法"这一层，学习者拿到的是"一串没见过的东西"。

## Level 2 存储型 XSS Stored XSS —— ✅ 已完成

**载体**：留言板，留言存进 `lab_xss.db` 的 `xss_guestbook` 表，所有访客可见。

**这一关才加过滤器**：只删掉 `<script` 这七个字符（故意很弱的黑名单），
把「黑名单挡不住」和「存储型影响所有访客」两个教学点合到一关里。

**通关判定**：数据库里存在一条留言，过滤之后仍然含有可执行结构。

**教学点**：绕过手法与反射型相同，差别在**影响面** ——
反射型要骗人点链接，存储型只需要等人来访；页面会分别列出
"库里的原始内容"与"过滤后的结果"做对比。

---

# 八之三、文件上传 Unrestricted File Upload（1 关，已完成）

**载体**：头像上传。

**两个叠加的漏洞**：
1. 校验用**黑名单**（`.php .jsp .asp .aspx`）而且**只看后缀名**；
2. 文件被存进 **`static/uploads/`**（web 可直接访问），并且保留用户给的文件名。

**通关判定**：文件被保存成功，而且**它的内容不是图片**
（文件头匹配不上任何图片格式）。判定看的是磁盘上真实存在的文件。

**页面给出**：保存路径、**可直接访问的 URL**、文件头字节、以及"客户端声明的类型 vs
文件头实际识别结果"的对比 —— 后者才是真相。

**靶场自己唯一的防护**：只取文件名的最后一段（防 `../` 写到项目外），
因为路径穿越不是本关的教学点，而且真写出去会把靶场本身搞坏。

---

# 八之四、SSRF 服务端请求伪造（1 关，已完成）

**载体**："网页快照"功能 —— 服务端替你去请求一个 URL。

**内部靶子**：`app.py` 里的 `/internal/admin-config` 与 `/internal/status`，
**故意不做登录校验**（真实内网服务常常如此），响应里带内部标记 `INTERNAL-ONLY`。

**通关判定**（三个客观条件同时成立）：
1. 请求成功；
2. 目标地址是**内网 / 环回地址**（用 `socket.getaddrinfo` 解析成 IP 后判断，
   不是比较字符串）；
3. 响应里出现 `INTERNAL-ONLY`。

**教学点**：抓一个外网网页**不算** SSRF（服务器本来就能上外网）——
关键是"让服务器去访问它内部才够得着的地方"。
页面还会提到云环境的经典目标 `169.254.169.254`。

**安全开关**：`MINISEC_SSRF_ALLOW_EXTERNAL=0` 可收紧为"只允许请求本机"，
默认放开（漏洞要真实）。

---

# 八之五、命令注入 OS Command Injection（1 关，已完成）

**载体**："网络诊断"工具 —— 执行 `ping -n 1 -w 1000 <你的输入>`（Linux 为 `-c 1 -W 1`）。

**漏洞**：字符串拼接 + `shell=True`，两者缺一不可。

**靶子**：`lab_sandbox/` 工作目录里的 `secret.txt`（内容为本关 flag）。

**通关判定**：命令输出里出现了 `flag{...}` ——
也就是你成功让服务器执行了**一条不属于这个功能的命令**。

**标准 payload**：Windows `127.0.0.1 & type secret.txt`；
Linux / macOS `127.0.0.1; cat secret.txt`。

⚠️ **这一关真的执行系统命令**，因此加了三道"不改变漏洞、只限制爆炸半径"的措施：
1. 工作目录固定在 `lab_sandbox/`；
2. 执行超时 `MINISEC_CMDI_TIMEOUT`（默认 3 秒）；
3. 输出截断 4000 字符。

**输入不做任何过滤** —— 过滤了就不是这个漏洞了。
这也是**决定不上线**之后才敢做的设计（见第十三章）：
本地自己跑和"给陌生人一个 shell"是两件完全不同的事。

---

# 八之六、越权访问 Broken Access Control（1 关，已完成）

**载体**：「我的笔记」功能 —— 列表只显示自己的笔记，点开某一条时走另一个接口。

**漏洞**：详情接口的 SQL 只有 `WHERE id = ?`，**没有 `owner_id` 条件**。

```python
# ⚠️ 故意漏洞：只按 id 取记录 —— 没有问"这条记录是不是你的"
cursor.execute(
    "SELECT id, owner_id, title, content FROM idor_notes WHERE id = ?",
    (note_id,)
)
```

**靶子库** `lab_idor.db`：`idor_users`（4 个用户）+ `idor_notes`（7 条笔记）。
id=6 那条属于 admin 且 `is_private=1`，内容就是本关的 flag。

**通关判定**：读到的笔记，**它的 `owner_id` 和当前身份不一致**。
判定比较的是"数据的归属"和"你提交的身份"这两个值，与关键词无关。

**标准做法**：保持 `as=1`（alice）不变，把 `note_id` 从 1 试到 7。

**这一关和前面几关的形态不同**，也是它值得单独做一关的原因：
SQL 注入 / XSS / 命令注入都是「输入被当成了代码」，
越权是「逻辑上少问了一句：这条数据是你的吗」。
平台自己的登录用了 `login_required`（认证：你是谁），
但没有任何地方回答「你能看什么」（授权）—— 这就是 OWASP Top 10 的第一名。

**页面上刻意保留了「身份切换」下拉**（alice / bob / carol）：
真实系统里这个身份来自会话、用户改不了，做成可切换只是为了让你能同时
看到"我的视角"和"别人的数据"。整个实验过程中身份保持不变——
越权的定义就是"身份没变，数据换了"。

---

# 八之七、CSRF 跨站请求伪造（1 关，已完成）

**载体**：「修改资料（邮箱）」功能 + 一个模拟的**攻击者页面**。

**漏洞**：改邮箱接口只靠 Cookie 认人，**从不校验请求是从哪来的**：

```python
# ⚠️ 故意漏洞：身份只来自 Cookie，请求来源从未被校验
username = session.get("csrf_lab_user")
email = request.form.get("email")
conn.execute("UPDATE csrf_users SET email = ? WHERE username = ?", (email, username))
```

**靶子库** `lab_csrf.db`：`csrf_users`（victim@example.com / admin@example.com）。

**通关判定**：victim 的邮箱变成 `attacker@evil.example`。

**怎么打**：进入关卡 → 点左侧「打开攻击者页面」→ 那个页面里有一个
**自动提交的表单**，指向改邮箱接口，而且**不带令牌**（攻击者当然拿不到）→
回到关卡页，邮箱已经被改了。

**本项目的对照设计（这一关最值钱的地方）**：

- 平台自身的接口由 `security.py` **全站校验** CSRF 令牌（`before_request` +
  `compare_digest` 固定时间比较）；
- 只有这一关的靶子接口被**故意**放进 `CSRF_EXEMPT_PATHS` 豁免名单，
  用来演示"不校验会怎样"。豁免名单在 `security.py` 里，并且写明了
  **只给实验靶子用，平台接口任何时候都不准加进来**；
- 回归测试专门验证了这一点：靶子接口不带令牌能提交（200），
  而平台接口（恢复出厂）不带令牌照样 400。

**额外的教学点**：靶场的表单里其实**带了令牌**，但后端从来没看过它 ——
"加了但没校验"等于没加。页面上的「这次请求的四要素」表格
（Cookie / 令牌 / Referer / 请求体）把这件事摊开给你看。

---

# 九、上线安全基线清单

| 项目 | 状态 | 说明 |
|---|---|---|
| 关闭 debug 模式 | ✅ 已支持 | `MINISEC_DEBUG=0`；本地默认开（仅 127.0.0.1） |
| 密钥外置 | ✅ 已支持 | `MINISEC_SECRET_KEY`，默认值是开发专用 |
| 密码哈希存储 | ✅ 已完成 | `werkzeug.security`，不再存明文 |
| 靶子库与平台库隔离 | ✅ 已完成 | 见第六章 |
| 数据库一键重建 | ✅ 已完成 | `init_db.py` |
| 禁止搜索引擎收录 | ✅ 已完成 | base.html 里 `robots: noindex, nofollow` |
| 免责声明 | ✅ 已完成 | 全站页脚 |
| 靶场入口不强制注册 | 🟡 当前方案 | 共用演示账号 admin/123456，登录页已公示 |
| 限速防刷（保护 100 CPU 秒） | ✅ 已完成 | `ratelimit.py`：整站 150/分，登录 10/分，实验查询 40/分，恢复出厂 5/分 |
| `robots.txt` 文件 | ✅ 已完成 | 返回 `Disallow: /`，配合页面里的 `noindex` |
| CSRF 防护 | ✅ 已完成 | `security.py` 手写会话令牌，全站 POST 校验，拒绝页为双语 400 |
| 靶子数据"恢复出厂"入口 | ✅ 已完成 | 页面按钮 → `POST /labs/sql/reset`，只重建靶子库 |
| 生产入口保护 | ✅ 已完成 | `wsgi.py` 强制 `MINISEC_DEBUG=0`；没有密钥直接拒绝启动（fail closed） |
| 依赖可复现 | ✅ 已完成 | `requirements.txt`（venv 不进库，靠它重建环境） |
| 正式 WSGI 配置 | ✅ 模板已就绪 | `deploy/` 里有配置模板与部署指南；实际部署属阶段 2 |
| 命令注入沙箱 | ⬜ 远期 | 做那一关之前必须解决 |

---

# 十、测试

`smoke_test.py` 共 **166 项检查**，按关卡 + 平台基线分组：

1. **数据库结构**：平台库有 users/labs/progress；六个靶子库各自只有自己的表；
   任何靶子库里都没有平台表；靶子目录（uploads / lab_sandbox）存在
2. **登录与权限**：未登录跳转（含全部关卡页）、错误提示、正常登录、**平台登录对注入免疫**
3. **实验列表与关卡导航**：7 个实验全部可进入（一个「开发中」都没有）、进度徽标、
   关卡链接、未知 lab 404、未分关实验走占位页
4. **关卡页公共结构**：每个关卡都含后端代码 / 攻击分析 / 分层提示 / 实验说明
5. **SQL Level 1 / 2 / 3 行为**：注入通关、错误分支、判定不过严也不过松、
   UNION 列数错误专门提示、跨表读到 flag
6. **XSS Level 1 / 2 行为**：黑名单被绕过、事件属性命中、存储型落库、过滤前后对比
7. **文件上传行为**：真图片不判完成、黑名单后缀被拒、非图片文件绕过并落地、
   页面给出可访问 URL、账本记录
8. **SSRF 行为**：测试里临时起一个本地 HTTP 服务器当内部靶子
   （不依赖外网、也不要求网站先跑起来）；打到内网但无标记不算通关、
   非 http 协议被拒、连不上有提示
9. **命令注入行为**：正常诊断不判完成、追加命令读到 flag、执行历史落库、
   页面明确提示"真的会执行系统命令"
10. **越权访问行为**：列表只给自己的笔记、身份不变改 id 读到别人的数据、
   读到管理员私密笔记里的 flag、不存在的 id 有提示、非法身份参数被兜底
11. **CSRF 行为**：攻击者页面（自动提交 + 无令牌）、不带令牌也能提交并判通关、
   请求四要素展示、豁免是定向的（平台接口仍 400）、恢复出厂后邮箱复原
12. **通关进度 / 数据 / 恢复出厂 / 上线安全防护**：进度落库与徽标、
   各关恢复出厂互不影响且会清掉该关进度、`robots.txt`、CSRF 400、限速 429、
   平台账号始终不受影响

**约定：每次改动代码后都跑一次 `python smoke_test.py`，必须全 PASS。**

另有一个逐关验收脚本 `verify_levels.py`：一关一条命令，
每关跑「一个正例 + 一个反例」，并把输入 / 实际结果 / 判定打出来。
两者的分工是：`smoke_test` 保证"没改坏"，`verify_levels` 用来看"这一关判得对不对"。

```
python verify_levels.py           逐关跑一遍，最后给汇总
python verify_levels.py list      列出全部关卡编号
python verify_levels.py sql1      只验收某一关
```

---

# 十一、技术决策记录（为什么这么做）

| 决策 | 理由 |
|---|---|
| 平台库与靶子库分成两个文件 | 靶子注定被打穿，不能和平台账号住在一起（UNION 单语句即可跨表读） |
| 用 `init_db.py` 取代 5 个一次性脚本 | 那些脚本重复运行会插重复数据，且只建了 1 张表 → 删库就崩、换电脑就崩 |
| 数据库文件不进 git | 有了幂等重建脚本，数据完全由代码派生，不入库反而更干净 |
| 平台密码改存哈希 | 公网部署的基本要求；同时演示"平台自身是安全的"这一教学点 |
| 登录错误提示统一为"用户名或密码错误" | 不告诉攻击者用户名是否存在 |
| `EXPECTED_ROWS = 1` + 行数判定通关 | 判定标准客观可复现，不依赖关键词黑名单（黑名单只用于页面提示） |
| 未实现关卡显示"开发中"而不是死链 | 访客点出 404 会让项目显得半成品 |
| Level 2/3 清单暂时写在 Python 里 | 关卡还少，写进数据库属于过度设计；关卡变多后再入库 |
| 本地保留 `debug=True` | 本地开发方便且安全（只监听 127.0.0.1）；公网由环境变量关闭 |
| 靶子数据用弱口令 + 明文 | 教学需要：要让学习者直观看到"密码全泄露了" |
| 自己写 CSRF 与限速，不引第三方库 | 依赖越少越容易在免费平台上跑起来；逻辑本身很简单（会话令牌 + 内存计数），也是好教学素材 |
| 限速按 IP，默认不信任 `X-Forwarded-For` | 那个请求头访客能随便伪造，盲目相信等于给限速开后门 |
| 限速把 GET 也算进去 | 目的是保护 CPU 额度而不是只保护"危险操作"，页面渲染一样花 CPU |
| `wsgi.py` 没有密钥就拒绝启动（fail closed） | 宁可起不来，也不能带着公开源码里的开发密钥上网 |
| 恢复出厂只重建靶子库 | 访客的操作不该影响平台账号与实验目录（分库隔离的又一次体现） |
| **一关一个靶子库**（Level 2 用 `lab_login.db`） | 两关的假数据互不干扰；练习登录绕过不会搞乱 Level 1，恢复出厂也能一关一关地做 |
| **Level 2 通关判定 = “进了 admin 但不是合法凭据”** | 判定客观可复现，而且判的正是本关要教的东西：**绕过**密码，而不是**知道**密码。直接输入 `admin/admin123` 是正常登录，不该算通关 |
| Level 2 的密码框用普通文本框 | 方便学习者看清自己构造的 payload 长什么样；真实系统当然要用 `type="password"` |
| **关卡清单抽成 `curriculum.py`** | 清单要同时被关卡页、进度统计、恢复出厂、回归测试四处用到；写在四处，加一关就得改四遍，迟早漏 |
| **通关进度存平台库** | "哪几关打过了"是学习记录，属于平台数据；和靶子数据混在一起，一次恢复出厂就把记录抹了 |
| **判定一律看"事实"而不是"关键词"** | 返回的行数 / 是不是合法凭据 / 结果里有没有 flag / 磁盘上文件是不是图片 / 响应里有没有内部标记 —— 都不依赖黑名单写得全不全 |
| **新关卡共用 `lab_base.html`** | 五段式骨架对每一关都一样，抽出来之后每个新关卡只需要写"内容和差异"，模板从 500 行降到 200 行 |
| **XSS 关卡故意不禁用 JS** | 教学要让你真的看到弹窗；如果浏览器不执行，这一关就变成了"看代码想象" |
| **SSRF 的内部靶子放在本项目里** | 不依赖外网、不依赖第三方靶场，测试也能自己起一个临时服务器验证 |
| **命令注入关真的执行命令** | "模拟一个 shell"教不会任何东西；用沙箱目录 + 超时 + 输出截断限制爆炸半径，而不是靠过滤输入 |
| **`/internal/...` 故意不鉴权** | 真实内网服务常常就是这样（"反正只有内网能访问"）；给它加认证，SSRF 这一关的教学价值就没了 |
| **`requirements.txt` 只写 ASCII 注释** | pip 读取 requirements 文件用的是**系统区域编码**（中文 Windows 为 GBK，pip 只对 UTF-8 BOM 做特殊处理），UTF-8 中文注释会让 `pip install -r` 直接抛 `UnicodeDecodeError` —— **下载项目的人第一步就装不上依赖**。中文说明放在 README 与本文档里（实测踩到，见第十四章） |
| CSRF 令牌比较前先转成字节 | `compare_digest` 比较字符串时只接受 ASCII，非 ASCII 会抛异常变成 500（写测试时真踩到了） |

---

# 十二、约定（UI / 双语 / 教学 / 协作）

## UI 风格

关键词：Security Tool / Technical Documentation / Cyber Lab（类似 Kali、Burp Suite、HTB）。

- **避免**：大量小卡片堆叠、花哨渐变、商业 SaaS 风
- **采用**：大区域布局、横向分割线、技术文档感、简洁深色安全工具风
- 配色：`#0f172a` 底 / `#020617` 深底 / `#111827` 面板 / `#334155` 分割线 / `#2563eb` 强调

实验页布局：标题区 → 实验说明 → `----` → 左（操作/输入/结果）| 右（Backend Code /
Generated SQL / Attack Analysis / Hint）→ `----` → 漏洞与修复 → 实验总结。

## 双语要求

所有网页内容中英成对出现，不只写中文。

## 教学设计原则（每个 Level 必须包含五段）

Background 原理 → Laboratory 操作 → Analysis 分析 → Vulnerability 成因 → Fix 修复。

## 协作与代码习惯

- 默认中文回复，技术名词保留英文；按阶段推进，不跳跃，不提前设计大量未来功能
- 修改代码时给出**完整文件**，保持现有结构，并解释修改原因
- 教学代码故意保留明文密码与错误详情，标注"教学性故意"即可，不在本阶段加固
- 每次改完运行 `python smoke_test.py`

---

# 十三、下一步计划

| 阶段 | 内容 | 状态 |
|---|---|---|
| 阶段 0 | 数据库分库 + 一键重建、Level 1 封版、代码卫生、提交存档 | ✅ 完成 |
| 阶段 1 | 可上线改造：限速、`robots.txt`、CSRF、恢复出厂入口、生产入口与部署文档 | ✅ 完成 |
| 阶段 2 | 部署到 PythonAnywhere，拿到真实网址并手机验证 | ❌ **已决定不做**（2026-09-19） |
| 阶段 3 | 写门面站（含纯前端注入演示）+ 打开 GitHub Pages | ❌ **已决定不做**（2026-09-19） |
| 阶段 4 | Level 2 登录绕过（独立靶子库 `lab_login.db`） | ✅ 完成 |
| 阶段 5 | Level 3 UNION 查询 | ✅ 完成 |
| 阶段 6 | 横向扩展 XSS×2 / File Upload / SSRF / Command Injection | ✅ 完成 |
| 阶段 7 | 通关进度记录 + 关卡目录单一数据源 + 关卡页基模板 | ✅ 完成 |
| 阶段 8 | 越权访问实验（水平越权 / IDOR） | ✅ 完成 |
| 阶段 9 | CSRF 实验（含模拟攻击者页面 + 定向豁免名单） | ✅ 完成 |
| 阶段 10 | 代码整洁：SQL L1/L2 页面迁移到 `lab_base.html` | ✅ 完成 |

> **关于阶段 2 / 3 的决定（2026-09-19）**：本项目的用途是能力证明与面试展示，
> 不会有真实用户访问，因此不做公网部署与门面站。
> 部署方案（`deploy/DEPLOY.md`）与生产环境安全加固（关闭调试、密钥外置、fail-closed、
> 靶子数据隔离、限速、CSRF）都已经完成并保留——面试时讲的是这套**设计与取舍**，
> 而不是“我有一个网址”。需要时随时可以按文档上线。

---

# 十四、已知问题清单

**已解决（阶段 0）**：数据库无法从零重建、venv 与缓存进版本库、无 .gitignore、
Level 2/3 死链、`lab.english` 渲染空白、`labs.py` 里的死代码、无实验总结、
提示只在通关后出现、结果未表格化、平台密码明文、密钥硬编码。

**已解决（阶段 1）**：无限速、无 `robots.txt`、无 CSRF 防护、没有恢复出厂入口、
没有生产入口保护、没有依赖清单、错误页是默认英文页。

**已解决（阶段 5，真踩到的坑）**：`requirements.txt` 里写了中文注释，
导致**中文 Windows 上 `pip install -r requirements.txt` 直接崩溃**
（`UnicodeDecodeError: 'gbk' codec can't decode byte`）。
这个 bug 只有在「干净克隆一份 → 从零建 venv → 真的去装依赖」时才会暴露，
在自己已经装好依赖的开发机上永远看不到。已改为纯 ASCII 注释。

**仍待处理**：

1. `auth.py` 的 `login_required` 只判断 `session["username"]` 是否存在，
   没有做会话过期时间（远期可加）
2. 实验完成状态不持久化（刷新即重置）——属"学习进度记录"功能，远期再做
3. 关键词特征库较简单（只认单引号、`--`、`OR/AND/UNION`、`=`）；
   目前只用于页面提示，不影响通关判定，做 Level 3 时需要扩充
4. 限速计数存在内存里，只在单进程下准确（免费托管只有一个 worker，够用；
   将来扩容需要换成共享存储）
5. 没有部署过，且已决定不做（理由见第十三章）；`deploy/DEPLOY.md` 与 `wsgi.py` 已经就绪，
   真需要上线时按文档走一遍即可
7. 命令注入关只在 Windows 上实测过（`&` 与 `type`）；Linux 分支写了 `;` 与 `cat`
   但没有真机验证
8. `labs` 表里保留着 `status` 字段和「开发中」徽标的分支，但**当前 7 个实验
   全部是 ready** —— 这套机制留给以后新增实验用（新增实验只要往 `labs` 表加一行，
   没做好的会显示"开发中"而不是给一个死链接）。
   同时 `templates/lab.html`（无分关实验的占位页）目前也处于"备用未使用"状态。
