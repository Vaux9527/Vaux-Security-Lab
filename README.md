# MiniSec Vulnerability Lab

> **MiniSec is a Chinese-language web security teaching lab covering 6 vulnerability classes across 10 hands-on levels. Every level walks the same five stages: principle → hands-on → analysis → root cause → fix.**
>
> MiniSec 是一个中文 Web 安全教学靶场，覆盖 6 类漏洞共 10 个关卡，每一关都走完「原理 → 操作 → 分析 → 成因 → 修复」五段。

**版本: v1.0**（7 个实验 / 10 个关卡全部可用） · Python 3.9+ / Flask 3.1 · Windows / macOS / Linux 均可运行
（仅依赖 Flask 与 Werkzeug 两个包；无前端框架、无 JS 构建、无需联网、无需任何 API key）

---

## 定位

靶场负责**把漏洞真的复现出来、把看不见的东西变成看得见的**；人负责理解原理、举一反三。

```text
打开一个关卡
    ↓
读背景原理 → 观察「后端代码」与「实际执行的语句/渲染出的 HTML/执行的命令」
    ↓
在靶子上真的打一次（SQL 真的执行、脚本真的弹窗、命令真的在系统上跑）
    ↓
页面解释：这次为什么成功/为什么没成功
    ↓
通关后给完整的「漏洞代码 vs 修复代码」对照 + 实验总结
```

每一关都提供三样东西：**可打的靶子**、**可观察的证据**、**可复制的修复写法**。

**判定看事实，不看关键词** —— 判的是数据库/磁盘/网络里真实发生了什么，不是"你输入里有没有某个词"。
所以用黑名单外的手法绕过时，判定依然正确。

## 下载后先读：你需要自己准备什么

这个仓库里**只有源码**——没有虚拟环境、没有数据库文件、没有任何依赖的副本。
这是故意的（`venv/` 有 22 MB、1800 多个文件，不该进版本库），所以下面这些东西**要你自己准备**：

| 要准备什么 | 必须？ | 怎么弄 |
|---|---|---|
| **Python 3.9 或更高** | ✅ **唯一需要你手动安装的东西** | [python.org/downloads](https://www.python.org/downloads/) 下载安装。<br>**Windows 安装时务必勾选 `Add Python to PATH`** |
| **Flask / Werkzeug**（两个包） | ✅ 由 pip 自动装 | 一条命令 `pip install -r requirements.txt`（见步骤 3） |
| **虚拟环境 `venv/`** | ✅ 一条命令生成 | `python -m venv venv`（见步骤 2）。仓库里**没有**这个目录 |
| 数据库 | ❌ 不需要 | SQLite 单文件，由 `init_db.py` 从零生成，不用装任何数据库服务 |
| Docker / Node.js / 任何 API key | ❌ 不需要 | —— |
| 联网 | 只在装依赖时需要 | 装完之后完全离线可玩 |

先确认 Python 装好了：

```bash
python --version        # Windows
python3 --version       # macOS / Linux
```

输出 `Python 3.9.x` 或更高就没问题（本项目在 3.10.9 上开发）。
如果提示"找不到命令"，回到上面那一步：Windows 重装 Python 时**勾选 `Add Python to PATH`**。

## 快速开始

### 从零到跑起来：四步

**第 1 步 · 下载代码**

```bash
git clone https://github.com/Vaux9527/Vaux-Security-Lab.git
cd Vaux-Security-Lab/MiniSec
```

> 不想用 git 也行：仓库页面点 **Code → Download ZIP**，解压后进 `MiniSec` 目录，后面完全一样。

**第 2 步 · 建虚拟环境**（仓库里没有这个目录，需要你自己生成）

```bash
python -m venv venv
```

> macOS / Linux 若提示 `python: command not found`，把 `python` 换成 `python3`。
> 预期结果：`MiniSec/` 下出现一个 `venv/` 目录（约 22 MB，这是它不该进仓库的原因）。

**第 3 步 · 装依赖**

```powershell
# Windows（PowerShell）
.\venv\Scripts\python.exe -m pip install -r requirements.txt
```

```bash
# macOS / Linux
./venv/bin/python -m pip install -r requirements.txt
```

> 预期最后一行：`Successfully installed Flask-3.1.3 Werkzeug-3.1.8`
> 国内网络慢的话加镜像：`-i https://pypi.tuna.tsinghua.edu.cn/simple`

**第 4 步 · 建库并启动**

```powershell
# Windows
.\venv\Scripts\python.exe init_db.py     # 建数据库（幂等，可重复运行）
.\venv\Scripts\python.exe app.py         # 启动
```

```bash
# macOS / Linux
./venv/bin/python init_db.py
./venv/bin/python app.py
```

> 预期输出：`Running on http://127.0.0.1:5001`
> 然后浏览器打开 <http://127.0.0.1:5001>，用 **`admin` / `123456`** 登录，进「漏洞实验」挑一关开始。

**（可选）第 5 步 · 确认一切正常**

```bash
.\venv\Scripts\python.exe smoke_test.py     # 应输出 All smoke checks passed.（166 项）
```

### 打不开 / 装不上？

| 现象 | 原因与解法 |
|---|---|
| `python: command not found` | Python 没装，或装的时候没勾 `Add Python to PATH` |
| `pip install` 报 `UnicodeDecodeError` | 你往 `requirements.txt` 里加了中文注释。pip 用系统区域编码读这个文件（中文 Windows 是 GBK），**必须保持纯 ASCII** |
| `ModuleNotFoundError: No module named 'flask'` | 虚拟环境没建，或依赖没装成功（回到步骤 2、3），或你用的是系统 Python 而不是 `./venv/bin/python` |
| 端口 5001 被占用 | `$env:MINISEC_PORT=5002`（Win）/ `MINISEC_PORT=5002 ./venv/bin/python app.py`（Unix） |
| 页面样式不对 / 404 | 确认是在 `MiniSec/` 目录下启动的 |
| 想推倒重来 | `python init_db.py --reset`，然后重跑 `app.py` |

更多问题见下面的 [常见问题](#常见问题)。

> **只监听 127.0.0.1**：只有你自己的机器能访问，同事/同学连不上 —— 这是故意的，安全。
> 想换端口用 `MINISEC_PORT`（见 [环境要求](#环境要求)）。

---

### 逐关验收（改代码后推荐先跑这个）

```bash
.\venv\Scripts\python.exe verify_levels.py          # 10 关全跑：每关一个正例 + 一个反例
.\venv\Scripts\python.exe verify_levels.py list     # 列出全部关卡编号
.\venv\Scripts\python.exe verify_levels.py csrf     # 只验收某一关
```

每一关都跑「**一个正例 + 一个反例**」：正例必须通关、反例必须不通关。
两边都对，才说明这一关的判定既不过松、也不过严。

### 回归测试

```bash
.\venv\Scripts\python.exe smoke_test.py             # 166 项，应输出 All smoke checks passed.
```

---

## 怎么用

### 1. 进站

打开 <http://127.0.0.1:5001> → 用 `admin` / `123456` 登录 → 点「漏洞实验」。

首页和实验列表都会显示**总进度**（例如 `已通关 3 / 10 关`），每个实验旁边标注自己通关了几关。

### 2. 每个关卡页面的布局

```text
┌─ 标题区：关卡名 / 难度 / 本关目标 / 通关判定规则
│
├─ 实验说明：这一关的漏洞是什么、怎么算通关
│
├─ 左栏 实验区域                    右栏 分析区域
│   ├─ 操作表单（输入 payload）      ├─ Backend Code   后端真正执行的代码
│   ├─ 恢复实验数据 按钮             ├─ 关键证据        实际执行的 SQL / 渲染出的 HTML /
│   ├─ 通关横幅（成功后出现）        │                实际执行的命令 / 保存的文件
│   └─ 查询结果 / 输出 / 表格        ├─ Attack Analysis 这次为什么成功 / 为什么没成功
│                                   └─ Hint 提示      3 级分层提示（逐级展开）
│
├─ 通关后：漏洞与修复（坏代码 vs 参数化/白名单/令牌的对照）
└─ 通关后：实验总结（成因 / 手法 / 危害 / 修复 + 一句口诀 + 下一关预告）
```

### 3. 卡住了怎么办

1. **先自己想一分钟** —— 每关的目标和判定规则都写在页面上；
2. **展开分层提示** —— 3 级，从"看什么"到"怎么做"；
3. **看右栏的「关键证据」** —— 你输入之后 SQL 变成什么样、HTML 里出现了什么，全都在那儿；
4. （XSS 两关额外有）**「可执行结构速查表」** —— 五类能执行 JS 的写法 + 各自原理。

> 判定失败时页面会解释原因。比如登录绕过那关你输入 `alice' --`：
> 不会只说"没通关"，而是告诉你"你确实绕过了密码，只是本关要的是 admin"。

### 4. 数据搞乱了 / 想从头再练

- **单关恢复**：每个关卡页上都有「恢复实验数据」按钮，只重建**这一关**的靶子；
- **全部重置**：`python init_db.py --reset`（所有靶子恢复出厂，通关进度也清零）。

一关一个靶子库，所以重置某一关不会影响别的关，更不会碰平台账号。

### 5. 通关判定长什么样（10 关一览）

| # | 实验 | 关卡 | 标准 payload | 通关判定（看事实） |
|---|---|---|---|---|
| 1 | SQL 注入 | Level 1 基础查询注入 | `admin' OR '1'='1' --` | 查询实际返回行数 > 1 |
| 2 | SQL 注入 | Level 2 登录绕过 | 用户名 `admin' --`，密码随意 | 进了 admin，且提交的不是一组合法凭据 |
| 3 | SQL 注入 | Level 3 UNION 查询 | `' UNION SELECT id, title, content, 'x' FROM secret_notes --` | 结果里出现内部表的 flag |
| 4 | XSS | Level 1 反射型 | `<script>alert(1)</script>` | 回显 HTML 里存在**可执行结构** |
| 5 | XSS | Level 2 存储型 | 留言 `<img src=x onerror=alert(1)>` | 数据库里存在可执行留言 |
| 6 | 文件上传 | Level 1 | 上传一个 `note.html` | 保存成功，且**文件头不是图片** |
| 7 | SSRF | Level 1 | `http://127.0.0.1:5001/internal/admin-config` | 目标是**内网地址**且响应含内部标记 |
| 8 | 命令注入 | Level 1 | `127.0.0.1 & type secret.txt`（Win）<br>`127.0.0.1; cat secret.txt`（Unix） | 输出里出现沙箱 flag |
| 9 | 越权访问 | Level 1 水平越权 | 保持 `as=1`，改 `note_id=6` | 读到**归属不是自己**的笔记 |
| 10 | CSRF | Level 1 跨站请求伪造 | 打开关卡里的「攻击者页面」 | 数据库里的邮箱变成攻击者地址 |

> 每关的 payload 都可以在**地址栏里直接试**，例如：
> `/labs/xss/level1?q=<script>alert(1)</script>` 或 `/labs/idor/level1?as=1&note_id=6`

---

## 关卡清单（含靶子与教学点）

| # | 实验 | 靶子 | 教学点 |
|---|---|---|---|
| 1 | SQL 注入 · 基础查询注入 | `lab_sql.db` / `sql_users` | 字符串拼接让数据变成代码 |
| 2 | SQL 注入 · 登录绕过 | `lab_login.db` / `login_users` | 认证不该写进 SQL 条件里 |
| 3 | SQL 注入 · UNION 查询 | `lab_union.db` / `secret_notes` | 列数探测 + 跨表读取 + 最小权限 |
| 4 | XSS · 反射型 | 无状态（搜索回显） | 输入进 HTML 就等于代码 |
| 5 | XSS · 存储型 | `lab_xss.db` / `xss_guestbook` | 黑名单挡不住 + 一次注入所有访客中招 |
| 6 | 文件上传 | `static/uploads/`（web 可直接访问） | 后缀黑名单 vs 文件头校验 |
| 7 | SSRF | `/internal/...` 内部接口（故意不鉴权） | 服务器的网络位置是一种权限 |
| 8 | 命令注入 | `lab_sandbox/`（含目标文件 secret.txt） | 拼命令 + shell = 交出 shell |
| 9 | 越权访问 | `lab_idor.db` / `idor_notes` | 认证 ≠ 授权（OWASP 第一名） |
| 10 | CSRF | `lab_csrf.db` / `csrf_users` + 模拟攻击者页面 | Cookie 只证明你是谁，不证明请求是你发的 |

---

## 输出示例

`smoke_test.py`（166 项回归测试；这里只截取开头与结尾）：

```text
== 数据库结构：平台库与六个靶子库必须分开 ==
  PASS  平台库包含 users / labs / progress
  PASS  Level 1 靶子库只有 sql_users
  PASS  Level 2 靶子库只有 login_users
  ...
== CSRF 跨站请求伪造 ==
  PASS  以 victim 身份进入，邮箱是原值
  PASS  页面讲清关键事实：Cookie 是浏览器自动带的
  PASS  正常改邮箱：能改成，但不判通关
  PASS  攻击者页面：自动提交表单 + 指向靶子接口 + 不带令牌
  PASS  不带令牌的请求照样改成功：判通关
  PASS  豁免是定向的：平台接口（恢复出厂）仍然要求令牌（400）
== 靶场自身不泄漏平台数据 ==
  PASS  关卡页面不暴露平台库路径
  PASS  页面有免责声明

All smoke checks passed.
```

`verify_levels.py`（逐关验收，每关一个正例 + 一个反例）：

```text
──────────────────────────────────────────────────────────────────
【SQL Level 1　基础查询注入】
  浏览器复核： http://127.0.0.1:5001/labs/sql/level1

  ✅ 正例　用户名 = admin' OR '1'='1' --
      预期：出现 LEVEL 1 COMPLETED，结果表 4 行、多出来的高亮
  ✅ 反例　用户名 = bob' --
      预期：命中注入特征，但不判通关（只返回 1 行）

  结论：✅ 通过
──────────────────────────────────────────────────────────────────
...
  通过 10 / 10 关
```

`init_db.py --show`（打印每个库里现在有什么）：

```text
====================
平台库 platform.db -> E:\Vaux-Security-Lab\MiniSec\platform.db
====================

-- labs (7 行) --
   列: id, name, title, title_en, description, description_en, status, entry_url
    (1, 'sql', 'SQL注入实验', 'SQL Injection Lab', ...)

-- progress (3 行) --
   列: id, lab, level, cleared_at
    (1, 'sql', 1, '2026-09-19T15:04:11')
```

---

## 架构

```text
浏览器
  │  ① 表单提交（带 CSRF 令牌）/ 地址栏 payload
  ▼
app.py（入口）+ security.py（全站令牌校验）+ ratelimit.py（每 IP 限速）
  │  ② 除 CSRF 实验的靶子接口外，所有 POST 都必须带令牌
  ▼
routes/  8 个蓝图
  ├── labs.py       实验列表 + 关卡列表（含通关进度）
  ├── sql_lab.py    Level 1 / 2 / 3
  ├── xss_lab.py    Level 1 / 2
  ├── upload_lab.py · ssrf_lab.py · cmdi_lab.py · idor_lab.py · csrf_lab.py
  │  ③ 每个关卡：读输入 → 拼进"故意有漏洞"的代码 → 执行 → 判定 → 记录进度
  ▼
database.py  分库连接
  ├── platform.db   平台数据（账号 / 实验目录 / 通关进度）← 永远不碰
  └── lab_*.db      8 个靶子库 + 2 个靶子目录 ← 随便打，可随时重建
  │  ④ 判定依据全部来自这里真实执行的结果
  ▼
progress.py  通关进度记录（平台库）  ·  curriculum.py  关卡清单（唯一数据源）
```

### 核心模块

| 模块 | 职责 |
|---|---|
| `curriculum.py` | **关卡清单的唯一来源**：关卡列表、总数、按实验查找。加一关只改这里 |
| `progress.py` | 通关进度：落库、查询、重置某一关时连带清除 |
| `security.py` | CSRF 令牌防护（手写，不依赖第三方库）+ **靶子定向豁免名单** |
| `ratelimit.py` | 每 IP 限速（内存计数，单进程够用） |
| `init_db.py` | 数据库 / 靶子目录**一键幂等重建**，靶子不进版本库 |
| `database.py` | 平台库与靶子库分开连接，缺库时自动建 |
| `lab_base.html` | **关卡页公共骨架**：9 个关卡页都继承它，每关模板只写差异（约 200 行） |

### 关键机制

**判定看事实** — 每关判定都基于真实执行结果：返回行数、凭据合法性、结果里有没有 flag、
磁盘文件的文件头、解析出的 IP 是不是内网、输出里有没有沙箱文件内容、数据归属是否匹配身份。
没有一关依赖关键词黑名单。

**一关一库** — 每个关卡有自己的靶子库（或靶子目录）。理由是：
① 各关假数据互不干扰；② 可以一关一关地恢复出厂；
③ 靶子注定被打穿，绝不能和平台账号同库（UNION 一条语句就能读走同库的表）。

**平台安全 vs 靶子故意不安全** — 平台自身全程参数化查询、哈希存密码、
无密钥拒绝启动（fail closed）；只有靶子故意留洞。CSRF 那一关最能说明：
靶子接口被放进 `security.py` 的豁免名单，名单里写明**只给实验靶子用**，
而回归测试专门验证"靶子不带令牌能过、平台接口不带令牌 400"。

**把看不见的变成看得见的** — SQL 关卡显示「实际执行的语句」，
XSS 关卡显示「渲染进页面的 HTML」，命令注入显示「实际执行的完整命令」，
上传显示「保存路径 + 文件头字节 + 访问地址」，SSRF 显示「服务端实际发出的请求」。

**靶子是"代码派生"的** — `*.db`、`static/uploads/`、`lab_sandbox/` 全部不进版本库，
由 `init_db.py` 从零生成。换一台电脑 clone 下来跑一条命令就能开工。

---

## 目录结构

```text
Vaux-Security-Lab/
├── README.md                   本文件
└── MiniSec/
    ├── app.py                  入口：登录 / 首页 / robots.txt / 内部接口 / 错误页
    ├── config.py               配置中心（全部可用环境变量覆盖，见下）
    ├── curriculum.py           ⭐ 关卡清单唯一数据源
    ├── progress.py             ⭐ 通关进度记录
    ├── database.py             平台库 / 靶子库分开连接
    ├── security.py             ⭐ CSRF 令牌防护 + 靶子豁免名单
    ├── ratelimit.py            每 IP 限速
    ├── init_db.py              数据库与靶子目录一键重建（--reset / --show）
    ├── auth.py                 登录校验装饰器
    ├── smoke_test.py           ⭐ 回归测试 166 项
    ├── verify_levels.py        ⭐ 逐关验收（正例 + 反例）
    ├── wsgi.py                 生产入口（本地不用；无密钥拒绝启动）
    ├── routes/                 8 个蓝图：实验列表 + 7 个实验
    ├── templates/              20 个模板（含 lab_base.html 骨架与 XSS 速查表）
    ├── static/
    │   ├── style.css           深色安全工具风主题
    │   └── uploads/            【生成物·不进库】文件上传关的靶子目录
    ├── lab_sandbox/            【生成物·不进库】命令注入关的工作目录
    ├── deploy/DEPLOY.md        上线方案（当前不用，保留备用）
    └── PROJECT_CONTEXT.md      ⭐ 权威设计文档：理念 / 决策记录 / 已知问题
```

> 想了解"为什么这么设计、每个决策的取舍、踩过哪些坑"，看
> **[MiniSec/PROJECT_CONTEXT.md](MiniSec/PROJECT_CONTEXT.md)** —— 那才是这个项目的主文档。

---

## 设计原则

1. **五段式** — 每关必须有背景、操作、分析、成因、修复，缺一段不算做完
2. **判定看事实** — 判真实执行结果，不判输入里有没有关键词
3. **一关一库** — 靶子彼此隔离，也和平台数据隔离
4. **平台自身安全** — 参数化查询、哈希密码、CSRF 令牌、限速、fail closed
5. **把看不见的变成看得见的** — 展示实际执行的语句 / 渲染的 HTML / 执行的命令
6. **分层提示，不直接给答案** — 3 级提示 + 招式表（讲原理与类别，不替你选）
7. **失败也要解释原因** — "绕过了密码但进的是别人"要说清楚
8. **靶子可重建** — 数据库与靶子目录不进版本库，一条命令从零生成
9. **公共骨架复用** — 9 个关卡页共用一套模板骨架
10. **诚实边界** — 已知限制写进 README 与项目文档，不假装完整

---

## 测试

| 脚本 | 作用 | 规模 |
|---|---|---|
| `smoke_test.py` | 回归测试：改完代码跑它，确认没改坏东西 | **166 项** |
| `verify_levels.py` | 逐关验收：一关一条命令，打给你看每关判得对不对 | **10 关 × (正例 + 反例)** |

`smoke_test.py` 的覆盖范围：

| 分组 | 内容 |
|---|---|
| 数据库结构 | 平台库 / 8 个靶子库 / 靶子目录，彼此不含对方的表 |
| 登录与权限 | 未登录跳转、错误提示、**平台登录对注入免疫** |
| 实验列表与导航 | 7 个实验全部可进入、进度徽标、404 处理 |
| 关卡页公共结构 | 每关都含后端代码 / 攻击分析 / 分层提示 |
| 10 个关卡各一组 | 正例通关、错误分支、判定不过松也不过严 |
| 通关进度 | 落库、徽标、恢复出厂会清掉该关进度 |
| 上线安全防护 | `robots.txt`、CSRF 400、限速 429 |
| 分库隔离 | 任何操作都不影响平台账号 |

> SSRF 那一组会**临时起一个本地 HTTP 服务器**当「内部靶子」——
> 所以测试不联网也能跑，也不要求先把网站启动起来。

---

## 版本路线

| 阶段 | 主题 | 内容 |
|---|---|---|
| 0 ✅ | 地基 | 数据库分库 + 一键幂等重建、Level 1 封版、代码卫生 |
| 1 ✅ | 可上线改造 | 限速、`robots.txt`、CSRF 令牌、恢复出厂入口、生产入口（fail closed）、部署文档 |
| 2 ✅ | SQL 关卡补齐 | Level 2 登录绕过（独立靶子库）、Level 3 UNION（列数探测教学） |
| 3 ✅ | 横向扩展 | XSS 反射型 / 存储型、文件上传、SSRF、命令注入（真执行 + 沙箱） |
| 4 ✅ | 越权与 CSRF | 水平越权（IDOR）、CSRF（模拟攻击者页面 + 定向豁免名单） |
| 5 ✅ | 工程化收尾 | 通关进度记录、关卡清单单一数据源、关卡页公共骨架、166 项回归测试 + 逐关验收脚本 |

---

## 环境要求

- **Python 3.9+**（开发环境 3.10.9）
- **Python 依赖只有两个**：`Flask==3.1.3`、`Werkzeug==3.1.8`（见 `requirements.txt`）
- **不需要**：数据库服务、Docker、Node.js、任何 API key、联网
- 操作系统：Windows / macOS / Linux（命令注入关的 payload 按平台自动切换）

### 全部可用环境变量（都有默认值，不设也能跑）

| 变量 | 默认 | 作用 |
|---|---|---|
| `MINISEC_PORT` | `5001` | 本地端口 |
| `MINISEC_DEBUG` | `1` | 调试模式；公网部署必须设 `0` |
| `MINISEC_SECRET_KEY` | 开发占位值 | 会话签名密钥；`wsgi.py` 下不设会**拒绝启动** |
| `MINISEC_PLATFORM_DB` | `platform.db` | 平台库位置 |
| `MINISEC_LAB_<实验名>_DB` | `lab_*.db` | 某个靶子库的位置 |
| `MINISEC_UPLOAD_DIR` | `static/uploads/` | 文件上传关的靶子目录 |
| `MINISEC_SANDBOX_DIR` | `lab_sandbox/` | 命令注入关的工作目录 |
| `MINISEC_SSRF_ALLOW_EXTERNAL` | `1` | 设 `0` 则 SSRF 关只允许请求本机 |
| `MINISEC_RATE_LIMIT` | `1` | 设 `0` 关闭限速（本地想狂刷时用） |
| `MINISEC_TRUST_PROXY` | `0` | 在可信代理后才设 `1`（否则限速可被伪造头绕过） |

---

## 常见问题

**Q：5001 端口被占用了？**

```bash
# Windows
$env:MINISEC_PORT=5002; .\venv\Scripts\python.exe app.py
# macOS / Linux
MINISEC_PORT=5002 ./venv/bin/python app.py
```

**Q：XSS 关卡没弹窗？**

XSS 要在**真实浏览器**里打才会弹（`smoke_test.py` 用的是测试客户端，不执行 JS）。
如果浏览器里也没弹：确认没装屏蔽脚本的扩展、地址栏 payload 有没有被浏览器转义
（用页面上的输入框提交更保险）。

**Q：命令注入关在我这儿执行不了？**

- Windows 用 `&` 分隔：`127.0.0.1 & type secret.txt`
- macOS / Linux 用 `;` 分隔：`127.0.0.1; cat secret.txt`
- 页面上的提示会按你的系统自动显示对应写法。
- 该关**真的会执行系统命令**，工作目录被固定在 `lab_sandbox/`、3 秒超时、输出截断 4000 字符。

**Q：`pip install -r requirements.txt` 报 `UnicodeDecodeError`？**

这是本项目在中文 Windows 上真踩过的坑：pip 读取 requirements 文件时用的是
**系统区域编码**（中文 Windows 是 GBK，pip 只对 UTF-8 BOM 做特殊处理），
所以文件里只要有 UTF-8 中文注释，`pip install -r` 会在装任何东西之前就崩掉——
下载项目的人**第一步就装不上依赖**。

因此 `MiniSec/requirements.txt` **刻意只写 ASCII 注释**（原因也写在文件里）。
如果你自己往里加中文注释，就会重现这个错误。

**Q：我想把进度清零、从头再练？**

`python init_db.py --reset`（所有靶子恢复出厂 + 通关进度清零）。
只想重置一关，用关卡页上的「恢复实验数据」按钮。

**Q：上传的文件、沙箱里生成的文件在哪？**

`MiniSec/static/uploads/` 与 `MiniSec/lab_sandbox/`，两个目录都不进版本库，
被 `.gitignore` 排除，随时可以删掉重新生成。

**Q：改完代码要跑什么？**

```bash
.\venv\Scripts\python.exe smoke_test.py     # 必须全 PASS
.\venv\Scripts\python.exe verify_levels.py  # 受影响的那几关
```

**Q：能放到公网上给别人玩吗？**

技术上可以（`deploy/DEPLOY.md` 里写好了免费方案与生产加固），但**本项目的决定是不上线**：
它用于能力证明与面试展示，不会有真实用户访问。
更重要的是——**命令注入关真的会执行系统命令**，公网上跑等于给陌生人一个 shell。

---

## 已知限制

诚实列出来，避免误解：

1. **不打算上线**（见上面 FAQ）。部署方案与生产加固都已写好并保留，需要时按文档走一遍即可。
2. **命令注入关只在 Windows 上实测过**（`&` + `type`）；macOS / Linux 分支写了 `;` + `cat`，但没有真机验证。
3. **限速计数存在内存里**，只在单进程下准确（本地靶场够用）。
4. **登录会话没有过期时间**（本地教学场景可以接受）。
5. `labs` 表里保留了 `status` 字段与「开发中」徽标分支，**当前 7 个实验全部可用** ——
   这套机制留给以后新增实验：没做完的会显示"开发中"而不是给一个死链接。

---

## 免责声明

本项目**只用于网络安全教学**。所有漏洞都是刻意保留的，且只存在于隔离的实验靶子数据里。

- 请只在**自己的机器**上运行（默认只监听 `127.0.0.1`）；
- **命令注入关会真的执行系统命令**，请勿在不受控的环境里运行；
- **绝不要**把这里的技术用于攻击你没有获得授权的系统。

---

## 后续想做的方向（不是待办清单）

- 更多关卡类型：XXE、JWT 与会话安全、逻辑漏洞（支付 / 优惠券）
- 把这个靶场当作被测目标，写一个自动化漏洞扫描脚本 ——
  让项目从"教学平台"升级成"安全工具的开发底座"
- 通关进度的可视化统计（现在有总进度，可以做得更细）
- 仓库里的下一个方向：AI 安全自学笔记（LLM 应用的攻击面与防御）
