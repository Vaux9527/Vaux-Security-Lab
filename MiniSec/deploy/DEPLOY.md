# MiniSec 上线部署指南

> ⚠️ **本方案当前不使用**（2026-09-19 决定）：MiniSec 用于能力证明与面试展示，
> 不会有真实用户访问，因此**不做公网部署、不做门面站**。
> 这份文档与 `wsgi.py`、生产环境加固一起保留备用 —— 真需要上线时按本文档走一遍即可。
> 决定不上的原因见 `PROJECT_CONTEXT.md` 第十三章。

> 目标：把 MiniSec 部署成"公网可访问的在线靶场"，同时保留一个静态门面站。
> 方案（路线 C）：**门面站放 GitHub Pages，真靶场放 PythonAnywhere 免费版**。
>
> 为什么不直接把现在的代码放上 GitHub Pages：
> GitHub Pages 只能托管静态文件，不能运行 Python/Flask/数据库，
> 而 SQL 注入演示必须由服务器执行 SQL —— 两者性质不同。

---

## 0. 上线前先做这三件事（本地）

```powershell
cd <你 clone 下来的仓库路径>\MiniSec      # 例如 E:\Vaux-Security-Lab\MiniSec

# 1) 确认回归测试全绿（应为 166 项 PASS）
.\venv\Scripts\python.exe smoke_test.py

# 2) 确认生产入口的保护生效：不给密钥应当拒绝启动
.\venv\Scripts\python.exe -c "import wsgi"
#    预期：RuntimeError: 拒绝启动：公网部署必须先设置环境变量 MINISEC_SECRET_KEY

# 3) 生成一个随机密钥，记下来，第 3 步要用
.\venv\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(48))"
```

---

## 1. 把代码推到 GitHub

仓库地址：<https://github.com/Vaux9527/Vaux-Security-Lab>

```powershell
cd E:\Vaux-Security-Lab
git status          # 确认没有未提交的改动
git push            # 推到 GitHub（PythonAnywhere 会从这里拉代码）
```

> 注意：仓库是公开的，所以**代码里不能有任何真密钥**。
> 我们的做法是：代码里只有开发用占位密钥，生产密钥通过环境变量传入，
> 而且没传密钥时 `wsgi.py` 会直接拒绝启动。

---

## 2. 在 PythonAnywhere 拉代码并建库

1. 注册免费账号：<https://www.pythonanywhere.com> （Beginner 免费版，不需要信用卡）
2. 右上角 **Consoles → Bash** 打开一个命令行，依次执行：

```bash
# 拉代码
git clone https://github.com/Vaux9527/Vaux-Security-Lab.git

# 建虚拟环境（如果提示 python3.10 不存在，换成 python3.12 等，
# Flask 3.1 支持 Python 3.9 以上）
mkvirtualenv --python=/usr/bin/python3.10 minisec

# 装依赖
pip install -r ~/Vaux-Security-Lab/MiniSec/requirements.txt

# 建数据库并查看结果
cd ~/Vaux-Security-Lab/MiniSec
python init_db.py --show
```

---

## 3. 配置 Web 应用

1. 顶部 **Web** 标签 → **Add a new web app** → **Manual configuration** → 选同一个 Python 版本
2. 填两个路径：
   - **Source code**：`/home/你的用户名/Vaux-Security-Lab/MiniSec`
   - **Working directory**：`/home/你的用户名/Vaux-Security-Lab/MiniSec`
3. 点 **WSGI configuration file** 那个链接，把编辑框里的内容**全部删掉**，
   换成 `deploy/pythonanywhere_wsgi.py` 的内容，并改这三处：
   - `YOURNAME` → 你的用户名
   - `Vaux-Security-Lab` → 仓库目录名（用 `ls ~` 确认）
   - `MINISEC_SECRET_KEY` → 第 0 步生成的随机字符串
4. 回到 Web 页面，点绿色 **Reload** 按钮
5. 打开 `https://你的用户名.pythonanywhere.com`

> PythonAnywhere 自带正式服务器（uWSGI），**不需要**你自己装 gunicorn。

---

## 4. 上线后的验收清单

| 检查项 | 怎么做 | 期望结果 |
|---|---|---|
| 首页可访问 | 打开网址 | 深色首页正常显示 |
| 能登录 | `admin / 123456` | 登录成功 |
| 漏洞演示正常 | SQL 注入 → 输入 `admin' OR '1'='1' --` | 显示 LEVEL 1 COMPLETED，4 个用户表格 |
| 调试模式已关闭 | 访问 `/labs/不存在的名字` | 显示双语 404 页面（**不是**能执行代码的调试器页面） |
| robots.txt 生效 | 访问 `/robots.txt` | 返回 `Disallow: /` |
| 表单防伪生效 | 用浏览器开发者工具删掉表单里的 `csrf_token` 再提交 | 显示 400「表单校验失败」 |
| 限速生效 | 快速刷新实验页很多次 | 出现 429「请求过于频繁」 |
| 恢复出厂可用 | 点页面上的「恢复实验数据」 | 提示已恢复，靶子回到 4 个用户 |

---

## 5. 以后怎么更新代码

```bash
# 在 PythonAnywhere 的 Bash 控制台里
cd ~/Vaux-Security-Lab
git pull
```

然后回 Web 页面点一次 **Reload**。（免费版没有自动部署，要手动点。）

---

## 6. 免费版的限制（心里有数）

| 限制 | 影响 | 应对 |
|---|---|---|
| 每天 100 CPU 秒 | 被扫描器刷几分钟就用完，当天网站打不开 | 已内置限速 + robots.txt；被刷时可在 Web 页面临时停用应用 |
| 只有 1 个网站 | 不能同时跑多个项目 | 够用 |
| 磁盘 512MB（**持久保存**） | SQLite 数据库能活下来 ✅ | 这是选它而不是 Render 的主要原因 |
| 不能用定时任务 | 不能做"每天自动重置靶子" | 已经做成页面上的按钮 |
| 外网访问受限 | 服务器访问外部网站受限 | MiniSec 不需要访问外网 |
| 不能 SSH | 只能用网页版 Bash 控制台 | 够用 |
| 长期不登录可能被停用 | 网站会下线 | 定期登录一次（以官网说明为准） |

---

## 7. 门面站（GitHub Pages）

推荐做法：**不新建仓库**，直接用现有仓库的 `docs/` 目录。

1. 在仓库根目录建 `MiniSec` 同级的 `docs/` 文件夹，放静态站点：
   ```
   Vaux-Security-Lab/
   ├── MiniSec/        ← Flask 应用（真靶场）
   └── docs/           ← 静态门面站（GitHub Pages）
       ├── index.html
       ├── sql-injection.html
       ├── style.css
       └── demo.js     ← 纯前端"注入演示"
   ```
2. GitHub 仓库 → **Settings → Pages** → Source 选 `Deploy from a branch`，
   Branch 选 `main` + 目录选 `/docs` → Save
3. 等 1~2 分钟，访问 `https://vaux9527.github.io/Vaux-Security-Lab/`

### 门面站该放什么

- 项目介绍、五步学习法、实验清单（含完成状态）
- 每关的原理讲解（中文 + 英文），Level 1 现在就能写
- **纯前端"注入演示"**：用 JavaScript 实时显示"你输入后 SQL 变成什么样"，
  并把注入部分高亮 —— 不需要后端，永远不会崩，教学冲击力强
- 「进入在线实验环境」按钮 → 跳到 PythonAnywhere 的网址
- 免责声明

### 门面站的注意事项

- **用按钮跳转，不要用 iframe 内嵌靶场**：浏览器的 Cookie 策略会拦 iframe 里的登录态
- 门面站**要**被搜索引擎收录（和靶场相反），所以不要加 `noindex`
- 门面站里不要出现任何"答案代码"以外的敏感信息（真实的密钥一律不写）

---

## 8. 常见故障排查

| 现象 | 原因 | 解决 |
|---|---|---|
| 打开网站 502 / 报错页 | WSGI 配置里的路径写错，或没装依赖 | 看 Web 页面的 **Error log**；确认 `Source code` 路径和 `pip install` 都成功 |
| `ModuleNotFoundError: flask` | 虚拟环境没装依赖，或 WSGI 里没指定虚拟环境 | 在 Web 页面 **Virtualenv** 一栏填 `/home/你的用户名/.virtualenvs/minisec` |
| 提示 `拒绝启动：... MINISEC_SECRET_KEY` | WSGI 文件里没设密钥（这是保护，不是 bug） | 按第 3 步补上随机密钥 |
| 网站能开但显示旧内容 | 改完代码没重启 | 点 Web 页面的 **Reload** |
| 数据库读不到 | 工作目录不对，或没建库 | 确认 Working directory 正确；在 Bash 里跑 `python init_db.py --show` |
| 频繁出现 429 | 限速生效了（可能是你自己刷太多或有人在扫） | 等一分钟；必要时把 `MINISEC_RATE_LIMIT_*` 调大 |
