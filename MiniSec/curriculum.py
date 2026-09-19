# -*- coding: utf-8 -*-
"""实验与关卡的目录（单一数据源）。

为什么要有这个文件：
关卡清单要同时被四个地方用到 —— 实验页的关卡列表、进度统计（总共几关）、
恢复出厂的清理范围、以及回归测试。如果每个地方各写一份，
加一关就要改四个文件，迟早会漏。

所以：**关卡清单只在这里定义一次**，其他地方都 import 它。

结构：
    LEVELS_BY_LAB = {实验名: [关卡, ...]}

每个关卡是一个字典：
    id            关卡号（同一个实验内唯一）
    title / title_en         标题（中英）
    description / description_en  一句话说明（中英）
    status        ready = 可以进入；planned = 还没做（页面显示"开发中"，不给死链）
    url           进入地址（status 为 planned 时留空）
"""

SQL_LEVELS = [
    {
        "id": 1,
        "title": "Level 1 基础查询注入",
        "title_en": "Basic Query Injection",
        "description": "学习用户输入如何影响SQL查询逻辑。",
        "description_en": "Learn how user input changes the SQL query logic.",
        "status": "ready",
        "url": "/labs/sql/level1",
    },
    {
        "id": 2,
        "title": "Level 2 登录绕过",
        "title_en": "Login Bypass",
        "description": "学习利用SQL注入绕过身份验证。",
        "description_en": "Learn to bypass authentication using SQL injection.",
        "status": "ready",
        "url": "/labs/sql/level2",
    },
    {
        "id": 3,
        "title": "Level 3 UNION查询",
        "title_en": "UNION Based Injection",
        "description": "学习判断字段数量并跨表读取数据。",
        "description_en": "Learn column counting and cross-table data extraction.",
        "status": "ready",
        "url": "/labs/sql/level3",
    },
]

XSS_LEVELS = [
    {
        "id": 1,
        "title": "Level 1 反射型XSS",
        "title_en": "Reflected XSS",
        "description": "学习用户输入被当作脚本执行的过程。",
        "description_en": "Learn how user input ends up being executed as a script.",
        "status": "ready",
        "url": "/labs/xss/level1",
    },
    {
        "id": 2,
        "title": "Level 2 存储型XSS",
        "title_en": "Stored XSS",
        "description": "学习一次注入、所有访客中招的持久化攻击。",
        "description_en": "Learn the persistent attack: inject once, hit every visitor.",
        "status": "ready",
        "url": "/labs/xss/level2",
    },
]

UPLOAD_LEVELS = [
    {
        "id": 1,
        "title": "Level 1 文件上传",
        "title_en": "Unrestricted File Upload",
        "description": "学习只检查后缀名的校验为什么靠不住。",
        "description_en": "Learn why an extension blacklist is not a real defense.",
        "status": "ready",
        "url": "/labs/upload/level1",
    },
]

SSRF_LEVELS = [
    {
        "id": 1,
        "title": "Level 1 服务端请求伪造",
        "title_en": "Server-Side Request Forgery",
        "description": "学习借服务器之手访问它才够得着的内部资源。",
        "description_en": "Learn to make the server reach resources only it can see.",
        "status": "ready",
        "url": "/labs/ssrf/level1",
    },
]

CMDI_LEVELS = [
    {
        "id": 1,
        "title": "Level 1 命令注入",
        "title_en": "OS Command Injection",
        "description": "学习用户输入进入系统命令时的后果。",
        "description_en": "Learn what happens when input flows into an OS command.",
        "status": "ready",
        "url": "/labs/cmdi/level1",
    },
]

IDOR_LEVELS = [
    {
        "id": 1,
        "title": "Level 1 水平越权",
        "title_en": "Insecure Direct Object Reference",
        "description": "学习改一个编号就读到别人数据的越权漏洞。",
        "description_en": "Learn to read someone else's data by changing one id.",
        "status": "ready",
        "url": "/labs/idor/level1",
    },
]

CSRF_LEVELS = [
    {
        "id": 1,
        "title": "Level 1 跨站请求伪造",
        "title_en": "Cross-Site Request Forgery",
        "description": "学习借你已登录的身份，在你不知情时发出请求。",
        "description_en": "Learn to send requests as a logged-in user who never made them.",
        "status": "ready",
        "url": "/labs/csrf/level1",
    },
]

# 实验 -> 关卡清单。新增实验时在这里加一行即可。
LEVELS_BY_LAB = {
    "sql": SQL_LEVELS,
    "xss": XSS_LEVELS,
    "upload": UPLOAD_LEVELS,
    "ssrf": SSRF_LEVELS,
    "cmdi": CMDI_LEVELS,
    "idor": IDOR_LEVELS,
    "csrf": CSRF_LEVELS,
}


def levels_of(lab_name):
    """取某个实验的关卡清单（没有分关的实验返回空列表）。"""

    return LEVELS_BY_LAB.get(lab_name, [])


def level_count(lab_name):
    """某个实验一共有多少关（只算已经可以进入的）。"""

    return len([lv for lv in levels_of(lab_name) if lv["status"] == "ready"])


def find_level(lab_name, level_id):
    """按实验名 + 关卡号找一关，找不到返回 None。"""

    for level in levels_of(lab_name):
        if level["id"] == level_id:
            return level

    return None
