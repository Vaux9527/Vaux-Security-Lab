# -*- coding: utf-8 -*-
"""数据库连接层。

MiniSec 把数据分成两类，分开存放：

    platform.db   平台自己的数据（登录账号、实验目录）—— 必须安全
    lab_*.db      实验靶子数据 —— 故意存在漏洞，可以整体删除重建

为什么要分开？
SQL 注入实验的目标就是"读别的表"，如果靶子和平台账号住在同一个数据库里，
访客就能用一条 UNION 语句把平台账号全部读走。
分开之后，最坏情况也只是靶子被打烂，删掉重建即可。
"""

import sqlite3

import init_db
from config import PLATFORM_DB, lab_db_path


def _connect(path):
    """连接数据库；文件不存在时自动建库（全新环境也能直接启动）。"""

    if not path.exists():
        init_db.ensure_databases()

    return sqlite3.connect(path)


def get_platform_db():
    """平台数据库连接：登录账号、实验目录等。"""

    return _connect(PLATFORM_DB)


def get_lab_db(lab_name):
    """某个实验的靶子数据库连接（里面只有假数据）。"""

    return _connect(lab_db_path(lab_name))
