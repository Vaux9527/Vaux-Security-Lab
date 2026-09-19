# -*- coding: utf-8 -*-
"""实验列表页 + 实验详情页（含分关实验的关卡列表）。

实验目录存在平台数据库的 labs 表里，所以新增实验只需要往表里加一行。

分两种实验：
    - 有分关的实验（sql / xss / upload / ssrf / cmdi）
      详情页渲染关卡列表，每关带"已通关 / 可进入 / 开发中"状态
    - 还没分关的实验（如 idor，状态 wip）
      详情页渲染通用占位说明，不留死链

关卡清单本身来自 curriculum.py（单一数据源），这里只负责取出来展示。
"""

from flask import Blueprint, abort, render_template

import curriculum
import progress
from auth import login_required
from database import get_platform_db

labs_bp = Blueprint(
    "labs",
    __name__
)

LAB_COLUMNS = """
name, title, title_en, description, description_en, status, entry_url
"""


def _to_dict(row):
    """把数据库的一行转成模板里好用的字典。"""

    return {
        "name": row[0],
        "title": row[1],
        "title_en": row[2],
        "description": row[3],
        "description_en": row[4],
        "status": row[5],
        "entry_url": row[6],
    }


def _all_labs():
    """读出全部实验。"""

    conn = get_platform_db()

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT
        """ + LAB_COLUMNS + """
        FROM labs
        ORDER BY id
        """
    )

    rows = cursor.fetchall()

    conn.close()

    return [_to_dict(row) for row in rows]


@labs_bp.route("/labs")
@login_required
def labs():

    lab_list = _all_labs()

    # 每个实验的通关情况：{实验名: (已通关, 总数)}
    progress_by_lab = progress.summary()

    for lab in lab_list:

        cleared, total = progress_by_lab.get(lab["name"], (0, 0))

        lab["cleared"] = cleared
        lab["total"] = total

    return render_template(
        "labs.html",
        labs=lab_list,
        cleared_total=progress.total_cleared(),
        level_total=progress.total_levels()
    )


@labs_bp.route("/labs/<lab_name>")
@login_required
def lab(lab_name):

    info = None

    for lab in _all_labs():

        if lab["name"] == lab_name:
            info = lab
            break

    if info is None:
        abort(404)

    levels = curriculum.levels_of(lab_name)

    # 有分关的实验：渲染关卡列表（带通关状态）
    if levels:

        cleared = progress.cleared_levels(lab_name)

        info["cleared"] = len(cleared)
        info["total"] = curriculum.level_count(lab_name)

        return render_template(
            "levels.html",
            lab_info=info,
            levels=levels,
            cleared_levels=cleared,
            cleared_count=len(cleared)
        )

    # 还没分关的实验：渲染通用占位页
    return render_template(
        "lab.html",
        lab_info=info
    )
