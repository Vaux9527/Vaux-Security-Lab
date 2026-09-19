# -*- coding: utf-8 -*-
"""通关进度记录（平台数据，不是靶子数据）。

为什么放在平台库而不是靶子库：
"哪几关打过了"是你的学习记录，属于平台数据；
而靶子库是用来被打穿的、随时可以删掉重建的。
两者混在一起，一次"恢复出厂"就会把学习记录也抹掉。

设计取舍：
- 只记"首次通关时间"，不记尝试次数、不记 payload
  （第一版够用；真要做统计，那是另一个功能，不提前设计）
- 写进度用 INSERT OR IGNORE + UNIQUE(lab, level)，天然幂等：
  同一关反复通关不会写重复行
- 恢复某一关的靶子数据时，把那一关的进度也清掉（重新开始）
"""

from datetime import datetime

from database import get_platform_db

import curriculum

# 靶子库名 -> 实验名。
# Level 2 有自己独立的靶子库（lab_login.db），但进度上它仍然属于 "sql" 这个实验，
# 所以这里要做一次映射：重置 sql_login 时，清掉的是 sql 实验的第 2 关进度。
LAB_TO_EXPERIMENT = {
    "sql": "sql",
    "sql_login": "sql",
    "sql_union": "sql",
    "xss": "xss",
    "upload": "upload",
    "cmdi": "cmdi",
    "idor": "idor",
    "csrf": "csrf",
}

# 靶子库名 -> 该库对应哪几关（重置时只清这几关的进度）
LAB_TO_LEVELS = {
    "sql": [1],
    "sql_login": [2],
    "sql_union": [3],
    "xss": [1, 2],
    "upload": [1],
    "cmdi": [1],
    "idor": [1],
    "csrf": [1],
}


def mark_cleared(lab_name, level_id):
    """记录"这一关通关了"。重复调用不会写重复行。"""

    conn = get_platform_db()
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT OR IGNORE INTO progress(lab, level, cleared_at)
        VALUES (?, ?, ?)
        """,
        (lab_name, level_id, datetime.now().isoformat(timespec="seconds")),
    )

    conn.commit()
    conn.close()


def cleared_levels(lab_name):
    """某个实验已经通关的关卡号集合。"""

    conn = get_platform_db()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT level FROM progress WHERE lab = ?",
        (lab_name,),
    )

    levels = {row[0] for row in cursor.fetchall()}

    conn.close()

    return levels


def is_cleared(lab_name, level_id):
    """某一关是否已经通关。"""

    return level_id in cleared_levels(lab_name)


def clear_lab(lab_name):
    """清掉某个实验的全部进度（重置靶子数据时调用）。"""

    conn = get_platform_db()
    cursor = conn.cursor()

    cursor.execute("DELETE FROM progress WHERE lab = ?", (lab_name,))

    conn.commit()
    conn.close()


def clear_for_target_lab(target_lab):
    """重置某个靶子库时，清掉它对应的那几关进度。

    例如重置 lab_login.db，清掉的是 sql 实验第 2 关的进度，
    Level 1 和 Level 3 的记录不受影响。
    """

    lab_name = LAB_TO_EXPERIMENT.get(target_lab)

    if lab_name is None:
        return

    conn = get_platform_db()
    cursor = conn.cursor()

    for level_id in LAB_TO_LEVELS.get(target_lab, []):

        cursor.execute(
            "DELETE FROM progress WHERE lab = ? AND level = ?",
            (lab_name, level_id),
        )

    conn.commit()
    conn.close()


def summary():
    """每个实验的通关情况：{实验名: (已通关数, 总关卡数)}。"""

    result = {}

    for lab_name in curriculum.LEVELS_BY_LAB:

        result[lab_name] = (
            len(cleared_levels(lab_name)),
            curriculum.level_count(lab_name),
        )

    return result


def total_cleared():
    """总共通关了多少关（首页用）。"""

    return sum(cleared for cleared, _ in summary().values())


def total_levels():
    """一共有多少关（首页用）。"""

    return sum(total for _, total in summary().values())
