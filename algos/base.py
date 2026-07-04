"""MaiMAlgo — 加解密算法通用接口

所有 .maialgo 文件必须导出一个 MaiMAlgo 的子类。
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class MaiMAlgo(ABC):
    """加解密算法抽象基类。"""

    # ── 元信息属性 ──────────────────────────────────────

    @property
    @abstractmethod
    def name(self) -> str:
        """算法唯一标识（小写，如 "aes"）。"""
        ...

    @property
    @abstractmethod
    def description(self) -> str:
        """算法简要说明（供 tool description 展示）。"""
        ...

    @property
    @abstractmethod
    def type_category(self) -> str:
        """算法分类：
        - "encoding"    编解码（无需密码）
        - "symmetric"   对称加密（需要密码）
        - "asymmetric"  非对称加密（需要密码/密钥对）
        - "hash"        哈希（单向，仅加密可用）
        - "simple"      简单变换
        """
        ...

    # ── 可选属性 ────────────────────────────────────────

    @property
    def needs_password(self) -> bool:
        """是否需要密码。默认：type_category != 'encoding' 时 True。"""
        return self.type_category not in ("encoding", "hash", "simple")

    @property
    def parameter_info(self) -> list[dict[str, Any]]:
        """external_args 中每个参数的说明。

        每项格式：
            {"name": "<参数名>", "type": "string|int|bool",
             "description": "<说明>", "default": <默认值|None>,
             "choices": ["可选值1", ...] | None}
        """
        return []

    # ── 核心接口 ────────────────────────────────────────

    @abstractmethod
    def encrypt(self, data: str, password: str | None = None, **kwargs: Any) -> str:
        """加密 / 编码。

        参数:
            data:     待加密的原文。
            password: 密码 / 密钥（可为空）。
            kwargs:   external_args 解析后的键值对。

        返回:
            加密 / 编码后的字符串。
        """
        ...

    @abstractmethod
    def decrypt(self, data: str, password: str | None = None, **kwargs: Any) -> str:
        """解密 / 解码。"""
        ...

    # ──工具方法 ─────────────────────────────────────────

    def format_parameter_info(self) -> str:
        """将 parameter_info 格式化为 AI 可读的文本。"""
        if not self.parameter_info:
            return "无额外参数。"
        lines = ["可选参数说明："]
        for p in self.parameter_info:
            choices = ""
            if p.get("choices"):
                choices = f" 可选值: {', '.join(str(c) for c in p['choices'])}"
            default = ""
            if p.get("default") is not None:
                default = f" (默认: {p['default']})"
            lines.append(
                f"  - {p['name']}（{p['type']}）{default}"
                f"\n    {p.get('description', '')}{choices}"
            )
        return "\n".join(lines)
