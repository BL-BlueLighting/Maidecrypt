"""DecryptPlugin — 为 AI 提供加解密工具调用能力。"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any, ClassVar

# 必须在其他导入之前将插件目录加入 sys.path，否则 algos 包无法被发现
_PLUGIN_DIR = str(Path(__file__).resolve().parent)
if _PLUGIN_DIR not in sys.path:
    sys.path.insert(0, _PLUGIN_DIR)

from maibot_sdk import MaiBotPlugin, Tool, PluginConfigBase, Field
from maibot_sdk.types import ToolParameterInfo, ToolParamType

from algos.base import MaiMAlgo

# ── 常量 ─────────────────────────────────────────────────

PLUGIN_DIR = Path(_PLUGIN_DIR)
ALGOS_DIR = PLUGIN_DIR / "algos"


# ── 算法发现引擎 ─────────────────────────────────────────

_algo_registry: dict[str, MaiMAlgo] = {}


def _load_single_maialgo(file_path: Path) -> MaiMAlgo | None:
    """加载单个 .maialgo 文件，返回算法实例。

    使用 SourceFileLoader 绕过 imp 对 .py 扩展名的限制，
    允许加载 .maialgo 扩展名的 Python 源码文件。
    """
    try:
        module_name = f"__decryptplugin_{file_path.stem}__"

        # SourceFileLoader 可加载任意扩展名的 Python 源文件
        from importlib.machinery import SourceFileLoader

        loader = SourceFileLoader(module_name, str(file_path))
        spec = importlib.util.spec_from_loader(
            module_name, loader, origin=str(file_path)
        )
        if spec is None:
            return None

        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        loader.exec_module(module)

        algo_cls: type[MaiMAlgo] | None = getattr(module, "__algo__", None)
        if algo_cls is None:
            return None
        if not (isinstance(algo_cls, type) and issubclass(algo_cls, MaiMAlgo)):
            return None

        instance = algo_cls()
        return instance
    except Exception:
        import traceback
        traceback.print_exc()
        return None


def _discover_algorithms() -> dict[str, MaiMAlgo]:
    """扫描 algos/*.maialgo，加载所有算法。"""
    registry: dict[str, MaiMAlgo] = {}
    if not ALGOS_DIR.is_dir():
        return registry

    for f in sorted(ALGOS_DIR.glob("*.maialgo")):
        instance = _load_single_maialgo(f)
        if instance is not None:
            registry[instance.name] = instance

    return registry


# 模块加载时预扫描所有算法，供 Tool 装饰器构建参数描述
_algo_registry.update(_discover_algorithms())


def _build_type_description() -> str:
    """为 type 参数构建完整的算法说明文本。"""
    if not _algo_registry:
        lines = ["⚠️ 未加载任何算法。"]
    else:
        lines = ["可用加解密算法："]
        for name, algo in _algo_registry.items():
            pw = "需要密码" if algo.needs_password else "无需密码"
            cat = algo.type_category
            lines.append(f"  - {name}: {algo.description} [{cat}, {pw}]")

    return "\n".join(lines)


def _build_type_enum() -> list[str]:
    """返回所有已注册算法的名称列表，供 AI 选填。"""
    return list(_algo_registry.keys())


def _get_algo_info_markdown(algo: MaiMAlgo) -> str:
    """生成单个算法的详细说明。"""
    lines = [
        f"# {algo.name}",
        f"**分类**: {algo.type_category}",
        f"**需要密码**: {'是' if algo.needs_password else '否'}",
        f"**描述**: {algo.description}",
        "",
        algo.format_parameter_info(),
    ]
    return "\n".join(lines)


# ── 插件配置 ─────────────────────────────────────────────

class DecryptPluginConfig(PluginConfigBase):
    disabled_types: list[str] = Field(
        default_factory=list,
        description="禁用的算法类型列表",
    )


# ── 插件主类 ─────────────────────────────────────────────

class DecryptPlugin(MaiBotPlugin):
    config_model = DecryptPluginConfig

    config_reload_subscriptions: ClassVar[tuple[str, ...]] = ()

    def __init__(self) -> None:
        super().__init__()
        self._loaded_algos: dict[str, MaiMAlgo] = {}

    # ── 生命周期 ─────────────────────────────────────────

    async def on_load(self) -> None:
        self.ctx.logger.info("DecryptPlugin 正在加载…")
        self._loaded_algos = _discover_algorithms()
        disabled = self.config.disabled_types if hasattr(self, "config") else []
        for name in disabled:
            self._loaded_algos.pop(name, None)

        self.ctx.logger.info(
            "DecryptPlugin 已加载，共 %d 个算法: %s",
            len(self._loaded_algos),
            ", ".join(self._loaded_algos),
        )

    async def on_unload(self) -> None:
        self.ctx.logger.info("DecryptPlugin 已卸载")

    async def on_config_update(self, scope: str, config_data: dict, version: str) -> None:
        if scope == "self":
            self.ctx.logger.info("DecryptPlugin 配置已更新: version=%s", version)
            # 重新扫描算法
            self._loaded_algos = _discover_algorithms()
            disabled = config_data.get("disabled_types", [])
            for name in disabled:
                self._loaded_algos.pop(name, None)

    # ── 工具方法 ─────────────────────────────────────────

    def _resolve_algo(self, type_name: str) -> MaiMAlgo:
        algo = self._loaded_algos.get(type_name)
        if algo is None:
            known = ", ".join(self._loaded_algos) or "无可用算法"
            raise ValueError(
                f"未知的算法类型 '{type_name}'。当前可用: {known}"
            )
        return algo

    # ── 工具: 加密 ───────────────────────────────────────

    @Tool(
        "decplg_encrypt",
        brief_description="加密/编码数据",
        detailed_description=(
            "通用的加密或编码工具，根据 type 参数选择算法对数据进行加密。\n"
            + "参数：\n"
            + "  - type: 算法类型（见下方列表）\n"
            + "  - data: 待加密的原文\n"
            + "  - password: 密码（编码类算法可选填）\n"
            + "  - external_args: 额外参数列表（如 AES 的 [\"ECB\",\"PKCS7\",128]）\n\n"
            + _build_type_description()
        ),
        parameters=[
            ToolParameterInfo(
                name="type",
                param_type=ToolParamType.STRING,
                description=_build_type_description(),
                required=True,
                enum_values=_build_type_enum(),
            ),
            ToolParameterInfo(
                name="data",
                param_type=ToolParamType.STRING,
                description="待加密的原文数据",
                required=True,
            ),
            ToolParameterInfo(
                name="password",
                param_type=ToolParamType.STRING,
                description="密码或密钥（编解码类算法可留空）",
                required=False,
                default=None,
            ),
            ToolParameterInfo(
                name="external_args",
                param_type=ToolParamType.ARRAY,
                description=(
                    "附加参数列表，每项为 string / int / bool。"
                    "如 AES 的 mode/padding/key_size: [\"ECB\",\"PKCS7\",128]"
                ),
                items_schema={"type": ["string", "integer", "boolean"]},
                required=False,
                default=None,
            ),
        ],
    )
    async def handle_encrypt(
        self,
        type: str,
        data: str,
        password: str | None = None,
        external_args: list[str | int | bool] | None = None,
        **kwargs,
    ) -> dict:
        """加密 / 编码数据。"""
        try:
            algo = self._resolve_algo(type)
            kwargs_dict = _parse_external_args(external_args or [])
            result = algo.encrypt(data, password=password, **kwargs_dict)
            return {"success": True, "algorithm": type, "result": result}
        except Exception as e:
            return {"success": False, "algorithm": type, "error": str(e)}

    # ── 工具: 解密 ───────────────────────────────────────

    @Tool(
        "decplg_decrypt",
        brief_description="解密/解码数据",
        detailed_description=(
            "通用的解密或解码工具，根据 type 参数选择算法对数据进行解密。\n"
            + "参数：\n"
            + "  - type: 算法类型（见下方列表）\n"
            + "  - data: 待解密的数据\n"
            + "  - password: 密码（编码类算法可选填）\n"
            + "  - external_args: 额外参数列表\n\n"
            + _build_type_description()
        ),
        parameters=[
            ToolParameterInfo(
                name="type",
                param_type=ToolParamType.STRING,
                description=_build_type_description(),
                required=True,
                enum_values=_build_type_enum(),
            ),
            ToolParameterInfo(
                name="data",
                param_type=ToolParamType.STRING,
                description="待解密的数据",
                required=True,
            ),
            ToolParameterInfo(
                name="password",
                param_type=ToolParamType.STRING,
                description="密码或密钥（编解码类算法可留空）",
                required=False,
                default=None,
            ),
            ToolParameterInfo(
                name="external_args",
                param_type=ToolParamType.ARRAY,
                description=(
                    "附加参数列表，每项为 string / int / bool。"
                    "如 AES 的 mode/padding/key_size: [\"ECB\",\"PKCS7\",128]"
                ),
                items_schema={"type": ["string", "integer", "boolean"]},
                required=False,
                default=None,
            ),
        ],
    )
    async def handle_decrypt(
        self,
        type: str,
        data: str,
        password: str | None = None,
        external_args: list[str | int | bool] | None = None,
        **kwargs,
    ) -> dict:
        """解密 / 解码数据。"""
        try:
            algo = self._resolve_algo(type)
            kwargs_dict = _parse_external_args(external_args or [])
            result = algo.decrypt(data, password=password, **kwargs_dict)
            return {"success": True, "algorithm": type, "result": result}
        except Exception as e:
            return {"success": False, "algorithm": type, "error": str(e)}

    # ── 工具: 算法详情查询 ──────────────────────────────

    @Tool(
        "decplg_algorithm_info",
        brief_description="查询加解密算法的详细信息",
        detailed_description=(
            "获取某个加解密算法的详细说明，包括参数含义、可选值等。"
        ),
        parameters=[
            ToolParameterInfo(
                name="type",
                param_type=ToolParamType.STRING,
                description="要查询的算法类型",
                required=True,
                enum_values=_build_type_enum(),
            ),
        ],
    )
    async def handle_algorithm_info(
        self,
        type: str,
        **kwargs,
    ) -> dict:
        """返回算法的详细信息。"""
        try:
            algo = self._resolve_algo(type)
            return {
                "success": True,
                "algorithm": type,
                "info": _get_algo_info_markdown(algo),
            }
        except Exception as e:
            return {"success": False, "algorithm": type, "error": str(e)}


# ── 外部参数解析 ─────────────────────────────────────────

def _parse_external_args(
    args: list[str | int | bool],
) -> dict[str, Any]:
    """将 external_args 列表解析为 kwargs 字典。

    支持两种格式：
    1. 顺序传参: ["ECB", "PKCS7", 128]
       → 需配合算法参数的顺序。
    2. 键值对传参: ["mode=ECB", "padding=PKCS7", "key_size=128"]
       → 显式指定参数名。

    如果全是键值对格式，按命名解析；
    否则按位置解析，每个算法自行处理。
    """
    if not args:
        return {}

    # 检测是否为键值对格式
    kv_pairs: dict[str, Any] = {}
    positional: list[Any] = []
    for arg in args:
        if isinstance(arg, str) and "=" in arg:
            key, _, val = arg.partition("=")
            kv_pairs[key.strip()] = _coerce_value(val.strip())
        else:
            positional.append(arg)

    if kv_pairs and not positional:
        return kv_pairs
    elif positional:
        return {"_positional": positional}
    else:
        return {}


def _coerce_value(val: str) -> str | int | bool:
    """将字符串值尝试转换为 int / bool。"""
    if val.lower() in ("true", "yes", "1"):
        return True
    if val.lower() in ("false", "no", "0"):
        return False
    try:
        return int(val)
    except ValueError:
        return val


# ── 工厂函数（必须） ────────────────────────────────────

def create_plugin():
    return DecryptPlugin()
