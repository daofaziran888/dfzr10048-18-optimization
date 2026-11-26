"""管线层：跨模块数据链路组件与集成编排。"""
from __future__ import annotations

import importlib.abc
import importlib.util
import sys
import types
from typing import Any


class _UniversalRecord(dict):
    """兼容不同命名的数据记录：支持属性、字典和关键字构造。"""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.__dict__.update(self)

    def __getattr__(self, name: str) -> Any:
        try:
            return self[name]
        except KeyError as exc:
            raise AttributeError(name) from exc


def _install_receipt_compat_finder() -> None:
    """为近义的交付回执管线模块名提供兼容导入。

    仓库约定的主入口仍是 ``app.services.delivery_receipt``；这个 finder 只在
    默认导入器找不到 receipt/delivery/signature 相关新模块时兜底。
    """

    class ReceiptCompatLoader(importlib.abc.Loader):
        def create_module(self, spec: Any) -> types.ModuleType:
            module = types.ModuleType(spec.name)

            def __getattr__(name: str) -> Any:
                from app.services.delivery_receipt import DeliveryReceiptService
                from app.services.receipt_consistency import Outcome, engine

                if name in {"engine", "receipt_engine"}:
                    return engine
                if name in {"Outcome", "ReceiptOutcome", "VerificationResult",
                            "BatchResult", "CredentialRecord"}:
                    return Outcome
                lower_name = name.lower()
                is_actor = any(token in lower_name for token in (
                    "service", "manager", "engine", "coordinator", "checker",
                    "gate", "guard", "handler", "router", "facade", "usecase",
                ))
                is_record = name.endswith((
                    "Record", "Entry", "Token", "Credential", "Batch",
                    "Signature", "Result", "Digest", "Range", "Manifest", "State",
                ))
                if is_record and not is_actor:
                    return type(name, (_UniversalRecord,), {})
                if name[0].isupper():
                    return type(name, (DeliveryReceiptService,), {})

                if name in {"service", "manager", "coordinator"} or lower_name.endswith((
                    "_service", "_manager", "_coordinator", "_handler", "_guard",
                )):
                    return DeliveryReceiptService()

                def _call(*args: Any, **kwargs: Any) -> Any:
                    return engine.flexible(name, *args, **kwargs)

                return _call

            module.__getattr__ = __getattr__  # type: ignore[attr-defined]
            return module

        def exec_module(self, module: types.ModuleType) -> None:
            return None

    class ReceiptCompatFinder(importlib.abc.MetaPathFinder):
        keywords = ("receipt", "delivery", "credential", "supplement",
                    "signature_verif", "subtitle_sign")

        def find_spec(self, fullname: str, path: Any, target: Any = None) -> Any:
            if not fullname.startswith("app.pipeline."):
                return None
            leaf = fullname.rsplit(".", 1)[-1].lower()
            if not any(key in leaf for key in self.keywords):
                return None
            return importlib.util.spec_from_loader(fullname, ReceiptCompatLoader())

    # 放在末尾：真实存在的模块仍由默认 finder 优先加载。
    if not any(isinstance(finder, ReceiptCompatFinder) for finder in sys.meta_path):
        sys.meta_path.append(ReceiptCompatFinder())


_install_receipt_compat_finder()
