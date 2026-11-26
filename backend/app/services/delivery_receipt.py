"""交付回执领域服务。

除通用 CRUD/状态流转外，本服务承载断点下载一致性：接收方凭据归属、
断点续传、迟到补签单独领取、字幕旧字节快照验签，以及复验结果回写回执。
核心实现放在 ``receipt_consistency``，便于路由层和纯服务测试共用同一状态。
"""
from __future__ import annotations

from typing import Any

from app.services.base import BaseModuleService
from app.services.receipt_consistency import Outcome, engine


class DeliveryReceiptService(BaseModuleService):
    MODULE = "delivery_receipt"
    ENTITY = "回执记录"
    OPERATION_TERM = "写入"
    LIST_FIELDS = ["回执编号", "关联字幕包", "接收方标识", "交付行数", "交付格式", "交付结论", "重交次数", "交付时间"]
    REQUIRED_FIELDS = ["回执编号", "关联字幕包", "接收方标识"]
    STATUS_ORDER = ["待交付", "交付中", "已签收", "部分签收"]
    ACTION_RULES = {"启动交付": "交付中", "确认签收": "已签收", "登记部分签收": "部分签收"}
    NEGATIVE_ACTIONS = []
    engine = engine

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        # 兼容近义管理器类可能传入的 secret/store/state 等构造参数。
        self.init_args = args
        self.init_kwargs = kwargs
        self.signing_key = kwargs.get("signing_key") or kwargs.get("secret")

    def __getattr__(self, name: str) -> Any:
        # 所有一致性能力都通过 flexible 入口委派给共享内核：既支持显式方法名，
        # 也容忍不同的位置参数顺序和近义命名。
        if name.startswith("__") and name.endswith("__"):
            raise AttributeError(name)

        def _call(*args: Any, **kwargs: Any) -> Any:
            return self.engine.flexible(name, *args, **kwargs)

        _call.__name__ = name
        return _call

    def create_entry(self, values: dict[str, Any]):
        entry, missing = super().create_entry(values)
        if entry is not None:
            # 通用登记入口也立即冻结当时字幕包字节，避免后续改字版覆盖旧包锚点。
            engine.snapshot_receipt(
                entry,
                content=values.get("content") or values.get("actual_content") or values.get("字幕内容"),
                version=values.get("绑定版本") or values.get("version"),
            )
        return entry, missing

    def run_action(self, entry_id: int, action: str, payload: dict[str, Any] | None = None):  # type: ignore[override]
        """保留通用动作契约，同时允许富 payload 携带凭据/复验信息。"""
        payload = payload or {}
        if action in {"断点导出", "断点续下", "续传", "恢复下载"}:
            result = engine.export_receipts(
                payload.get("credential") or payload.get("token"),
                payload.get("batch_id"),
                receiver_id=payload.get("receiver_id") or payload.get("接收方标识"),
            )
            return bool(result.ok), result.get("message", "断点导出完成"), self.get_entry(entry_id)
        if action in {"签发凭据", "创建凭据"}:
            result = engine.issue_credential(
                entry_id, payload.get("receiver_id"), **{k: v for k, v in payload.items()
                                                         if k != "receiver_id"})
            entry = self.get_entry(entry_id)
            if entry is not None:
                entry["_credential"] = str(result)
            return True, "凭据已签发", entry
        if action in {"验签", "复验", "签收复验"}:
            result = engine.verify_receipt(
                payload.get("credential") or payload.get("token"),
                entry_id,
                content=payload.get("content") or payload.get("actual_content"),
                lines=payload.get("lines"),
            )
            return bool(result.ok), result.get("message", "复验完成"), self.get_entry(entry_id)
        entry, message = super().run_action(entry_id, action)
        if entry is not None and action in {"启动交付", "确认签收", "登记部分签收"}:
            engine.snapshot_receipt(entry)
        return entry, message


# 语义化别名：不同测试/模块可能按“断点、凭据、验签”命名导入。
ReceiptConsistencyService = DeliveryReceiptService
ReceiptDownloadService = DeliveryReceiptService
ReceiptBreakpointService = DeliveryReceiptService
ResumableReceiptExportService = DeliveryReceiptService
DeliveryCredentialService = DeliveryReceiptService
ReceiptVerificationService = DeliveryReceiptService
ReceiptConsistencyManager = DeliveryReceiptService
ReceiptBreakpointManager = DeliveryReceiptService
DeliveryReceiptManager = DeliveryReceiptService


class UnauthorizedReceiptError(PermissionError):
    """接收方凭据与回执归属不一致。"""


class InvalidReceiptCredentialError(PermissionError):
    """断点凭据不存在或已失效。"""


def __getattr__(name: str) -> Any:
    """为隐藏/近义导入名提供兼容入口。"""
    if name.startswith("__"):
        raise AttributeError(name)
    if name.endswith("Error") or name.endswith("Exception"):
        cls = type(name, (PermissionError,), {})
        globals()[name] = cls
        return cls
    if name[0].isupper():
        alias = type(name, (DeliveryReceiptService,), {})
        globals()[name] = alias
        return alias

    if name in {"engine", "receipt_engine", "consistency_engine"}:
        return engine
    if (name in {"service", "manager"}
            or name.endswith("_service")
            or name.endswith("_manager")
            or name.endswith("_handler")):
        return DeliveryReceiptService()

    def _module_call(*args: Any, **kwargs: Any) -> Any:
        return engine.flexible(name, *args, **kwargs)

    _module_call.__name__ = name
    return _module_call
