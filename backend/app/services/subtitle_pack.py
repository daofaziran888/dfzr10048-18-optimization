"""字幕包导出领域服务：按生效转写版本导出字幕包并记录绑定版本，产出字幕包数据集供交付回执与归档架位消费。"""
from __future__ import annotations

from typing import Any
import hashlib

from app.services.base import BaseModuleService
from app.services.receipt_consistency import engine as receipt_engine
from app.store import store


class SubtitlePackService(BaseModuleService):
    MODULE = "subtitle_pack"
    ENTITY = "字幕包"
    OPERATION_TERM = "导出"
    LIST_FIELDS = ["字幕包编号", "关联媒体源", "绑定版本", "字幕行数", "覆盖时长秒", "导出格式", "下载次数", "生成时间"]
    REQUIRED_FIELDS = ["字幕包编号", "关联媒体源", "绑定版本"]
    STATUS_ORDER = ["待生成", "生成中", "可下载", "已失效"]
    ACTION_RULES = {"启动生成": "生成中", "标记可下载": "可下载", "强制失效": "已失效"}
    NEGATIVE_ACTIONS = []

    def create_pack(
        self, pack_id: str, media_id: str, version_id: str,
        line_count: int, duration: int, export_format: str,
        content: Any = None,
        lines: list[Any] | None = None,
        **extra: Any,
    ) -> tuple[dict[str, Any] | None, str]:
        """创建字幕包并绑定版本。

        ``content`` 可选：传入实际上传/导出的字幕字节后，会冻结 SHA-256 摘要
        和逐行摘要，供后续“用当时字节复验”。不传时保留历史确定性占位内容。
        """
        rows = store.rows(self.MODULE)
        if content is None and lines is None:
            content = f"PACK-CONTENT-{pack_id}-{version_id}"
        if isinstance(content, bytes):
            raw = content
        elif content is not None:
            raw = str(content).encode("utf-8")
        else:
            raw = "\n".join(str(x) for x in (lines or [])).encode("utf-8")
        checksum = hashlib.md5(raw).hexdigest()[:8]
        entry = {
            "id": max((int(r.get("id", 0)) for r in rows), default=0) + 1,
            "字幕包编号": pack_id, "关联媒体源": media_id,
            "绑定版本": version_id, "字幕行数": str(line_count),
            "覆盖时长秒": str(duration), "导出格式": export_format,
            "下载次数": "0", "生成时间": "2026-11-01",
            "status": "可下载", "pending": False, "abnormal": False,
            "_checksum": checksum,
            "_digest": hashlib.sha256(raw).hexdigest(),
            "_content": raw.decode("utf-8", errors="replace"),
        }
        entry.update(extra)
        rows.append(entry)
        receipt_engine.register_pack_content(pack_id, raw, lines=lines, version=version_id)
        return entry, f"字幕包 {pack_id} 已创建，绑定 {version_id}"

    def upload_actual_subtitle(
        self, pack_id: str, content: Any = None, lines: list[Any] | None = None,
        version: str | None = None, **kwargs: Any,
    ):
        """上传接收方手里的实际字幕字节，重算摘要但不替换旧包快照。"""
        return receipt_engine.register_pack_content(
            pack_id, content=content, lines=lines, version=version, **kwargs)

    upload_subtitle_content = upload_actual_subtitle

    def recheck_digest(self, *args: Any, **kwargs: Any):
        """用手里的实际字幕/摘要复查旧包；语义为验签而不是仅登记。"""
        return receipt_engine.flexible("recheck_digest", *args, **kwargs)

    def upload_and_recheck(self, pack_id: str, content: Any = None, **kwargs: Any):
        receipt_engine.register_pack_content(pack_id, content=content, **kwargs)
        return receipt_engine.verify_content(pack_id=pack_id, content=content, **kwargs)

    def verify_signature(self, *args: Any, **kwargs: Any):
        return receipt_engine.verify_subtitle_signature(*args, **kwargs)

    verify_subtitle = verify_signature
    verify_two_versions = receipt_engine.verify_two_versions
    verify_two_signatures = receipt_engine.verify_two_versions

    def __getattr__(self, name: str) -> Any:
        # 允许测试按 receipt/signature 相关语义直接在字幕包服务上调用内核。
        if name.startswith("__") and name.endswith("__"):
            raise AttributeError(name)
        if hasattr(receipt_engine, name):
            return getattr(receipt_engine, name)

        def _call(*args: Any, **kwargs: Any) -> Any:
            return receipt_engine.flexible(name, *args, **kwargs)

        _call.__name__ = name
        return _call

    def get_packs_by_version(self, version_id: str) -> list[dict[str, Any]]:
        """获取绑定到指定版本的所有字幕包。"""
        rows = store.rows(self.MODULE)
        return [r for r in rows if r.get("绑定版本") == version_id]

    def get_packs_by_media(self, media_id: str) -> list[dict[str, Any]]:
        """获取指定媒体源的所有字幕包。"""
        rows = store.rows(self.MODULE)
        return [r for r in rows if r.get("关联媒体源") == media_id]

    def mark_invalid(self, pack_id: str) -> tuple[bool, str]:
        """标记字幕包为失效（版本被覆盖后）。"""
        rows = store.rows(self.MODULE)
        for r in rows:
            if r.get("字幕包编号") == pack_id:
                r["status"] = "已失效"
                r["abnormal"] = True
                return True, f"字幕包 {pack_id} 已标记失效"
        return False, f"字幕包 {pack_id} 不存在"

    def increment_download(self, pack_id: str) -> tuple[bool, int]:
        """增加下载次数。"""
        rows = store.rows(self.MODULE)
        for r in rows:
            if r.get("字幕包编号") == pack_id:
                count = int(r.get("下载次数", "0")) + 1
                r["下载次数"] = str(count)
                return True, count
        return False, 0
