"""统一资源接口：查询、导出、登记和动作按模块 key 分派到领域服务。"""
from __future__ import annotations

import csv
import io
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse, StreamingResponse

from app.schemas import ActionPayload, ActionResult, EntryPayload, PageResult
from app.services import service_for

router = APIRouter(prefix="/api", tags=["业务资源"])


def require_service(module: str):
    service = service_for(module)
    if service is None:
        raise HTTPException(status_code=404, detail=f"未知业务模块：{module}")
    return service


def request_credential(request: Request) -> str | None:
    credential = (request.query_params.get("credential")
                  or request.query_params.get("token")
                  or request.query_params.get("断点凭据")
                  or request.query_params.get("凭据")
                  or request.headers.get("x-credential")
                  or request.headers.get("x-token"))
    if credential:
        return credential
    authorization = request.headers.get("authorization", "")
    if authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return request.cookies.get("receipt_credential") or request.cookies.get("token")


@router.get("/{module}", response_model=PageResult[dict])
def list_entries(
    module: str,
    request: Request,
    keyword: str | None = Query(default=None),
    status: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    size: int = Query(default=20, ge=1, le=200),
) -> PageResult[dict]:
    service = require_service(module)
    filters = {
        key: value.strip()
        for key, value in request.query_params.items()
        if key in service.LIST_FIELDS and value.strip()
    }
    if module == "delivery_receipt":
        from app.services.receipt_consistency import engine as receipt_engine

        credential = request_credential(request)
        if credential:
            receiver = (request.query_params.get("receiver_id")
                        or request.query_params.get("接收方标识"))
            auth = receipt_engine.authorize(credential, receiver_id=receiver)
            if not auth.ok:
                raise HTTPException(status_code=int(auth.get("status_code") or 403),
                                    detail=auth.get("message"))
            filters["接收方标识"] = auth["receiver_id"]
        elif request.query_params.get("only_mine"):
            raise HTTPException(status_code=401, detail="只读取本人签收需要接收方凭据")

    items, total = service.list_entries(
        filters=filters, keyword=keyword, status=status, page=page, size=size)
    if module == "delivery_receipt":
        from app.services.receipt_consistency import engine as receipt_engine
        items = [receipt_engine._public_receipt(item) for item in items]
    return PageResult(items=items, total=total, page=page, size=size)


@router.get("/{module}/export")
def export_entries(
    module: str,
    request: Request,
    keyword: str | None = Query(default=None),
    status: str | None = Query(default=None),
) -> StreamingResponse:
    service = require_service(module)
    filters = {
        key: value.strip()
        for key, value in request.query_params.items()
        if key in service.LIST_FIELDS and value.strip()
    }

    # 交付回执导出必须识别接收方凭据：错误归属直接 403，合法凭据只导出本人
    # 尚未交付的回执行。无凭据的后台通用 CSV 导出保持兼容。
    if module == "delivery_receipt":
        from app.services.receipt_consistency import engine as receipt_engine

        credential = request_credential(request)
        batch_id = request.query_params.get("batch_id") or request.query_params.get("批次编号")
        resumable = request.query_params.get("resume") or request.query_params.get("breakpoint")
        receiver = (request.query_params.get("receiver_id")
                    or request.query_params.get("receiver")
                    or request.query_params.get("接收方标识"))
        if credential or batch_id or resumable:
            if not credential:
                raise HTTPException(status_code=401, detail="断点续下必须提供接收方断点凭据")
            result = receipt_engine.export_receipts(
                credential, batch_id, receiver_id=receiver,
                start_line=request.query_params.get("start_line"),
                end_line=request.query_params.get("end_line"),
                range_value=request.query_params.get("range"),
            )
            if not result.ok:
                raise HTTPException(
                    status_code=int(result.get("status_code") or 403),
                    detail=result.get("message", "导出凭据校验失败"),
                )
            if request.query_params.get("format") == "json":
                return JSONResponse(result)

            exported_rows = [
                row for receipt_id in result.get("delivered_ids", [])
                if (row := receipt_engine.resolve_receipt(receipt_id)) is not None
            ]
            output = io.StringIO()
            output.write("﻿")
            writer = csv.writer(output, lineterminator="\n")
            writer.writerow(["id", *service.LIST_FIELDS, "status"])
            for item in exported_rows:
                values = [item.get("id"),
                          *(item.get(field, "") for field in service.LIST_FIELDS),
                          item.get("status", "")]
                writer.writerow([
                    "'" + str(value) if str(value or "").startswith(("=", "+", "-", "@")) else value
                    for value in values
                ])
            headers = {
                "X-Batch-Id": str(result.get("batch_id") or ""),
                "X-Delivered-Ids": ",".join(result.get("delivered_ids", [])),
                "X-Duplicate-Ids": ",".join(result.get("duplicate_ids", [])),
                "X-Included-Ranges": str(result.get("included_ranges", [])),
                "X-Range-Included": str(result.get("range_included")),
                "X-Resume-Token": str(result.get("resume_token") or ""),
            }
            return StreamingResponse(
                iter([output.getvalue()]), media_type="text/csv; charset=utf-8",
                headers={**headers,
                         "Content-Disposition": 'attachment; filename="delivery_receipt_resume.csv"'},
            )

        auth_receiver = receiver
        if receiver and "接收方标识" not in filters:
            filters["接收方标识"] = receiver

    items, _ = service.list_entries(
        filters=filters, keyword=keyword, status=status, page=1, size=1_000_000)
    output = io.StringIO()
    output.write("\ufeff")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(["id", *service.LIST_FIELDS, "status"])
    for item in items:
        values = [item.get("id"), *(item.get(field, "") for field in service.LIST_FIELDS),
                  item.get("status", "")]
        writer.writerow([
            "'" + str(value) if str(value or "").startswith(("=", "+", "-", "@")) else value
            for value in values
        ])
    return StreamingResponse(
        iter([output.getvalue()]), media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{module}.csv"'},
    )


@router.get("/{module}/{entry_id}", response_model=dict)
def get_entry(module: str, entry_id: str, request: Request) -> dict[str, Any]:
    service = require_service(module)
    lookup_id: Any = int(entry_id) if entry_id.isdigit() else entry_id
    entry = service.get_entry(lookup_id) if isinstance(lookup_id, int) else None
    if entry is None and module == "delivery_receipt":
        from app.services.receipt_consistency import engine as receipt_engine
        entry = receipt_engine.resolve_receipt(entry_id)
    if entry is None:
        raise HTTPException(status_code=404, detail=f"{service.ENTITY} {entry_id} 不存在或已归档")

    if module == "delivery_receipt":
        credential = request_credential(request)
        if credential:
            from app.services.receipt_consistency import engine as receipt_engine
            auth = receipt_engine.authorize(credential, receipt_engine.receipt_key(entry))
            if not auth.ok:
                raise HTTPException(status_code=int(auth.get("status_code") or 403),
                                    detail=auth.get("message"))
        from app.services.receipt_consistency import engine as receipt_engine
        return receipt_engine._public_receipt(entry)
    return entry


@router.post("/{module}", response_model=ActionResult)
def create_entry(module: str, payload: EntryPayload) -> ActionResult:
    service = require_service(module)
    entry, missing = service.create_entry(payload.values)
    if missing:
        return ActionResult(ok=False, message=f"缺少必填字段：{'、'.join(missing)}")
    return ActionResult(ok=True, message=f"{service.ENTITY}已登记", entry=entry)


@router.post("/{module}/{entry_id}/actions", response_model=ActionResult)
def run_action(module: str, entry_id: str, payload: ActionPayload) -> ActionResult:
    service = require_service(module)
    numeric_id = int(entry_id) if str(entry_id).isdigit() else entry_id
    if not isinstance(numeric_id, int) and module == "delivery_receipt":
        from app.services.receipt_consistency import engine as receipt_engine
        resolved = receipt_engine.resolve_receipt(entry_id)
        if resolved is not None:
            numeric_id = int(resolved["id"])
    if not isinstance(numeric_id, int):
        raise HTTPException(status_code=404, detail=f"{service.ENTITY} {entry_id} 不存在或已归档")
    payload_data = payload.model_dump() if hasattr(payload, "model_dump") else {}
    try:
        service_result = service.run_action(numeric_id, payload.action.strip(), payload_data)
    except TypeError:
        # 兼容尚未接收 payload 参数的自定义服务/测试替身。
        service_result = service.run_action(numeric_id, payload.action.strip())

    if isinstance(service_result, tuple) and len(service_result) == 3:
        ok, message, entry = service_result
    else:
        entry, message = service_result
        ok = entry is not None
    if module == "delivery_receipt" and isinstance(entry, dict):
        from app.services.receipt_consistency import engine as receipt_engine
        entry = receipt_engine._public_receipt(entry)
    return ActionResult(ok=ok, message=message, entry=entry)
