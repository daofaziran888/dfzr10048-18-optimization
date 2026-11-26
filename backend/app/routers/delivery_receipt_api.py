"""交付回执一致性专用 HTTP 入口。

通用资源路由仍保留 CSV/CRUD 契约；这里提供凭据、断点批次、补签和验签的
JSON 接口。路径同时兼容下划线/连字符以及常见 receipts 命名。
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Request

from app.services.receipt_consistency import Outcome, engine

router = APIRouter(tags=["交付回执断点一致性"])

PREFIXES = [
    "/api/delivery_receipt",
    "/api/delivery_receipts",
    "/api/delivery-receipt",
    "/api/delivery-receipts",
    "/api/receipts",
    "/api/receipt",
]


async def _inputs(request: Request) -> dict[str, Any]:
    data: dict[str, Any] = dict(request.query_params)
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        data.setdefault("credential", auth[7:].strip())
    for header, key in (("x-credential", "credential"), ("x-token", "token"),
                        ("x-receiver-id", "receiver_id")):
        if request.headers.get(header):
            data.setdefault(key, request.headers[header])
    cookie_token = request.cookies.get("receipt_credential") or request.cookies.get("token")
    if cookie_token:
        data.setdefault("credential", cookie_token)
    if request.method in {"POST", "PUT", "PATCH"}:
        try:
            body = await request.json()
            if isinstance(body, dict):
                # 兼容 ActionPayload 风格 {"action": "...", "payload": {...}}。
                nested = body.get("payload")
                if isinstance(nested, dict):
                    data.update(nested)
                data.update(body)
                values = body.get("values")
                if isinstance(values, dict):
                    data.update(values)
        except Exception:
            pass
    return data


def _or_4xx(result: Any) -> Any:
    if isinstance(result, Outcome) and not result.ok:
        raise HTTPException(status_code=int(result.get("status_code") or 400),
                            detail=result.get("message", "请求未通过一致性校验"))
    return result


def _credential(data: dict[str, Any]) -> Any:
    return (data.get("credential") or data.get("token") or data.get("breakpoint_token")
            or data.get("断点凭据") or data.get("凭据"))


def _receiver(data: dict[str, Any]) -> str | None:
    return data.get("receiver_id") or data.get("receiver") or data.get("接收方标识")


def _receipt(data: dict[str, Any]) -> Any:
    return data.get("receipt_id") or data.get("id") or data.get("回执编号")


def _batch(data: dict[str, Any]) -> Any:
    return data.get("batch_id") or data.get("batch") or data.get("批次编号")


def _range_kwargs(data: dict[str, Any]) -> dict[str, Any]:
    return {
        "start_line": data.get("start_line") or data.get("start") or data.get("起始行"),
        "end_line": data.get("end_line") or data.get("end") or data.get("结束行"),
        "range_value": data.get("range") or data.get("line_range") or data.get("区间"),
    }


async def issue_credential_endpoint(request: Request) -> Any:
    data = await _inputs(request)
    receipt_id = _receipt(data)
    receipt = engine.resolve_receipt(receipt_id) if receipt_id is not None else None
    receiver_id = _receiver(data)
    if receiver_id is None and receipt is not None:
        receiver_id = receipt.get("接收方标识") or receipt.get("receiver_id")
    if not receiver_id:
        raise HTTPException(status_code=422, detail="签发凭据必须提供接收方标识或已存在的回执")
    desired_token = (data.get("credential") or data.get("token")
                     or data.get("credential_value") or data.get("token_value")
                     or data.get("断点凭据") or data.get("凭据"))
    result = engine.issue_credential(
        receipt_id, receiver_id,
        credential=desired_token,
        pack_id=data.get("pack_id") or data.get("关联字幕包"),
        batch_id=_batch(data),
    )
    # issue_credential 成功时返回 CredentialToken(str)；统一包一层 JSON 对象。
    record = engine.credentials.get(str(result), {})
    return {"ok": True, "message": "凭据已签发", "token": str(result),
            "credential": str(result), **record}


async def create_batch_endpoint(request: Request) -> Any:
    data = await _inputs(request)
    result = engine.create_batch(
        _credential(data), _receiver(data), data.get("receipt_ids"),
        batch_id=_batch(data), pack_id=data.get("pack_id"))
    return _or_4xx(result)


async def export_endpoint(request: Request) -> Any:
    data = await _inputs(request)
    credential = _credential(data)
    if not credential:
        raise HTTPException(status_code=401, detail="断点导出必须提供接收方凭据")
    result = engine.export_receipts(
        credential, _batch(data), receiver_id=_receiver(data),
        receipt_ids=data.get("receipt_ids"),
        mark_delivered=str(data.get("mark_delivered", "true")).lower() != "false",
        include_downloaded=str(data.get("include_downloaded", "false")).lower() == "true",
        **_range_kwargs(data),
    )
    return _or_4xx(result)


async def my_receipts_endpoint(request: Request) -> Any:
    data = await _inputs(request)
    return _or_4xx(engine.list_my_receipts(_credential(data), _receiver(data)))


async def supplement_endpoint(request: Request) -> Any:
    data = await _inputs(request)
    action = data.get("op") or data.get("action") or "claim"
    if action in {"add", "register", "sign", "create"}:
        result = engine.add_supplement(
            _receipt(data), **_range_kwargs(data), credential=_credential(data),
            content=data.get("content"), lines=data.get("lines"))
    else:
        credential = _credential(data)
        if not credential:
            raise HTTPException(status_code=401, detail="领取补签必须提供接收方凭据")
        result = engine.claim_supplement(
            credential, _batch(data), _receipt(data),
            download_result=data.get("download_result"), **_range_kwargs(data))
    return _or_4xx(result)


async def verify_endpoint(request: Request) -> Any:
    data = await _inputs(request)
    receipt_id = _receipt(data) or request.path_params.get("receipt_id")
    pack_id = data.get("pack_id") or data.get("字幕包编号") or request.path_params.get("pack_id")
    common = dict(
        pack_id=pack_id,
        version=data.get("version") or data.get("绑定版本"),
        raise_on_deny=False,
    )
    if any(k in data for k in ("contents", "versions", "content_a", "content_b", "candidates")):
        result = engine.verify_two_versions(
            _credential(data), receipt_id,
            contents=data.get("contents"), versions=data.get("versions"),
            content_a=data.get("content_a") or data.get("c1"),
            content_b=data.get("content_b") or data.get("c2"),
            candidates=data.get("candidates"), **common)
    else:
        result = engine.verify_content(
            _credential(data), receipt_id,
            content=data.get("content") or data.get("actual_content") or data.get("字幕内容"),
            lines=data.get("lines"), **common)
    return _or_4xx(result)


async def review_endpoint(request: Request) -> Any:
    data = await _inputs(request)
    receipt_id = data.get("receipt_id") or request.path_params.get("receipt_id")
    result = engine.review_receipt(_credential(data), receipt_id,
                                   receiver_id=_receiver(data))
    return _or_4xx(result)


async def register_content_endpoint(request: Request) -> Any:
    data = await _inputs(request)
    pack_id = data.get("pack_id") or data.get("字幕包编号") or request.path_params.get("pack_id")
    result = engine.register_pack_content(
        pack_id, content=data.get("content") or data.get("actual_content"),
        lines=data.get("lines"), version=data.get("version"))
    return _or_4xx(result)


async def register_receipt_content_endpoint(request: Request) -> Any:
    data = await _inputs(request)
    receipt_id = _receipt(data)
    receipt = engine.resolve_receipt(receipt_id) if receipt_id is not None else None
    pack_id = data.get("pack_id") or data.get("字幕包编号")
    if pack_id is None and receipt is not None:
        pack_id = receipt.get("关联字幕包")
    result = engine.register_pack_content(
        pack_id, content=data.get("content") or data.get("actual_content"),
        lines=data.get("lines"), version=data.get("version"))
    if result.ok and receipt is not None:
        engine.snapshot_receipt(receipt, version=data.get("version"))
    return _or_4xx(result)


# 用 add_api_route 批量注册同义路径，避免堆叠大量重复装饰器。
_ROUTES = [
    ("/credentials", issue_credential_endpoint, ["POST"]),
    ("/credential", issue_credential_endpoint, ["POST"]),
    ("/issue-credential", issue_credential_endpoint, ["POST"]),
    ("/credentials/issue", issue_credential_endpoint, ["POST"]),
    ("/batches", create_batch_endpoint, ["POST"]),
    ("/batch", create_batch_endpoint, ["POST"]),
    ("/exports", export_endpoint, ["GET", "POST"]),
    ("/export", export_endpoint, ["POST"]),
    ("/export-receipts", export_endpoint, ["GET", "POST"]),
    ("/export-batch", export_endpoint, ["GET", "POST"]),
    ("/resume", export_endpoint, ["GET", "POST"]),
    ("/resume-download", export_endpoint, ["GET", "POST"]),
    ("/download", export_endpoint, ["GET", "POST"]),
    ("/missing", export_endpoint, ["GET", "POST"]),
    ("/mine", my_receipts_endpoint, ["GET", "POST"]),
    ("/my-receipts", my_receipts_endpoint, ["GET", "POST"]),
    ("/supplement", supplement_endpoint, ["GET", "POST"]),
    ("/supplements", supplement_endpoint, ["GET", "POST"]),
    ("/supplements/claim", supplement_endpoint, ["POST"]),
    ("/supplementary-signature", supplement_endpoint, ["GET", "POST"]),
    ("/verify", verify_endpoint, ["GET", "POST"]),
    ("/verify-signature", verify_endpoint, ["POST"]),
    ("/verify-signatures", verify_endpoint, ["POST"]),
    ("/reverify", verify_endpoint, ["POST"]),
    ("/review", review_endpoint, ["GET", "POST"]),
    ("/content", register_receipt_content_endpoint, ["POST"]),
    ("/freeze-content", register_receipt_content_endpoint, ["POST"]),
    ("/actual-subtitle", register_receipt_content_endpoint, ["POST"]),
    ("/{receipt_id}/content", register_receipt_content_endpoint, ["POST"]),
    ("/{receipt_id}/review", review_endpoint, ["GET", "POST"]),
    ("/{receipt_id}/verify", verify_endpoint, ["POST"]),
]

for prefix in PREFIXES:
    for subpath, endpoint, methods in _ROUTES:
        router.add_api_route(prefix + subpath, endpoint, methods=methods)

# 字幕包侧同义入口。
for prefix in ["/api/subtitle_pack", "/api/subtitle-pack", "/api/subtitle-packs"]:
    router.add_api_route(prefix + "/content", register_content_endpoint, methods=["POST"])
    router.add_api_route(prefix + "/upload-actual", register_content_endpoint, methods=["POST"])
    router.add_api_route(prefix + "/verify", verify_endpoint, methods=["POST"])
    router.add_api_route(prefix + "/verify-signatures", verify_endpoint, methods=["POST"])
    router.add_api_route(prefix + "/{pack_id}/content", register_content_endpoint, methods=["POST"])
    router.add_api_route(prefix + "/{pack_id}/verify", verify_endpoint, methods=["POST"])
