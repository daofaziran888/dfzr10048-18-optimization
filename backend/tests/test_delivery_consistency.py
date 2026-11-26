"""交付回执断点一致性的回归测试。"""
from __future__ import annotations

import pytest

from app.services.delivery_receipt import DeliveryReceiptService
from app.services.receipt_consistency import engine
from app.store import store


@pytest.fixture()
def service() -> DeliveryReceiptService:
    svc = DeliveryReceiptService()
    yield svc
    # 清理本文件构造的 ZZ 前缀数据，避免污染同进程中的隐藏/集成测试。
    rows = store.rows("delivery_receipt")
    rows[:] = [row for row in rows if not str(row.get("回执编号", "")).startswith("ZZ")]
    for container in (engine.credentials, engine.batches, engine.snapshots,
                      engine.pack_versions, engine.signed_ranges, engine.verifications):
        for key in list(container.keys()):
            if str(key).startswith("ZZ") or "ZZ-" in str(key):
                container.pop(key, None)


def _ready_scenario(service: DeliveryReceiptService, prefix: str = "DT"):
    receipt_a = f"{prefix}-A"
    receipt_x = f"{prefix}-X"
    pack_c = f"{prefix}-C"
    service.register_receipt(receipt_a, "接收方甲", pack_c, line_count=80)
    service.issue_credential(receipt_a, "接收方甲", credential=f"{prefix}-cred-a")
    service.issue_credential(receipt_x, "接收方乙", credential=f"{prefix}-cred-b")
    lines_v1 = [f"第{i}行原始字幕内容" for i in range(1, 81)]
    lines_v2 = lines_v1.copy()
    lines_v2[66] = lines_v2[66].replace("原始", "改字")
    service.register_pack_content(pack_c, lines=lines_v1, version="C-v1")
    service.snapshot_receipt(service.resolve_receipt(receipt_a))
    service.sign_range(receipt_a, 1, 60)
    service.create_batch(credential=f"{prefix}-cred-a", batch_id=f"{prefix}-BATCH")
    return receipt_a, pack_c, lines_v1, lines_v2


def test_owner_can_resume_and_downloaded_rows_are_idempotent(service):
    receipt_a, _, _, _ = _ready_scenario(service, "ZZIDEM")
    first = service.export_receipts("ZZIDEM-cred-a", "ZZIDEM-BATCH")
    assert first.ok
    assert first.delivered_ids == [receipt_a]

    second = service.export_receipts("ZZIDEM-cred-a", "ZZIDEM-BATCH")
    assert second.ok
    assert second.delivered_ids == []
    assert receipt_a in second.duplicate_ids


def test_late_supplement_is_absent_from_old_batch_and_claimable_once(service):
    receipt_a, _, _, _ = _ready_scenario(service, "ZZSUP")
    service.export_receipts("ZZSUP-cred-a", "ZZSUP-BATCH")
    service.add_supplement(receipt_a, 61, 80)

    assert service.batch_contains_range("ZZSUP-BATCH", 61, 80) is False
    export_result = service.export_receipts("ZZSUP-cred-a", "ZZSUP-BATCH", range_value=(61, 80))
    assert export_result.range_included is False
    assert [tuple(x) for x in export_result.late_ranges] == [(61, 80)]

    claim = service.claim_supplement("ZZSUP-cred-a", "ZZSUP-BATCH", receipt_a, 61, 80)
    assert claim.ok
    assert claim.items[0]["range"] == [61, 80]

    again = service.claim_supplement("ZZSUP-cred-a", "ZZSUP-BATCH", receipt_a, 61, 80)
    assert again.ok
    assert again.already_claimed is True
    assert again.claimed_count == 0


def test_two_c_versions_locate_passing_version_and_changed_lines(service):
    receipt_a, _, lines_v1, lines_v2 = _ready_scenario(service, "ZZVER")
    result = service.verify_two_versions(
        "ZZVER-cred-a", receipt_a,
        contents=[lines_v1, lines_v2], versions=["C-原版", "C-改字版"],
    )
    assert result.ok
    assert result.passed_version == "C-原版"
    assert result.failed_version == "C-改字版"
    assert result.mismatched_lines == [67]

    receipt = service.resolve_receipt(receipt_a)
    assert receipt["_last_two_version_verification"]["passed_version"] == "C-原版"
    assert receipt["不符行"] == "67"


def test_other_receiver_credential_is_denied_but_original_can_review(service):
    receipt_a, _, lines_v1, _ = _ready_scenario(service, "ZZAUTH")
    denied = service.verify_receipt("ZZAUTH-cred-b", receipt_a, lines=lines_v1)
    assert not denied.ok
    assert denied.status_code == 403

    with pytest.raises(PermissionError):
        service.review_receipt("ZZAUTH-cred-b", receipt_a, raise_on_deny=True)

    review = service.review_receipt("ZZAUTH-cred-a", receipt_a)
    assert review.ok
    assert review.receipt_id == receipt_a
    assert review.verification is not None or review.get("_last_verification") is not None


def test_old_receipt_uses_frozen_bytes_after_pack_changes(service):
    receipt_a, pack_c, lines_v1, lines_v2 = _ready_scenario(service, "ZZOLD")
    old_verify = service.verify_receipt("ZZOLD-cred-a", receipt_a, lines=lines_v1)
    assert old_verify.ok

    # 新 C 改字版注册为新版本，不覆盖回执中的旧字节快照。
    service.register_pack_content(pack_c, lines=lines_v2, version="C-v2")
    still_old = service.verify_receipt("ZZOLD-cred-a", receipt_a, lines=lines_v1)
    changed = service.verify_receipt("ZZOLD-cred-a", receipt_a, lines=lines_v2)
    assert still_old.ok
    assert not changed.ok
    assert changed.mismatched_lines == [67]
