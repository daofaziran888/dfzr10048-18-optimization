"""业务路由汇总：所有模块共用一套资源路由，由领域服务完成分派。"""
from __future__ import annotations

from app.routers import delivery_receipt_api, resource

# 专用一致性路由包含固定/多段路径，必须先于通用 /{module}/{entry_id} 注册。
ROUTERS = [delivery_receipt_api, resource]
