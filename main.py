import time
import os
import json
import hmac
import hashlib
import numpy as np
from typing import List, Optional
from fastapi import FastAPI, Depends, HTTPException, Security, Header, Request, status
from fastapi.security.api_key import APIKeyHeader
from pydantic import BaseModel, Field

app = FastAPI(
    title="B2B Operational Middleware Core",
    version="2.3.0",
    description="Stateless Outlier Detection & Reconciliation Engine"
)

API_KEY_NAME = "X-Venture-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=True)

# Dynamic secret loading from environment with fallback for local test
DEFAULT_VAULT = {
    "live_sec_prod_88294a8c1f0": {
        "client_id": "org_charleston_realestate",
        "secret": "sec_k982_charleston_signing_key_x"
    }
}
raw_vault_env = os.getenv("CLIENT_VAULT_JSON")
CLIENT_VAULT = json.loads(raw_vault_env) if raw_vault_env else DEFAULT_VAULT

async def verify_auth(
    request: Request,
    api_key: str = Security(api_key_header),
    x_signature: Optional[str] = Header(None),
    x_timestamp: Optional[str] = Header(None)
):
    if api_key not in CLIENT_VAULT:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized API Key."
        )
    
    # Check 1: Mandatory headers
    if not x_signature or not x_timestamp:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Missing mandatory X-Signature or X-Timestamp header."
        )

    # Check 2: Replay Attack Defense (5-minute tolerance window)
    try:
        req_time = int(x_timestamp)
        now = int(time.time())
        if abs(now - req_time) > 300:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Request timestamp expired. Tolerance is +/- 300 seconds."
            )
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid timestamp format."
        )

    client_record = CLIENT_VAULT[api_key]
    secret_bytes = client_record["secret"].encode("utf-8")
    body_bytes = await request.body()
    
    # Hash over timestamp + body to prevent payload/time decoupling
    message = f"{x_timestamp}.".encode("utf-8") + body_bytes
    computed_sig = hmac.new(secret_bytes, message, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(computed_sig, x_signature):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid payload cryptographic signature."
        )

    return client_record

class RecordItem(BaseModel):
    record_id: str
    metric_value: float
    category: str
    source_timestamp: int = Field(default_factory=lambda: int(time.time()))

class BatchPipelineRequest(BaseModel):
    batch_id: str
    records: List[RecordItem]

class ProcessedRecord(BaseModel):
    record_id: str
    standardized_score: float
    risk_flag: bool
    processing_latency_ms: float

class BatchPipelineResponse(BaseModel):
    batch_id: str
    client_id: str
    total_processed: int
    outliers_flagged: int
    data: List[ProcessedRecord]

@app.post("/v1/pipeline/process", response_model=BatchPipelineResponse)
async def process_batch_mad(
    payload: BatchPipelineRequest,
    client: dict = Depends(verify_auth)
):
    start_time = time.perf_counter()
    if not payload.records:
        raise HTTPException(status_code=400, detail="Empty payload.")

    values = np.array([r.metric_value for r in payload.records], dtype=np.float64)
    med = np.median(values)
    abs_deviations = np.abs(values - med)
    mad = np.median(abs_deviations)

    if mad > 1e-6:
        modified_z = 0.6745 * (values - med) / mad
    else:
        mean_dev = np.mean(abs_deviations)
        modified_z = (values - med) / (mean_dev if mean_dev > 1e-6 else 1.0)

    processed = []
    outlier_count = 0
    OUTLIER_THRESHOLD = 3.5

    for idx, item in enumerate(payload.records):
        score = float(modified_z[idx])
        is_risk = bool(abs(score) > OUTLIER_THRESHOLD)
        if is_risk:
            outlier_count += 1

        latency = (time.perf_counter() - start_time) * 1000.0
        processed.append(
            ProcessedRecord(
                record_id=item.record_id,
                standardized_score=round(score, 4),
                risk_flag=is_risk,
                processing_latency_ms=round(latency, 2)
            )
        )

    return BatchPipelineResponse(
        batch_id=payload.batch_id,
        client_id=client["client_id"],
        total_processed=len(processed),
        outliers_flagged=outlier_count,
        data=processed
    )

@app.get("/healthz")
async def health_check():
    return {"status": "healthy", "timestamp": int(time.time())}
