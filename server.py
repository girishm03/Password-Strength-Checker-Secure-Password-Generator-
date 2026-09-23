"""
FastAPI Backend Server for CyberShield Password Security Suite.
Exposes REST endpoints for real-time analysis, CSPRNG password generation, and serves the webpage frontend.
"""
import os
import webbrowser
from typing import List, Optional
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import uvicorn

from core.checker import PasswordChecker, PasswordAnalysis
from core.generator import PasswordGenerator, GeneratedPassword


app = FastAPI(
    title="CyberShield Password Security API",
    description="REST API for password strength checking, entropy calculation, and secure generation",
    version="1.0.0",
)

# Enable CORS for local development flexibility
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Pydantic request models
class AnalyzeRequest(BaseModel):
    password: str = Field(..., description="Password string to analyze")
    check_breach: bool = Field(True, description="Query HaveIBeenPwned API via k-anonymity")


class GenerateRequest(BaseModel):
    mode: str = Field("random", description="Mode: 'random', 'passphrase', 'pin', or 'token'")
    length: int = Field(16, ge=4, le=128)
    use_lower: bool = True
    use_upper: bool = True
    use_digits: bool = True
    use_symbols: bool = True
    exclude_ambiguous: bool = False
    num_words: int = Field(5, ge=3, le=12)
    separator: str = "-"
    capitalize: bool = True
    include_number: bool = True
    include_symbol: bool = False
    block_count: int = Field(4, ge=2, le=8)
    block_length: int = Field(4, ge=2, le=8)


class BulkAnalyzeRequest(BaseModel):
    passwords: List[str]
    check_breach: bool = False


def serialize_analysis(analysis: PasswordAnalysis) -> dict:
    """Helper to convert PasswordAnalysis to JSON serializable dict."""
    crack_times = {}
    for key, item in analysis.entropy.crack_times.items():
        crack_times[key] = {
            "scenario": item.scenario,
            "rate_desc": item.rate_desc,
            "seconds": item.seconds,
            "formatted": item.formatted,
        }

    vulnerabilities = [
        {
            "severity": v.severity,
            "title": v.title,
            "description": v.description,
        }
        for v in analysis.vulnerabilities
    ]

    return {
        "password": analysis.password,
        "score": analysis.score,
        "rating": analysis.rating,
        "length": analysis.length,
        "entropy": {
            "entropy_bits": analysis.entropy.entropy_bits,
            "pool_size": analysis.entropy.pool_size,
            "char_types": analysis.entropy.char_types,
            "search_space": str(analysis.entropy.search_space),
            "crack_times": crack_times,
        },
        "char_counts": analysis.char_counts,
        "vulnerabilities": vulnerabilities,
        "suggestions": analysis.suggestions,
        "nist_compliant": analysis.nist_compliant,
        "is_common_password": analysis.is_common_password,
        "is_breached": analysis.is_breached,
        "breach_count": analysis.breach_count,
        "breach_status_message": analysis.breach_status_message,
    }


def serialize_generated(gen: GeneratedPassword) -> dict:
    return {
        "password": gen.password,
        "length": gen.length,
        "entropy_bits": gen.entropy_bits,
        "mode": gen.mode,
        "pool_size": gen.pool_size,
        "rating": gen.rating,
    }


@app.post("/api/analyze")
async def analyze_password(req: AnalyzeRequest):
    """Analyze a single password's strength, entropy, crack time, and breach status."""
    analysis = PasswordChecker.analyze(req.password, check_breach=req.check_breach)
    return serialize_analysis(analysis)


@app.post("/api/generate")
async def generate_password(req: GenerateRequest):
    """Generate a cryptographically secure password, passphrase, PIN, or token."""
    mode = req.mode.lower()
    if mode == "random":
        gen = PasswordGenerator.generate_random_password(
            length=req.length,
            use_lower=req.use_lower,
            use_upper=req.use_upper,
            use_digits=req.use_digits,
            use_symbols=req.use_symbols,
            exclude_ambiguous=req.exclude_ambiguous,
        )
    elif mode == "passphrase":
        gen = PasswordGenerator.generate_passphrase(
            num_words=req.num_words,
            separator=req.separator,
            capitalize=req.capitalize,
            include_number=req.include_number,
            include_symbol=req.include_symbol,
        )
    elif mode == "pin":
        gen = PasswordGenerator.generate_pin(length=req.length)
    elif mode == "token":
        gen = PasswordGenerator.generate_formatted_token(
            block_count=req.block_count,
            block_length=req.block_length,
            separator=req.separator,
        )
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported mode: {req.mode}")

    return serialize_generated(gen)


@app.post("/api/bulk-analyze")
async def bulk_analyze_passwords(req: BulkAnalyzeRequest):
    """Analyze a list of passwords and calculate aggregate security metrics."""
    cleaned = [p.strip() for p in req.passwords if p.strip()]
    if not cleaned:
        raise HTTPException(status_code=400, detail="Password list cannot be empty.")

    results = []
    total_score = 0
    compliant_count = 0
    weak_count = 0
    breached_count = 0

    for p in cleaned:
        res = PasswordChecker.analyze(p, check_breach=req.check_breach)
        total_score += res.score
        if res.nist_compliant:
            compliant_count += 1
        if res.rating in ["Weak", "Very Weak"]:
            weak_count += 1
        if res.is_breached:
            breached_count += 1

        results.append({
            "password": res.password,
            "score": res.score,
            "rating": res.rating,
            "length": res.length,
            "entropy_bits": res.entropy.entropy_bits,
            "nist_compliant": res.nist_compliant,
            "is_breached": res.is_breached,
            "breach_count": res.breach_count,
            "vulnerabilities_count": len(res.vulnerabilities),
        })

    avg_score = round(total_score / len(cleaned), 1)

    return {
        "summary": {
            "total": len(cleaned),
            "avg_score": avg_score,
            "compliant_count": compliant_count,
            "weak_count": weak_count,
            "breached_count": breached_count,
        },
        "results": results,
    }


# Mount static files from 'public' or 'web' directory at root
base_dir = os.path.dirname(os.path.abspath(__file__))
public_dir = os.path.join(base_dir, "public")
web_dir = os.path.join(base_dir, "web")
static_dir = public_dir if os.path.exists(public_dir) else web_dir
if os.path.exists(static_dir):
    app.mount("/", StaticFiles(directory=static_dir, html=True), name="static")


def start_server():
    port = 8000
    print("\n==================================================================")
    print("  CYBERSHIELD WEB SERVER STARTED")
    print(f"  Access Webpage Front End: http://localhost:{port}")
    print(f"  API Docs:                http://localhost:{port}/docs")
    print("==================================================================\n")
    uvicorn.run("server:app", host="127.0.0.1", port=port, reload=False)


if __name__ == "__main__":
    start_server()
