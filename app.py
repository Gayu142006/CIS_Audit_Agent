import os
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Optional

from core.connector import get_connector
from core.collector import Collector
from core.rule_engine import RuleEngine
from core.prioritizer import Prioritizer
from core.reporter import Reporter

app = FastAPI(title="CIS Audit Agent")

# Mount static directory for frontend
os.makedirs("static", exist_ok=True)
app.mount("/static", StaticFiles(directory="static", html=True), name="static")

class AuditRequest(BaseModel):
    target_type: str  # 'local' or 'ssh'
    host: Optional[str] = None
    port: Optional[int] = 22
    username: Optional[str] = None
    password: Optional[str] = None
    key_path: Optional[str] = None

@app.post("/api/audit")
def trigger_audit(req: AuditRequest):
    env_vars = {}
    if req.target_type == "ssh":
        if not req.host or not req.username:
            raise HTTPException(status_code=400, detail="SSH host and username are required.")
        env_vars = {
            "SSH_HOST": req.host,
            "SSH_PORT": str(req.port),
            "SSH_USER": req.username,
        }
        if req.password:
            env_vars["SSH_PASSWORD"] = req.password
        if req.key_path:
            env_vars["SSH_KEY_PATH"] = req.key_path

    try:
        # 1. Connect
        connector = get_connector(req.target_type, env_vars)
        
        # 2. Collect
        collector = Collector(connector)
        raw_results = collector.run_all()
        
        # 3. Rule Engine
        rule_engine = RuleEngine()
        evaluated = rule_engine.evaluate(raw_results)
        
        # 4. Prioritize
        prioritizer = Prioritizer()
        fix_list = prioritizer.prioritize(evaluated)
        
        # 5. Report
        reporter = Reporter()
        target_name = req.host if req.target_type == "ssh" else "localhost"
        json_path, md_path, report_data = reporter.generate(evaluated, fix_list, target_name)
        
        if req.target_type == "ssh" and hasattr(connector, "close"):
            connector.close()
            
        return {
            "message": "Audit completed successfully",
            "report_data": report_data
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/")
def root():
    # Redirect root to /static/index.html
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/static/index.html")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
