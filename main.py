import uvicorn
from fastapi import FastAPI, HTTPException, BackgroundTasks, Query
from dotenv import load_dotenv

load_dotenv()

from service.scanner import scan
from databases.scanner_database import ScannerExecution

app = FastAPI()

@app.get("/")
def read_root():
    return {"service": "colcert-generador-informe", "status": "ok"}

@app.get("/scan")
def get_scans(limit: int = Query(10, le=1000)):
    scanner_db = ScannerExecution()
    return scanner_db.get_last_execs(limit)

@app.get("/scan/{id}")
def get_scan_by_id(id: int):
    scanner_db = ScannerExecution()
    result = scanner_db.get_exec(id)

    if not result:
        raise HTTPException(status_code=404, detail="Execution not found")

    return result

@app.post('/scan')
def post_scan(body: dict, background_tasks: BackgroundTasks):
    
    if 'domain' not in body:
        raise HTTPException(status_code=400, detail="Missing 'domain' in request body")
    
    scanner_db = ScannerExecution()
    scanner_db.create_exec(body['domain'])

    background_tasks.add_task(
        scan,
        scanner_db,
        body['domain'],
        "./templates/report_osint.docx"
    )

    return {"status": "processing", "id": scanner_db.exec_id}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000, proxy_headers=True)