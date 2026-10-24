# GA5 Incident Agent

## Local setup (PowerShell)

```powershell
cd C:\Sanjitaa\IIT\TDS\ga5_incident_agent
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
$env:OPENAI_API_KEY="YOUR_ACTUAL_API_KEY"
$env:OPENAI_MODEL="gpt-4.1-mini"
.\.venv\Scripts\python.exe -m uvicorn main:app --host 127.0.0.1 --port 8000
```

The API key must be configured in the process environment; never commit it. Deploy with `uvicorn main:app --host 0.0.0.0 --port $PORT` and configure `OPENAI_API_KEY` in the hosting provider.

## Important

The service creates dispatch proposals and waits for the grader's authoritative receipts. It does not execute real production tools. The grader's actual sample request and receipts should be used for end-to-end validation before using a limited Check/Save attempt.
