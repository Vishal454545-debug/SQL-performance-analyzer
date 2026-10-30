SQL PERFORMANCE ANALYZER — SQLITE VERSION

No PostgreSQL or separate database server is required. Python's built-in sqlite3 module uses a local database file.

SETUP (Windows PowerShell)
1. Extract this folder to a location such as Desktop\SQLAnalyzer_SQLite.
2. Open PowerShell in that folder.
3. Create a virtual environment:
   py -m venv .venv
4. Activate it:
   .\.venv\Scripts\Activate.ps1
   If PowerShell blocks activation, use: .\.venv\Scripts\python.exe -m pip install -r requirements.txt
5. Install dependencies:
   python -m pip install -r requirements.txt
6. Start the app on port 5001 (so the existing port 5000 application is not disturbed):
   $env:FLASK_PORT = "5001"
   python app.py
7. Open this URL in your browser:
   http://127.0.0.1:5001

The first start creates sql_analyzer.db beside app.py with sample employees and sales tables.
Try these queries in the dashboard:
  SELECT * FROM employees;
  SELECT department, COUNT(*) AS total FROM employees GROUP BY department;
  SELECT e.name, s.product, s.amount FROM employees e JOIN sales s ON e.employee_id = s.employee_id;

The database query endpoint accepts one read-only SELECT/WITH statement at a time. Query-only mode is enabled for analysis connections. Lexical analysis can still inspect other SQL text, but write statements are blocked from execution.

The dashboard includes SQL lexical analysis, SQLite query execution timing, EXPLAIN QUERY PLAN details, Windows OS/network measurements, and anomaly/bottleneck diagnosis. AI anomaly detection uses a threshold-based cold-start until enough prior workload samples have been recorded, after which IsolationForest can be used if its dependencies are installed.

To stop the server, press Ctrl+C in PowerShell. The existing application on port 5000 is not modified.
