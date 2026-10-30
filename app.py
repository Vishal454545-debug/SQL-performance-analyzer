import os
import re
import json
import time
import socket
import sqlite3
import subprocess
import threading
from collections import deque
from datetime import datetime, timezone

from flask import Flask, jsonify, request, send_file
from flask_cors import CORS

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
except ImportError:
    np = None
    IsolationForest = None

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": [
    "http://localhost:5500", "http://127.0.0.1:5500",
    "http://localhost:8000", "http://127.0.0.1:8000"
]}})

# SQLite uses a local file; no separate database server or password is required.
DB_PATH = os.path.abspath(os.getenv(
    "SQLITE_DB_PATH", os.path.join(os.path.dirname(os.path.abspath(__file__)), "sql_analyzer.db")
))

QUERY_TIMEOUT_MS = int(os.getenv("DB_QUERY_TIMEOUT_MS", "10000"))
MAX_SQL_LENGTH = 50000
HISTORY_LIMIT = 500
MIN_MODEL_SAMPLES = 20

history_lock = threading.Lock()
workload_history = deque(maxlen=HISTORY_LIMIT)
anomaly_model = None
model_sample_count = 0


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def get_windows_metrics():
    """Return system-level Windows metrics. Values are not query-specific."""
    script = r'''
    $os = Get-CimInstance Win32_OperatingSystem
    $cpu = Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average
    $disk = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" |
        Measure-Object -Property FreeSpace -Sum
    $diskTotal = Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" |
        Measure-Object -Property Size -Sum
    [PSCustomObject]@{
        cpu_percent = if ($null -ne $cpu.Average) { [math]::Round($cpu.Average, 2) } else { $null }
        total_ram_mb = [math]::Round($os.TotalVisibleMemorySize / 1024, 2)
        free_ram_mb = [math]::Round($os.FreePhysicalMemory / 1024, 2)
        process_count = (Get-Process).Count
        disk_total_gb = if ($diskTotal.Sum) { [math]::Round($diskTotal.Sum / 1GB, 2) } else { $null }
        disk_free_gb = if ($disk.Sum) { [math]::Round($disk.Sum / 1GB, 2) } else { $null }
    } | ConvertTo-Json -Compress
    '''
    result = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True, text=True, timeout=15
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "PowerShell metrics command failed")
    metrics = json.loads(result.stdout)
    total = metrics.get("total_ram_mb") or 0
    free = metrics.get("free_ram_mb") or 0
    metrics["memory_percent"] = round((total - free) / total * 100, 2) if total else None
    if metrics.get("disk_total_gb"):
        metrics["disk_used_percent"] = round(
            (metrics["disk_total_gb"] - metrics["disk_free_gb"]) / metrics["disk_total_gb"] * 100, 2
        )
    else:
        metrics["disk_used_percent"] = None
    return metrics


def get_network_metrics():
    script = r'''
    $stats = @(Get-NetAdapterStatistics -ErrorAction SilentlyContinue)
    $adapters = @(Get-NetAdapter -ErrorAction SilentlyContinue)
    $traffic = [PSCustomObject]@{
        bytes_sent = [long](($stats | Measure-Object -Property SentBytes -Sum).Sum)
        bytes_received = [long](($stats | Measure-Object -Property ReceivedBytes -Sum).Sum)
        packets_sent = [long](($stats | Measure-Object -Property SentUnicastPackets -Sum).Sum)
        packets_received = [long](($stats | Measure-Object -Property ReceivedUnicastPackets -Sum).Sum)
        errors_in = [long](($stats | Measure-Object -Property ReceivedPacketErrors -Sum).Sum)
        errors_out = [long](($stats | Measure-Object -Property OutboundPacketErrors -Sum).Sum)
        drops_in = [long](($stats | Measure-Object -Property ReceivedDiscardedPackets -Sum).Sum)
        drops_out = [long](($stats | Measure-Object -Property OutboundDiscardedPackets -Sum).Sum)
    }
    $interfaces = @(
        foreach ($adapter in $adapters) {
            $ip = Get-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1
            [PSCustomObject]@{
                name = $adapter.Name
                is_up = ($adapter.Status -eq "Up")
                mtu = if ($ip) { $ip.NlMtu } else { 0 }
                link_speed = $adapter.LinkSpeed
            }
        }
    )
    [PSCustomObject]@{ traffic = $traffic; interfaces = $interfaces } | ConvertTo-Json -Depth 5 -Compress
    '''
    result = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True, text=True, timeout=15
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "PowerShell network command failed")
    data = json.loads(result.stdout)
    latency_ms, latency_error = None, None
    # This tests the local Flask listener, NOT PostgreSQL query/network latency.
    try:
        start = time.perf_counter()
        with socket.create_connection(("127.0.0.1", int(os.getenv("FLASK_PORT", "5001"))), timeout=2):
            latency_ms = round((time.perf_counter() - start) * 1000, 2)
    except OSError as exc:
        latency_error = str(exc)
    interfaces = {
        item["name"]: {"is_up": item["is_up"], "mtu": item["mtu"], "link_speed": item["link_speed"]}
        for item in data.get("interfaces", [])
    }
    return {
        "status": "success", "timestamp": timestamp(), "traffic": data.get("traffic", {}),
        "interfaces": interfaces, "local_tcp_latency_ms": latency_ms,
        "latency_description": "Round-trip time to the local Flask TCP listener; not database latency.",
        "latency_error": latency_error
    }


KEYWORDS = {
    "SELECT", "FROM", "WHERE", "JOIN", "INNER", "LEFT", "RIGHT", "FULL", "OUTER", "CROSS", "ON",
    "GROUP", "BY", "ORDER", "HAVING", "LIMIT", "OFFSET", "FETCH", "INSERT", "INTO", "VALUES",
    "UPDATE", "SET", "DELETE", "CREATE", "TABLE", "ALTER", "DROP", "DISTINCT", "AS", "AND", "OR",
    "NOT", "NULL", "IS", "IN", "BETWEEN", "LIKE", "ILIKE", "CASE", "WHEN", "THEN", "ELSE", "END",
    "UNION", "ALL", "EXISTS", "COUNT", "SUM", "AVG", "MIN", "MAX", "WITH", "RECURSIVE", "TRUE", "FALSE",
    "RETURNING", "CAST", "INTERVAL", "EXPLAIN", "ANALYZE"
}

TOKEN_PATTERN = re.compile(
    r"(?P<COMMENT>--[^\n]*|/\*[\s\S]*?\*/)"
    r"|(?P<STRING>'(?:''|[^'])*')"
    r'|(?P<QUOTED_IDENTIFIER>"(?:""|[^"])*")'
    r"|(?P<NUMBER>\b\d+(?:\.\d+)?\b)"
    r"|(?P<IDENTIFIER>[A-Za-z_][A-Za-z0-9_$]*)"
    r"|(?P<OPERATOR><=|>=|<>|!=|:=|\|\||[-+*/%=<>])"
    r"|(?P<DELIMITER>[(),.;])"
    r"|(?P<WHITESPACE>\s+)"
    r"|(?P<UNKNOWN>.)"
)


def analyze_sql(sql):
    tokens = []
    counts = {"keywords": 0, "identifiers": 0, "literals": 0, "operators": 0,
              "delimiters": 0, "comments": 0, "unknown": 0}
    for match in TOKEN_PATTERN.finditer(sql):
        kind, value = match.lastgroup, match.group()
        if kind == "WHITESPACE":
            continue
        if kind == "IDENTIFIER":
            if value.upper() in KEYWORDS:
                kind = "KEYWORD"
                counts["keywords"] += 1
            else:
                counts["identifiers"] += 1
        elif kind in ("STRING", "NUMBER"):
            kind = "LITERAL"
            counts["literals"] += 1
        elif kind == "QUOTED_IDENTIFIER":
            kind = "IDENTIFIER"
            counts["identifiers"] += 1
        elif kind == "OPERATOR":
            counts["operators"] += 1
        elif kind == "DELIMITER":
            counts["delimiters"] += 1
        elif kind == "COMMENT":
            counts["comments"] += 1
        elif kind == "UNKNOWN":
            counts["unknown"] += 1
        tokens.append({"type": kind, "value": value, "position": match.start()})
    statement_count = len([part for part in sql.split(";") if part.strip()])
    # These are lexical indicators, not a full SQL parser.
    return {
        "tokens": tokens, "counts": counts, "total_tokens": len(tokens),
        "statement_count": statement_count, "sql_characters": len(sql),
        "complexity_indicators": {
            "join_count": len(re.findall(r"\bJOIN\b", sql, re.I)),
            "subquery_keyword_count": len(re.findall(r"\bSELECT\b", sql, re.I)),
            "where_clause_count": len(re.findall(r"\bWHERE\b", sql, re.I))
        }
    }


def ensure_read_only_sql(sql):
    """Conservative gate; SQLite query_only mode is the primary protection."""
    cleaned = re.sub(r"/\*[\s\S]*?\*/", " ", sql)
    cleaned = re.sub(r"--[^\n]*", " ", cleaned).strip()
    if not cleaned:
        raise ValueError("SQL query is empty after removing comments.")
    # Permit one statement, with an optional trailing semicolon only.
    without_trailing_semicolon = cleaned.rstrip().removesuffix(";").strip()
    if ";" in without_trailing_semicolon:
        raise ValueError("Database execution accepts one SQL statement at a time. Analyze batches lexically, then run statements separately.")
    first = re.match(r"([A-Za-z]+)", without_trailing_semicolon)
    if not first or first.group(1).upper() not in {"SELECT", "WITH"}:
        raise ValueError("Only read-only SELECT or WITH queries can be executed by this endpoint.")
    forbidden = re.compile(
        r"\b(INSERT|UPDATE|DELETE|MERGE|CALL|DO|COPY|CREATE|ALTER|DROP|TRUNCATE|GRANT|REVOKE|VACUUM|ANALYZE|REFRESH|LOCK|SET|RESET|LISTEN|NOTIFY|NEXTVAL|PG_TERMINATE_BACKEND|PG_CANCEL_BACKEND|LO_IMPORT|LO_EXPORT)\b",
        re.I
    )
    # Strip string literals before checking forbidden tokens to avoid false positives.
    no_strings = re.sub(r"'(?:''|[^'])*'", "''", without_trailing_semicolon)
    if forbidden.search(no_strings):
        raise ValueError("The query contains a command or function blocked by the read-only safety policy.")
    return without_trailing_semicolon


def db_connect(read_only=True):
    """Open the local SQLite database. Query connections are read-only."""
    if not os.path.isfile(DB_PATH):
        initialize_database()
    if read_only:
        conn = sqlite3.connect(f"file:{DB_PATH.replace(chr(92), '/') }?mode=ro", uri=True, timeout=5)
    else:
        conn = sqlite3.connect(DB_PATH, timeout=5)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only = ON")
    return conn


def initialize_database():
    """Create a small demo schema only if the database file does not exist."""
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=5)
    try:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS employees (
                employee_id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                department TEXT NOT NULL,
                salary REAL NOT NULL,
                city TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sales (
                sale_id INTEGER PRIMARY KEY,
                employee_id INTEGER NOT NULL,
                product TEXT NOT NULL,
                amount REAL NOT NULL,
                sale_date TEXT NOT NULL,
                FOREIGN KEY(employee_id) REFERENCES employees(employee_id)
            );
        """)
        count = conn.execute("SELECT COUNT(*) FROM employees").fetchone()[0]
        if count == 0:
            conn.executemany(
                "INSERT INTO employees (employee_id, name, department, salary, city) VALUES (?, ?, ?, ?, ?)",
                [(1, "Aarav", "Engineering", 85000, "Vellore"),
                 (2, "Diya", "Sales", 62000, "Chennai"),
                 (3, "Kabir", "Engineering", 91000, "Bengaluru"),
                 (4, "Meera", "HR", 58000, "Vellore"),
                 (5, "Ishaan", "Sales", 67000, "Chennai")]
            )
            conn.executemany(
                "INSERT INTO sales (sale_id, employee_id, product, amount, sale_date) VALUES (?, ?, ?, ?, ?)",
                [(1, 2, "Laptop", 75000, "2026-01-12"),
                 (2, 5, "Monitor", 18000, "2026-02-03"),
                 (3, 2, "Keyboard", 2500, "2026-02-15"),
                 (4, 1, "Laptop", 78000, "2026-03-01"),
                 (5, 5, "Mouse", 1200, "2026-03-11")]
            )
        conn.commit()
    finally:
        conn.close()


def extract_plan_nodes(plan, output=None):
    output = output or []
    if isinstance(plan, dict):
        if "Node Type" in plan:
            output.append({
                "node_type": plan.get("Node Type"),
                "relation": plan.get("Relation Name"),
                "index_name": plan.get("Index Name"),
                "estimated_rows": plan.get("Plan Rows"),
                "estimated_startup_cost": plan.get("Startup Cost"),
                "estimated_total_cost": plan.get("Total Cost"),
                "actual_rows": plan.get("Actual Rows"),
                "actual_total_time_ms": plan.get("Actual Total Time")
            })
        for value in plan.values():
            if isinstance(value, (dict, list)):
                extract_plan_nodes(value, output)
    elif isinstance(plan, list):
        for value in plan:
            extract_plan_nodes(value, output)
    return output


def execute_database_query(sql):
    safe_sql = ensure_read_only_sql(sql)
    result = {
        "status": "unavailable", "database": "SQLite", "execution_time_ms": None,
        "rows_returned": None, "columns": [], "sample_rows": [], "plan": None,
        "plan_nodes": [], "scan_types": [], "warnings": []
    }
    conn = db_connect(read_only=True)
    try:
        # EXPLAIN QUERY PLAN describes the planned access path without running the query.
        plan_rows = conn.execute("EXPLAIN QUERY PLAN " + safe_sql).fetchall()
        result["plan"] = [dict(row) for row in plan_rows]
        result["plan_nodes"] = [
            {"node_type": str(row[3]).split(" ")[0], "detail": row[3], "estimated_rows": None,
             "estimated_startup_cost": None, "estimated_total_cost": None}
            for row in plan_rows
        ]
        result["scan_types"] = [row[3] for row in plan_rows]
        start = time.perf_counter()
        cursor = conn.execute(safe_sql)
        elapsed_ms = (time.perf_counter() - start) * 1000
        result["execution_time_ms"] = round(elapsed_ms, 3)
        if cursor.description:
            result["columns"] = [col[0] for col in cursor.description]
            rows = cursor.fetchmany(101)
            result["rows_returned"] = min(len(rows), 100)
            result["sample_rows"] = [dict(row) for row in rows[:100]]
            if len(rows) > 100:
                result["warnings"].append("Only the first 100 rows are returned to the dashboard.")
        else:
            result["rows_returned"] = 0
        result["status"] = "success"
        result["database_file"] = os.path.basename(DB_PATH)
    finally:
        conn.close()
    return result


def numeric_features(database, os_metrics, network):
    plan_nodes = database.get("plan_nodes") or []
    seq_scans = sum(1 for node in plan_nodes if node.get("node_type") == "Seq Scan" or "SCAN" in str(node.get("detail", "")).upper() and "USING INDEX" not in str(node.get("detail", "")).upper())
    index_scans = sum(1 for node in plan_nodes if "Index" in str(node.get("node_type", "")))
    root = None
    try:
        root = database.get("plan")[0].get("Plan")
    except (TypeError, IndexError, AttributeError):
        pass
    traffic = network.get("traffic", {}) if isinstance(network, dict) else {}
    return {
        "execution_time_ms": float(database.get("execution_time_ms") or 0),
        "rows_returned": float(database.get("rows_returned") or 0),
        "plan_total_cost": float((root or {}).get("Total Cost") or 0),
        "plan_estimated_rows": float((root or {}).get("Plan Rows") or 0),
        "seq_scan_count": float(seq_scans),
        "index_scan_count": float(index_scans),
        "cpu_percent": float(os_metrics.get("cpu_percent") or 0),
        "memory_percent": float(os_metrics.get("memory_percent") or 0),
        "disk_used_percent": float(os_metrics.get("disk_used_percent") or 0),
        "process_count": float(os_metrics.get("process_count") or 0),
        "network_errors": float(traffic.get("errors_in") or 0) + float(traffic.get("errors_out") or 0),
        "network_drops": float(traffic.get("drops_in") or 0) + float(traffic.get("drops_out") or 0),
    }



def detect_anomaly(features):
    global anomaly_model, model_sample_count

    vector_keys = list(features.keys())
    vector = [features[key] for key in vector_keys]

    with history_lock:
        prior = list(workload_history)
        result = None

        # Use Isolation Forest when enough real workload history exists.
        if (
            IsolationForest is not None
            and np is not None
            and len(prior) >= MIN_MODEL_SAMPLES
        ):
            try:
                matrix = np.array(
                    [
                        [sample.get(key, 0.0) for key in vector_keys]
                        for sample in prior
                    ],
                    dtype=float,
                )

                candidate = IsolationForest(
                    n_estimators=100,
                    contamination="auto",
                    random_state=42,
                )

                candidate.fit(matrix)

                current_vector = np.array(
                    [vector],
                    dtype=float,
                )

                prediction = int(candidate.predict(current_vector)[0])
                score = float(
                    candidate.decision_function(current_vector)[0]
                )

                anomaly_detected = prediction == -1

                anomaly_model = candidate
                model_sample_count = len(prior)

                result = {
                    "is_anomaly": anomaly_detected,
                    "status": (
                        "Anomaly Detected"
                        if anomaly_detected
                        else "No Anomaly Detected"
                    ),
                    "method": "IsolationForest",
                    "anomaly_score": round(score, 5),
                    "baseline_samples": len(prior),
                    "explanation": (
                        "The workload differs from previously observed "
                        "workload patterns."
                        if anomaly_detected
                        else
                        "The workload is consistent with the patterns "
                        "observed in the current baseline."
                    ),
                }

            except Exception:
                # Fall back to runtime thresholds if ML fitting fails.
                result = None

        # Runtime-based fallback: no minimum-sample message is displayed.
        if result is None:
            reasons = []

            if features.get("execution_time_ms", 0) >= 1000:
                reasons.append(
                    "Query execution took at least 1 second"
                )

            if features.get("cpu_percent", 0) >= 90:
                reasons.append(
                    "System CPU usage is at least 90%"
                )

            if features.get("memory_percent", 0) >= 90:
                reasons.append(
                    "System memory usage is at least 90%"
                )

            if features.get("disk_used_percent", 0) >= 95:
                reasons.append(
                    "System disk space usage is at least 95%"
                )

            if (
                features.get("network_errors", 0) > 0
                or features.get("network_drops", 0) > 0
            ):
                reasons.append(
                    "Network interface errors or drops were recorded"
                )

            anomaly_detected = bool(reasons)

            result = {
                "is_anomaly": anomaly_detected,
                "status": (
                    "Anomaly Detected"
                    if anomaly_detected
                    else "No Anomaly Detected"
                ),
                "method": "runtime_thresholds",
                "anomaly_score": None,
                "baseline_samples": len(prior),
                "explanation": (
                    "; ".join(reasons)
                    if reasons
                    else "No anomaly detected by the current runtime checks."
                ),
            }

        # Record the actual workload for future comparisons.
        workload_history.append(features.copy())

    return result



def detect_bottlenecks(database, os_metrics, network):
    findings = []
    duration = database.get("execution_time_ms")
    nodes = database.get("plan_nodes") or []
    if duration is not None:
        if duration >= 1000:
            findings.append({"area": "database", "severity": "high", "finding": "Query execution took at least 1 second.",
                             "evidence": {"execution_time_ms": duration},
                             "recommendation": "Inspect the execution plan, row estimates, predicates, joins, and available indexes."})
        elif duration >= 250:
            findings.append({"area": "database", "severity": "medium", "finding": "Query execution took at least 250 ms.",
                             "evidence": {"execution_time_ms": duration},
                             "recommendation": "Compare repeated runs and inspect the plan before changing indexes."})
    seq_scans = [node for node in nodes if node.get("node_type") == "Seq Scan" or ("SCAN" in str(node.get("detail", "")).upper() and "USING INDEX" not in str(node.get("detail", "")).upper())]
    for node in seq_scans:
        if (node.get("estimated_rows") or 0) >= 10000:
            findings.append({"area": "query_plan", "severity": "medium", "finding": "Query plan includes a table scan; check whether filtering or an index could reduce scanned rows.",
                             "evidence": node,
                             "recommendation": "Check filter selectivity and consider an appropriate index; a table scan can still be optimal for small tables or low-selectivity queries."})
    cpu = os_metrics.get("cpu_percent")
    if cpu is not None and cpu >= 90:
        findings.append({"area": "cpu", "severity": "high", "finding": "System CPU utilization is very high.",
                         "evidence": {"cpu_percent": cpu}, "recommendation": "Compare CPU samples during repeated query runs and inspect competing processes."})
    elif cpu is not None and cpu >= 75:
        findings.append({"area": "cpu", "severity": "medium", "finding": "System CPU utilization is elevated.",
                         "evidence": {"cpu_percent": cpu}, "recommendation": "Repeat the workload and compare CPU utilization with query duration."})
    memory = os_metrics.get("memory_percent")
    if memory is not None and memory >= 90:
        findings.append({"area": "memory", "severity": "high", "finding": "System memory utilization is very high.",
                         "evidence": {"memory_percent": memory}, "recommendation": "Check memory pressure and database cache/work-memory settings before tuning."})
    disk = os_metrics.get("disk_used_percent")
    if disk is not None and disk >= 95:
        findings.append({"area": "disk_capacity", "severity": "high", "finding": "System disk space is nearly exhausted.",
                         "evidence": {"disk_used_percent": disk}, "recommendation": "Free or expand disk space. This indicates capacity pressure, not necessarily slow disk I/O."})
    traffic = network.get("traffic", {}) if isinstance(network, dict) else {}
    errors = int(traffic.get("errors_in") or 0) + int(traffic.get("errors_out") or 0)
    drops = int(traffic.get("drops_in") or 0) + int(traffic.get("drops_out") or 0)
    if errors or drops:
        findings.append({"area": "network", "severity": "medium", "finding": "Network interface error/drop counters are non-zero.",
                         "evidence": {"errors": errors, "drops": drops},
                         "recommendation": "Compare these cumulative counters over time; non-zero totals alone do not prove the current query is network-bound."})
    if not findings:
        findings.append({"area": "overall", "severity": "info", "finding": "No configured bottleneck threshold was crossed.",
                         "evidence": {"execution_time_ms": duration, "cpu_percent": cpu, "memory_percent": memory},
                         "recommendation": "Use repeated workload runs and compare execution plans and measurements; no finding is not proof that the query is optimal."})
    return {"findings": findings, "count": len(findings), "note": "OS and adapter metrics are system-level; they do not independently prove query causation."}


@app.get("/api/metrics/os")
def os_metrics():
    try:
        metrics = get_windows_metrics()
        metrics["timestamp"] = timestamp()
        metrics["scope"] = "whole Windows system, not an individual query"
        return jsonify(metrics)
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500


@app.get("/api/metrics/network")
def network_metrics():
    try:
        return jsonify(get_network_metrics())
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500


@app.get("/api/metrics/database")
def database_health():
    try:
        if not os.path.isfile(DB_PATH):
            initialize_database()
        with db_connect(read_only=True) as conn:
            tables = [row[0] for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
            ).fetchall()]
        return jsonify({"status": "success", "timestamp": timestamp(),
                        "connection": {"database": os.path.basename(DB_PATH), "engine": "SQLite", "tables": tables}})
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 503


@app.route("/api/analyze", methods=["POST"])
def analyze():
    data = request.get_json(silent=True) or {}
    sql = data.get("sql", "")
    if not isinstance(sql, str) or not sql.strip():
        return jsonify({"status": "error", "message": "Please provide a non-empty SQL query."}), 400
    if len(sql) > MAX_SQL_LENGTH:
        return jsonify({"status": "error", "message": f"SQL query must be {MAX_SQL_LENGTH:,} characters or fewer."}), 400

    lexical = analyze_sql(sql)
    response = {
        "status": "success", "timestamp": timestamp(), "lexical_analysis": lexical,
        "note": "OS and adapter metrics describe system conditions, not individual query execution."
    }
    # Default behavior: run database analysis. Set {"execute": false} to request lexical-only analysis.
    if data.get("execute", True) is False:
        response["database_analysis"] = {"status": "skipped", "message": "Database execution disabled by request."}
        response["ai_analysis"] = {"status": "skipped", "message": "AI analysis requires workload measurements."}
        return jsonify(response)

    try:
        database = execute_database_query(sql)
    except ValueError as exc:
        return jsonify({"status": "error", "message": str(exc), "lexical_analysis": lexical,
                        "database_analysis": {"status": "blocked"}}), 400
    except Exception as exc:
        return jsonify({"status": "success", "timestamp": timestamp(), "lexical_analysis": lexical,
                        "database_analysis": {"status": "error", "message": str(exc)},
                        "ai_analysis": {"status": "unavailable", "message": "AI diagnosis skipped because database execution did not complete."},
                        "note": "Lexical analysis succeeded; database analysis failed."}), 200

    try:
        os_data = get_windows_metrics()
    except Exception as exc:
        os_data = {"cpu_percent": None, "memory_percent": None, "disk_used_percent": None,
                   "process_count": None, "metrics_error": str(exc)}
    try:
        network_data = get_network_metrics()
    except Exception as exc:
        network_data = {"traffic": {}, "interfaces": {}, "metrics_error": str(exc)}

    features = numeric_features(database, os_data, network_data)
    anomaly = detect_anomaly(features)
    bottlenecks = detect_bottlenecks(database, os_data, network_data)
    response["database_analysis"] = database
    response["os_metrics"] = os_data
    response["network_metrics"] = network_data
    response["ai_analysis"] = {
        "status": "success", "model": anomaly["method"], "anomaly_detection": anomaly,
        "bottleneck_detection": bottlenecks,
        "feature_values": features,
        "limitations": [
            "IsolationForest activates after enough prior samples; early results use conservative thresholds.",
            "A sequential scan is not automatically bad; table size and selectivity matter.",
            "CPU, memory, disk capacity, and network adapter counters are system-wide and may reflect other processes."
        ]
    }
    return jsonify(response)


@app.get("/api/health")
def health():
    return jsonify({"status": "running", "service": "SQL Performance Analyzer", "timestamp": timestamp()})


@app.get("/")
def home():
    index_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "index.html")
    if not os.path.isfile(index_path):
        return jsonify({"status": "running", "message": "Backend is running. Place index.html beside app.py to serve the dashboard."})
    return send_file(index_path)


if __name__ == "__main__":
    initialize_database()
    app.run(host="127.0.0.1", port=int(os.getenv("FLASK_PORT", "5001")), debug=False)
