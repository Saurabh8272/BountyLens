# BountyLens

**AI-powered API Security Testing Platform**

A Burp Suite extension that crawls API endpoints and integrates with Claude via MCP, automatically mapping every parameter to suggested test cases derived from disclosed bounty reports on HackerOne and Bugcrowd. Features smart tracking (pass/fail/NA) per endpoint ensuring zero blind spots, contextual business-risk explanations per functionality, and automated export of detailed pentest reports in Word/PDF format.

---

## Architecture

```
┌──────────────────────────┐       HTTP (localhost:8888)       ┌─────────────────────────┐
│   Burp Suite Extension   │ ──────────────────────────────▶  │   BountyLens MCP Server  │
│   (bountylens_burp.py)   │                                   │   (bountylens_mcp.py)    │
│                          │  • Captures endpoints from proxy  │                           │
│  • Endpoint list UI      │  • Parses headers/body/params     │  • Stores endpoint data   │
│  • Dashboard view        │  • Sends to MCP bridge            │  • Suggests test cases    │
│  • Export triggers       │                                   │  • Tracks pass/fail/NA    │
└──────────────────────────┘                                   │  • Generates reports      │
                                                               │                           │
                                            MCP (stdio)        │  ◀── Claude Desktop /     │
                                         ◀─────────────────── │      Claude.ai connects   │
                                                               └───────────────────────────┘
```

## Setup

### 1. Install MCP Server Dependencies

```bash
cd BountyLens
pip install -r requirements.txt
```

Or with uv:
```bash
uv pip install -r requirements.txt
```

### 2. Start the MCP Server

```bash
python bountylens_mcp.py
```

This starts:
- **MCP server** on stdio (for Claude)
- **HTTP bridge** on `localhost:8888` (for Burp)

### 3. Load Burp Extension

1. Open Burp Suite Professional
2. Go to **Extender → Options** → Set Jython standalone JAR path
3. Go to **Extender → Extensions → Add**
4. Extension Type: **Python**
5. Select: `bountylens_burp.py`
6. Click **Next**

### 4. Connect Claude Desktop

Add to your Claude Desktop config (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "bountylens": {
      "command": "python",
      "args": ["/full/path/to/BountyLens/bountylens_mcp.py"]
    }
  }
}
```

Restart Claude Desktop. You should see BountyLens tools available.

---

## Usage Workflow

### Step 1: Crawl
Browse or crawl your target API in Burp. Endpoints auto-capture in the BountyLens tab.

### Step 2: Send to MCP
Click **"Send All to MCP"** in the Endpoints tab.

### Step 3: Analyze with Claude
In Claude, use natural language:

| What you say | What happens |
|---|---|
| "List all endpoints" | Calls `list_endpoints()` |
| "Analyze endpoint abc123 for vulnerabilities" | Calls `suggest_test_cases("abc123")` |
| "Mark test xyz as fail with evidence: IDOR confirmed" | Calls `set_test_result(...)` |
| "This endpoint handles user payments, high risk" | Calls `add_business_context(...)` |
| "Show me the coverage dashboard" | Calls `get_coverage_dashboard()` |
| "Export report as Word" | Calls `export_report("word")` |

### Step 4: Track
Use the Dashboard tab in Burp or ask Claude for coverage status.

### Step 5: Export
Generate Word/PDF/JSON reports with full findings, evidence, and business context.

---

## MCP Tools Reference

| Tool | Description |
|---|---|
| `list_endpoints(status_filter)` | List all endpoints, optionally filter by tested/untested |
| `get_endpoint_details(endpoint_id)` | Full details: params, headers, test cases, context |
| `suggest_test_cases(endpoint_id)` | AI-powered test case suggestions from bounty patterns |
| `set_test_result(endpoint_id, test_case_id, status, evidence)` | Update test result |
| `add_business_context(endpoint_id, context, risk_level)` | Add business risk explanation |
| `get_coverage_dashboard()` | Full coverage overview with blind spot detection |
| `export_report(format)` | Export as "json", "word", or "pdf" |

---

## Tech Stack

- **Burp Extension**: Jython (Python 2.7 on JVM), Java Swing UI
- **MCP Server**: Python 3.10+, FastMCP SDK
- **Reporting**: python-docx (Word), ReportLab (PDF)
- **Bridge**: HTTP REST on localhost

## License

MIT
