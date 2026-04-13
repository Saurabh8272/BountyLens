"""
BountyLens — Burp Suite Extension (Jython)
==========================================
Captures API endpoints from Burp's proxy/crawler and sends them
to the BountyLens MCP server running on localhost:8888.

Features:
- Auto-captures endpoints from proxy traffic
- Parses headers, query params, body params per request
- Sends data to MCP server bridge
- Built-in UI tab with endpoint list and tracking dashboard
- Manual send/refresh controls
- Export trigger from within Burp

Load this in Burp Suite → Extender → Add → Extension Type: Python → Select this file.
Requires: Jython standalone JAR configured in Burp.
"""

from burp import IBurpExtender, ITab, IHttpListener, IContextMenuFactory
from javax.swing import (
    JPanel, JTable, JScrollPane, JButton, JLabel, JTextField,
    JTabbedPane, JTextArea, JSplitPane, JOptionPane, JComboBox,
    BorderFactory, SwingConstants, SwingUtilities,
    BoxLayout, Box
)
from javax.swing.table import DefaultTableModel
from java.awt import BorderLayout, FlowLayout, GridLayout, Font, Color, Dimension
from java.net import URL, HttpURLConnection
from java.io import BufferedReader, InputStreamReader, OutputStreamWriter
import json
import threading


BRIDGE_URL = "http://127.0.0.1:8888"


class BurpExtender(IBurpExtender, ITab, IHttpListener, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("BountyLens")

        # Tracked endpoints to avoid duplicates
        self._seen_endpoints = set()
        self._endpoint_data = []

        # Build UI
        self._main_panel = JTabbedPane()
        self._build_endpoints_tab()
        self._build_dashboard_tab()
        self._build_settings_tab()

        # Register listeners
        callbacks.registerHttpListener(self)
        callbacks.addSuiteTab(self)

        callbacks.printOutput("[BountyLens] Extension loaded successfully!")
        callbacks.printOutput("[BountyLens] Make sure bountylens_mcp.py is running (python3 bountylens_mcp.py)")

    # ──────────────────────────────────────────
    # ITab
    # ──────────────────────────────────────────

    def getTabCaption(self):
        return "BountyLens"

    def getUiComponent(self):
        return self._main_panel

    # ──────────────────────────────────────────
    # UI: Endpoints Tab
    # ──────────────────────────────────────────

    def _build_endpoints_tab(self):
        panel = JPanel(BorderLayout())

        # Top controls
        controls = JPanel(FlowLayout(FlowLayout.LEFT))

        self._scope_filter = JTextField(30)
        self._scope_filter.setToolTipText("Filter by scope (e.g., api.target.com)")
        controls.add(JLabel("Scope Filter: "))
        controls.add(self._scope_filter)

        btn_refresh = JButton("Refresh", actionPerformed=self._refresh_table)
        controls.add(btn_refresh)

        btn_send_all = JButton("Send All to MCP", actionPerformed=self._send_all_to_mcp)
        controls.add(btn_send_all)

        btn_clear = JButton("Clear", actionPerformed=self._clear_endpoints)
        controls.add(btn_clear)

        self._status_label = JLabel("Endpoints: 0 | Sent: 0")
        controls.add(self._status_label)

        panel.add(controls, BorderLayout.NORTH)

        # Endpoint table
        columns = ["#", "Method", "URL", "Query Params", "Body Params", "Content-Type", "Sent"]
        self._table_model = DefaultTableModel(columns, 0)
        self._table = JTable(self._table_model)
        self._table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS)

        # Detail area
        self._detail_area = JTextArea(10, 50)
        self._detail_area.setEditable(False)
        self._detail_area.setFont(Font("Monospaced", Font.PLAIN, 12))

        split = JSplitPane(JSplitPane.VERTICAL_SPLIT,
                          JScrollPane(self._table),
                          JScrollPane(self._detail_area))
        split.setResizeWeight(0.7)

        panel.add(split, BorderLayout.CENTER)

        # Bottom: send selected
        bottom = JPanel(FlowLayout(FlowLayout.LEFT))
        btn_send_selected = JButton("Send Selected to MCP", actionPerformed=self._send_selected_to_mcp)
        bottom.add(btn_send_selected)
        btn_details = JButton("Show Details", actionPerformed=self._show_selected_details)
        bottom.add(btn_details)
        panel.add(bottom, BorderLayout.SOUTH)

        self._main_panel.addTab("Endpoints", panel)

    # ──────────────────────────────────────────
    # UI: Dashboard Tab
    # ──────────────────────────────────────────

    def _build_dashboard_tab(self):
        panel = JPanel(BorderLayout())

        top = JPanel(FlowLayout(FlowLayout.LEFT))
        btn_fetch = JButton("Fetch Dashboard from MCP", actionPerformed=self._fetch_dashboard)
        top.add(btn_fetch)

        btn_export_json = JButton("Export JSON", actionPerformed=lambda e: self._trigger_export("json"))
        btn_export_word = JButton("Export Word", actionPerformed=lambda e: self._trigger_export("word"))
        btn_export_pdf = JButton("Export PDF", actionPerformed=lambda e: self._trigger_export("pdf"))
        top.add(btn_export_json)
        top.add(btn_export_word)
        top.add(btn_export_pdf)

        panel.add(top, BorderLayout.NORTH)

        self._dashboard_area = JTextArea()
        self._dashboard_area.setEditable(False)
        self._dashboard_area.setFont(Font("Monospaced", Font.PLAIN, 13))
        self._dashboard_area.setText("Click 'Fetch Dashboard from MCP' to load coverage data.\n\n"
                                    "Make sure bountylens_mcp.py is running.")
        panel.add(JScrollPane(self._dashboard_area), BorderLayout.CENTER)

        self._main_panel.addTab("Dashboard", panel)

    # ──────────────────────────────────────────
    # UI: Settings Tab
    # ──────────────────────────────────────────

    def _build_settings_tab(self):
        panel = JPanel()
        panel.setLayout(BoxLayout(panel, BoxLayout.Y_AXIS))
        panel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20))

        panel.add(JLabel("BountyLens Settings"))
        panel.add(Box.createVerticalStrut(20))

        row1 = JPanel(FlowLayout(FlowLayout.LEFT))
        row1.add(JLabel("MCP Bridge URL: "))
        self._bridge_url_field = JTextField(BRIDGE_URL, 30)
        row1.add(self._bridge_url_field)
        panel.add(row1)

        row2 = JPanel(FlowLayout(FlowLayout.LEFT))
        row2.add(JLabel("Auto-capture from proxy: "))
        self._auto_capture = JComboBox(["Enabled", "Disabled"])
        row2.add(self._auto_capture)
        panel.add(row2)

        row3 = JPanel(FlowLayout(FlowLayout.LEFT))
        btn_health = JButton("Test Connection", actionPerformed=self._test_connection)
        row3.add(btn_health)
        self._connection_status = JLabel("")
        row3.add(self._connection_status)
        panel.add(row3)

        panel.add(Box.createVerticalStrut(20))
        info = JTextArea(
            "BountyLens v1.0\n"
            "AI-powered API Security Testing Platform\n\n"
            "How to use:\n"
            "1. Start the MCP server: python3 bountylens_mcp.py\n"
            "2. Browse/crawl target in Burp — endpoints auto-capture\n"
            "3. Click 'Send All to MCP' to push endpoints\n"
            "4. Use Claude (connected via MCP) to:\n"
            "   - list_endpoints() to see all captured APIs\n"
            "   - suggest_test_cases(id) to get security test suggestions\n"
            "   - set_test_result(id, tc_id, status) to track results\n"
            "   - add_business_context(id, context) for risk notes\n"
            "   - get_coverage_dashboard() for full overview\n"
            "   - export_report(format) for Word/PDF/JSON report\n"
            "5. Use the Dashboard tab to view coverage"
        )
        info.setEditable(False)
        info.setFont(Font("Monospaced", Font.PLAIN, 12))
        panel.add(JScrollPane(info))

        self._main_panel.addTab("Settings", panel)

    # ──────────────────────────────────────────
    # IHttpListener — auto-capture from proxy
    # ──────────────────────────────────────────

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            return

        if self._auto_capture.getSelectedItem() == "Disabled":
            return

        try:
            request_info = self._helpers.analyzeRequest(messageInfo)
            url_obj = request_info.getUrl()
            url_str = str(url_obj)
            method = request_info.getMethod()

            # Apply scope filter
            scope_filter = self._scope_filter.getText().strip()
            if scope_filter and scope_filter not in url_str:
                return

            # Deduplicate by method + URL path (ignore query for dedup)
            dedup_key = method + "|" + url_str.split("?")[0]
            if dedup_key in self._seen_endpoints:
                return
            self._seen_endpoints.add(dedup_key)

            # Parse headers
            headers = {}
            for header in request_info.getHeaders():
                header_str = str(header)
                if ": " in header_str:
                    key, val = header_str.split(": ", 1)
                    if key.lower() not in ["host", "content-length", "connection", "accept-encoding"]:
                        headers[key] = val

            # Parse query params
            query_params = {}
            if "?" in url_str:
                query_string = url_str.split("?", 1)[1]
                for param in query_string.split("&"):
                    if "=" in param:
                        k, v = param.split("=", 1)
                        query_params[k] = v

            # Parse body params
            body_params = {}
            content_type = ""
            body_offset = request_info.getBodyOffset()
            request_bytes = messageInfo.getRequest()

            if body_offset < len(request_bytes):
                body = self._helpers.bytesToString(request_bytes[body_offset:])
                ct_header = [str(h) for h in request_info.getHeaders() if str(h).lower().startswith("content-type")]
                if ct_header:
                    content_type = ct_header[0].split(": ", 1)[1] if ": " in ct_header[0] else ""

                if "json" in content_type.lower():
                    try:
                        body_params = json.loads(body)
                        if not isinstance(body_params, dict):
                            body_params = {"_body": body}
                    except:
                        body_params = {"_raw": body}
                elif "form" in content_type.lower():
                    for param in body.split("&"):
                        if "=" in param:
                            k, v = param.split("=", 1)
                            body_params[k] = v
                elif body.strip():
                    body_params = {"_raw": body[:500]}

            endpoint = {
                "url": url_str.split("?")[0],
                "method": method,
                "headers": headers,
                "query_params": query_params,
                "body_params": body_params,
                "content_type": content_type,
                "sent": False,
            }

            self._endpoint_data.append(endpoint)

            # Update table on EDT
            row_data = [
                len(self._endpoint_data),
                method,
                url_str.split("?")[0],
                ", ".join(query_params.keys()) if query_params else "-",
                ", ".join(body_params.keys()) if body_params else "-",
                content_type or "-",
                "No",
            ]

            SwingUtilities.invokeLater(lambda: self._add_table_row(row_data))

        except Exception as e:
            self._callbacks.printError("[BountyLens] Error capturing: " + str(e))

    def _add_table_row(self, row_data):
        self._table_model.addRow(row_data)
        self._update_status()

    def _update_status(self):
        total = len(self._endpoint_data)
        sent = sum(1 for ep in self._endpoint_data if ep.get("sent"))
        self._status_label.setText("Endpoints: %d | Sent: %d" % (total, sent))

    # ──────────────────────────────────────────
    # Actions
    # ──────────────────────────────────────────

    def _send_all_to_mcp(self, event):
        threading.Thread(target=self._do_send_all).start()

    def _do_send_all(self):
        unsent = [ep for ep in self._endpoint_data if not ep.get("sent")]
        if not unsent:
            self._callbacks.printOutput("[BountyLens] No new endpoints to send.")
            return

        payload = []
        for ep in unsent:
            payload.append({
                "url": ep["url"],
                "method": ep["method"],
                "headers": ep["headers"],
                "query_params": ep["query_params"],
                "body_params": ep["body_params"],
                "content_type": ep["content_type"],
            })

        try:
            bridge = self._bridge_url_field.getText().strip()
            response = self._http_post(bridge + "/endpoints/bulk", json.dumps(payload))
            result = json.loads(response)

            for ep in unsent:
                ep["sent"] = True

            # Update table sent column
            SwingUtilities.invokeLater(lambda: self._mark_all_sent())

            self._callbacks.printOutput(
                "[BountyLens] Sent %d endpoints to MCP server." % result.get("count", len(unsent))
            )
        except Exception as e:
            self._callbacks.printError("[BountyLens] Failed to send: " + str(e))

    def _send_selected_to_mcp(self, event):
        row = self._table.getSelectedRow()
        if row < 0:
            return

        ep = self._endpoint_data[row]
        if ep.get("sent"):
            self._callbacks.printOutput("[BountyLens] Already sent.")
            return

        payload = json.dumps({
            "url": ep["url"],
            "method": ep["method"],
            "headers": ep["headers"],
            "query_params": ep["query_params"],
            "body_params": ep["body_params"],
            "content_type": ep["content_type"],
        })

        try:
            bridge = self._bridge_url_field.getText().strip()
            self._http_post(bridge + "/endpoints", payload)
            ep["sent"] = True
            self._table_model.setValueAt("Yes", row, 6)
            self._update_status()
        except Exception as e:
            self._callbacks.printError("[BountyLens] Send failed: " + str(e))

    def _show_selected_details(self, event):
        row = self._table.getSelectedRow()
        if row < 0:
            return
        ep = self._endpoint_data[row]
        details = json.dumps(ep, indent=2)
        self._detail_area.setText(details)

    def _clear_endpoints(self, event):
        self._endpoint_data = []
        self._seen_endpoints.clear()
        self._table_model.setRowCount(0)
        self._update_status()

    def _refresh_table(self, event):
        self._table_model.setRowCount(0)
        for i, ep in enumerate(self._endpoint_data):
            self._table_model.addRow([
                i + 1,
                ep["method"],
                ep["url"],
                ", ".join(ep["query_params"].keys()) if ep["query_params"] else "-",
                ", ".join(ep["body_params"].keys()) if ep["body_params"] else "-",
                ep["content_type"] or "-",
                "Yes" if ep.get("sent") else "No",
            ])
        self._update_status()

    def _mark_all_sent(self):
        for i in range(self._table_model.getRowCount()):
            self._table_model.setValueAt("Yes", i, 6)
        self._update_status()

    def _fetch_dashboard(self, event):
        try:
            bridge = self._bridge_url_field.getText().strip()
            response = self._http_get(bridge + "/endpoints")
            endpoints = json.loads(response)

            if not endpoints:
                self._dashboard_area.setText("No endpoints found. Send endpoints from the Endpoints tab first.")
                return

            text = "BOUNTYLENS DASHBOARD (from MCP Bridge)\n"
            text += "=" * 50 + "\n\n"
            text += "Total endpoints: %d\n\n" % len(endpoints)

            for ep in endpoints:
                tc_count = len(ep.get("test_cases", []))
                tested = sum(1 for tc in ep.get("test_cases", []) if tc.get("status") in ("pass", "fail", "na"))
                text += "[%s] %s %s\n" % (ep["id"], ep["method"], ep["url"])
                text += "  Tests: %d/%d | Risk: %s\n" % (tested, tc_count, ep.get("risk_level", "?"))
                if ep.get("business_context"):
                    text += "  Context: %s\n" % ep["business_context"]
                text += "\n"

            self._dashboard_area.setText(text)
        except Exception as e:
            self._dashboard_area.setText("Error fetching dashboard: " + str(e))

    def _trigger_export(self, fmt):
        """Note: Export is triggered via Claude MCP tools. This is a helper that shows instructions."""
        msg = (
            "To export a %s report, tell Claude:\n\n"
            "  'Export the pentest report as %s'\n\n"
            "Claude will call export_report('%s') via MCP.\n"
            "The file will be saved in the MCP server's working directory."
        ) % (fmt.upper(), fmt, fmt)
        JOptionPane.showMessageDialog(self._main_panel, msg, "Export via MCP", JOptionPane.INFORMATION_MESSAGE)

    def _test_connection(self, event):
        try:
            bridge = self._bridge_url_field.getText().strip()
            response = self._http_get(bridge + "/health")
            data = json.loads(response)
            self._connection_status.setText("Connected! Endpoints: %s" % data.get("endpoints_count", 0))
            self._connection_status.setForeground(Color(0, 150, 0))
        except Exception as e:
            self._connection_status.setText("Failed: " + str(e))
            self._connection_status.setForeground(Color.RED)

    # ──────────────────────────────────────────
    # HTTP helpers (using Java's HttpURLConnection)
    # ──────────────────────────────────────────

    def _http_post(self, url_str, body):
        url = URL(url_str)
        conn = url.openConnection()
        conn.setRequestMethod("POST")
        conn.setRequestProperty("Content-Type", "application/json")
        conn.setDoOutput(True)

        writer = OutputStreamWriter(conn.getOutputStream())
        writer.write(body)
        writer.flush()
        writer.close()

        reader = BufferedReader(InputStreamReader(conn.getInputStream()))
        response = []
        line = reader.readLine()
        while line is not None:
            response.append(line)
            line = reader.readLine()
        reader.close()

        return "\n".join(response)

    def _http_get(self, url_str):
        url = URL(url_str)
        conn = url.openConnection()
        conn.setRequestMethod("GET")

        reader = BufferedReader(InputStreamReader(conn.getInputStream()))
        response = []
        line = reader.readLine()
        while line is not None:
            response.append(line)
            line = reader.readLine()
        reader.close()

        return "\n".join(response)
