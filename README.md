# BOS // Unified Business Operating System

An ultra-lightweight, zero-bloat, **MCP-native (Model Context Protocol)** Business Operating System designed for simultaneous execution by human operators and autonomous AI agents.

BOS unites 5 enterprise pillars (**ERP, CRM, Finance/HRMS, Workplace Productivity, Digital Presence**) into **5 Unified Primitives** backed by a single-file SQLite database in **WAL mode** with Human-in-the-Loop (HITL) guardrails and 1-click time-travel rollbacks.

---

## 1. Unified Architecture ("The 5 Primitives Rule")

Instead of sprawling across 50 separate tables and dozens of microservices, all 10 enterprise business workflows are mapped directly onto 5 Unified Core Tables + 2 System Guardrail Tables:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        HUMAN / AGENT WORKFLOWS                         │
│   ERP • CRM • Finance/Ledger • HRMS • Productivity • Digital Presence │
└────────────────────────────────────┬───────────────────────────────────┘
                                     │
                 ┌───────────────────┴───────────────────┐
                 │       DUAL-PROTOCOL SERVICE LAYER     │
                 │   REST API  ◄───►  MCP (STDIO & SSE)  │
                 └───────────────────┬───────────────────┘
                                     │
           ┌─────────────────────────┴─────────────────────────┐
           │       SYSTEM GUARDRAILS & GOVERNANCE LAYER        │
           │  • HITL Staging Interceptor (`staged_actions`)    │
           │  • Scoped RBAC Tokens (`agent_tokens`)            │
           │  • Time-Travel 1-Click Rollback (`audit_logs`)     │
           └─────────────────────────┬─────────────────────────┘
                                     │
 ┌───────────────────────────────────┴───────────────────────────────────┐
 │                   5 UNIFIED SQLITE DATABASE TABLES                    │
 │ 1. entities         (Leads, Customers, Vendors, Employees, Candidates)│
 │ 2. catalog_items    (Physical SKUs, Digital Assets, Billable Services)│
 │ 3. pipeline_states  (Deals, POs, Sales Orders, Tasks, Shifts, Apps)   │
 │ 4. ledger_entries   (Double-Entry Balanced Invoices, Bills, Payroll)  │
 │ 5. content_blocks   (Docs, Chat Messages, Reviews, Business NAP)      │
 └───────────────────────────────────────────────────────────────────────┘
```

### Table Mapping Matrix

| Unified Table | Module Representation | Key Attributes & State Machine |
| :--- | :--- | :--- |
| `entities` | CRM, HRMS, Supply Chain | `type` (person/org), `role` (lead/customer/vendor/employee/candidate), `status`, `metadata` JSON |
| `catalog_items` | ERP, Inventory, E-commerce | `sku`, `type` (physical/digital/service), `stock_qty`, `reorder_threshold`, `unit_price`, `cost_price` |
| `pipeline_states` | Sales, Operations, HR | `category` (deal/po/task/shift/app), `stage`, `entity_id`, `assigned_to`, `amount`, `due_date` |
| `ledger_entries` | Finance, Invoicing, Payroll | Immutable double-entry: `transaction_group_id`, `type` (debit/credit), `account`, `category`, `amount` |
| `content_blocks` | Docs, Comms, Reputation, NAP | `block_type` (doc/chat/review/nap), `channel_or_source`, `markdown_body`, `sentiment_score`, `sync_status` |
| `staged_actions` | **AI HITL Guardrail** | `agent_id`, `tool_name`, `parameters_json`, `proposed_payload_json`, `risk_level`, `status` |
| `audit_logs` | **Time-Travel Rollback** | `actor_type`, `table_name`, `record_id`, `action`, `before_json`, `after_json`, `is_reverted` |

---

## 2. Model Context Protocol (MCP) Server

BOS implements a first-class MCP server supporting **Dual Transports**:
1. **STDIO (`--stdio`)**: For local agent interfaces like Claude Desktop and Cursor.
2. **Streamable HTTP/SSE (`/mcp/sse`)**: For remote and cloud-hosted autonomous agents.

### A. Read-Only Context Resources (`mcp://`)
- `mcp://business/pulse`: Returns token-efficient executive summary (cash balance, net P&L, low-stock SKUs, overdue invoices, urgent negative reviews).
- `mcp://entities/{id}/360`: Returns full relationship graph, deal history, double-entry ledger transactions, and communications.
- `mcp://inventory/low-stock`: Returns all items where `stock_qty <= reorder_threshold`.

### B. Dual-Tier Tool Classification

```
                          Autonomous Tool Call
                                   │
                     Is tool High-Stakes or HITL?
                                  / \
                                 /   \
                             YES/     \NO (Safe Auto-Execute)
                               /       \
                              ▼         ▼
                    ┌────────────────┐ ┌────────────────┐
                    │ staged_actions │ │ Direct Execute │
                    │ (Inbox Approval│ │ & Audit Log    │
                    └────────────────┘ └────────────────┘
```

#### Safe / Auto-Execute Tools:
- `crm_search_entities`: Search leads, customers, vendors by keyword.
- `crm_move_deal_stage`: Update sales deal stage in `pipeline_states`.
- `inventory_check_stock`: Query SKU stock levels and reorder thresholds.
- `work_create_task`: Spawn project delivery tasks with assignments and deadlines.
- `docs_append_note`: Append markdown notes to internal wiki.
- `reviews_fetch_unanswered`: Fetch unreplied reviews across platforms.

#### High-Stakes / Staged Tools (Requires Operator Sign-off):
- `erp_draft_purchase_order`: Stages restock PO when inventory is low.
- `finance_issue_invoice`: Stages outbound invoice in double-entry ledger.
- `hrms_stage_payroll_run`: Stages batch salary disbursements.
- `presence_publish_review_reply`: Stages public brand response to customer review.
- `presence_sync_nap_listings`: Broadcasts business NAP to local directories.

---

## 3. Fast Quickstart (One Command)

### Using Bun (Native Fast Mode)
```bash
# Clone and start immediately
git clone <repo-url> && cd experiments
bun run start
```
The server will initialize `bos.db` in WAL mode, load `schema.sql`, seed default data, and open the command-first UI at `http://localhost:8080`.

### Using Docker & Docker Compose
```bash
# Single command build and launch
docker-compose up -d
```
All state is persistently mounted to the `./data` folder on your host machine.

---

## 4. Connecting AI Agents via MCP

### Claude Desktop Configuration (`claude_desktop_config.json`)
```json
{
  "mcpServers": {
    "bos-unified": {
      "command": "bun",
      "args": ["run", "/absolute/path/to/server.ts", "--stdio"]
    }
  }
}
```

### Cursor & Cloud Agent SSE Integration
Connect your agent to:
- **SSE Stream**: `http://localhost:8080/mcp/sse`
- **Messages**: `POST http://localhost:8080/mcp/messages?sessionId=<session>`
- **Authorization**: `Bearer bos_agent_support_110a`
