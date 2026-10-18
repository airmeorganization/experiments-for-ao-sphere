-- ====================================================================
-- BUSINESS OPERATING SYSTEM (BOS) - UNIFIED CORE SCHEMA
-- Single-file SQLite running in WAL mode with Double-Entry Ledger & HITL Guardrails
-- ====================================================================

PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;

-- --------------------------------------------------------------------
-- 0. SCHEMA MIGRATIONS TABLE
-- Tracks versioned schema evolution across restarts & upgrades
-- --------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- --------------------------------------------------------------------
-- 1. ENTITIES (Unified People & Organizations)
-- Leads, Customers, Vendors, Employees, Candidates
-- --------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS entities (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL CHECK (type IN ('person', 'organization')),
    role TEXT NOT NULL CHECK (role IN ('customer', 'lead', 'vendor', 'employee', 'candidate')),
    name TEXT NOT NULL,
    email TEXT,
    phone TEXT,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'lead_hot', 'lead_cold', 'onboarding', 'archived')),
    metadata JSON NOT NULL DEFAULT '{}',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_entities_role ON entities(role);
CREATE INDEX IF NOT EXISTS idx_entities_status ON entities(status);
CREATE INDEX IF NOT EXISTS idx_entities_email ON entities(email);

-- --------------------------------------------------------------------
-- 2. CATALOG_ITEMS (Unified Physical SKUs, Digital Assets & Services)
-- --------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS catalog_items (
    id TEXT PRIMARY KEY,
    sku TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    type TEXT NOT NULL CHECK (type IN ('physical', 'digital', 'service')),
    stock_qty INTEGER NOT NULL DEFAULT 0,
    reorder_threshold INTEGER NOT NULL DEFAULT 0,
    unit_price REAL NOT NULL DEFAULT 0.0,
    cost_price REAL NOT NULL DEFAULT 0.0,
    currency TEXT NOT NULL DEFAULT 'USD',
    supplier_entity_id TEXT REFERENCES entities(id) ON DELETE SET NULL,
    metadata JSON NOT NULL DEFAULT '{}',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_catalog_sku ON catalog_items(sku);
CREATE INDEX IF NOT EXISTS idx_catalog_type ON catalog_items(type);
CREATE INDEX IF NOT EXISTS idx_catalog_low_stock ON catalog_items(stock_qty, reorder_threshold);

-- --------------------------------------------------------------------
-- 3. PIPELINE_STATES (Universal State-Machine)
-- Deals, Purchase Orders, Sales Orders, Tasks, Shifts, Applications
-- --------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS pipeline_states (
    id TEXT PRIMARY KEY,
    category TEXT NOT NULL CHECK (category IN (
        'deal',
        'purchase_order',
        'sales_order',
        'project_task',
        'employee_shift',
        'candidate_application'
    )),
    title TEXT NOT NULL,
    stage TEXT NOT NULL,
    entity_id TEXT REFERENCES entities(id) ON DELETE SET NULL,
    assigned_to TEXT REFERENCES entities(id) ON DELETE SET NULL,
    amount REAL DEFAULT 0.0,
    priority TEXT NOT NULL DEFAULT 'medium' CHECK (priority IN ('low', 'medium', 'high', 'urgent')),
    due_date DATETIME,
    payload_json JSON NOT NULL DEFAULT '{}',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_pipeline_category_stage ON pipeline_states(category, stage);
CREATE INDEX IF NOT EXISTS idx_pipeline_entity ON pipeline_states(entity_id);
CREATE INDEX IF NOT EXISTS idx_pipeline_assigned ON pipeline_states(assigned_to);
CREATE INDEX IF NOT EXISTS idx_pipeline_due ON pipeline_states(due_date);

-- --------------------------------------------------------------------
-- 4. LEDGER_ENTRIES (Strict Double-Entry Financial Ledger)
-- Immutable ledger for Invoices, Bills, Payroll, Tax, E-commerce
-- --------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ledger_entries (
    id TEXT PRIMARY KEY,
    transaction_group_id TEXT NOT NULL,
    type TEXT NOT NULL CHECK (type IN ('debit', 'credit')),
    account TEXT NOT NULL CHECK (account IN (
        'cash',
        'accounts_receivable',
        'accounts_payable',
        'revenue',
        'cogs',
        'inventory',
        'payroll_expense',
        'tax_payable',
        'operating_expense'
    )),
    category TEXT NOT NULL CHECK (category IN ('invoice', 'bill', 'payroll', 'tax', 'expense', 'ecommerce')),
    amount REAL NOT NULL CHECK (amount >= 0),
    tax_amount REAL NOT NULL DEFAULT 0.0,
    currency TEXT NOT NULL DEFAULT 'USD',
    status TEXT NOT NULL DEFAULT 'posted' CHECK (status IN ('draft', 'staged', 'posted', 'voided')),
    reference_id TEXT,
    entity_id TEXT REFERENCES entities(id) ON DELETE SET NULL,
    description TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_ledger_group ON ledger_entries(transaction_group_id);
CREATE INDEX IF NOT EXISTS idx_ledger_account ON ledger_entries(account);
CREATE INDEX IF NOT EXISTS idx_ledger_category ON ledger_entries(category);
CREATE INDEX IF NOT EXISTS idx_ledger_status ON ledger_entries(status);
CREATE INDEX IF NOT EXISTS idx_ledger_entity ON ledger_entries(entity_id);

-- --------------------------------------------------------------------
-- 5. CONTENT_BLOCKS (Unified Workspace & Digital Presence Store)
-- Docs, Team Chat Messages, Customer Reviews, Business NAP Profiles
-- --------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS content_blocks (
    id TEXT PRIMARY KEY,
    block_type TEXT NOT NULL CHECK (block_type IN ('doc', 'chat_message', 'customer_review', 'business_nap')),
    channel_or_source TEXT NOT NULL,
    title TEXT,
    markdown_body TEXT NOT NULL,
    sentiment_score REAL DEFAULT 0.0,
    sentiment_label TEXT NOT NULL DEFAULT 'neutral' CHECK (sentiment_label IN ('positive', 'neutral', 'urgent_negative')),
    author_entity_id TEXT REFERENCES entities(id) ON DELETE SET NULL,
    parent_id TEXT REFERENCES content_blocks(id) ON DELETE CASCADE,
    sync_status TEXT NOT NULL DEFAULT 'synced' CHECK (sync_status IN ('synced', 'pending', 'failed', 'resolved')),
    metadata JSON NOT NULL DEFAULT '{}',
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_content_type_channel ON content_blocks(block_type, channel_or_source);
CREATE INDEX IF NOT EXISTS idx_content_sentiment ON content_blocks(sentiment_label);
CREATE INDEX IF NOT EXISTS idx_content_sync ON content_blocks(sync_status);

-- --------------------------------------------------------------------
-- 6. STAGED_ACTIONS (Human-in-the-Loop AI Action Queue)
-- Guardrail interceptor for high-risk autonomous agent tool calls
-- --------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS staged_actions (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    parameters_json JSON NOT NULL,
    proposed_payload_json JSON NOT NULL,
    risk_level TEXT NOT NULL CHECK (risk_level IN ('low', 'medium', 'high', 'critical')),
    reasoning TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected', 'edited')),
    reviewed_by TEXT,
    reviewed_at DATETIME,
    execution_result_json JSON,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_staged_status ON staged_actions(status);
CREATE INDEX IF NOT EXISTS idx_staged_agent ON staged_actions(agent_id);

-- --------------------------------------------------------------------
-- 7. AUDIT_LOGS (Immutable Time-Travel & 1-Click Rollback Stream)
-- --------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_logs (
    id TEXT PRIMARY KEY,
    actor_type TEXT NOT NULL CHECK (actor_type IN ('human', 'agent', 'system')),
    actor_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    table_name TEXT NOT NULL,
    record_id TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('INSERT', 'UPDATE', 'DELETE', 'ROLLBACK')),
    before_json JSON,
    after_json JSON,
    is_reverted INTEGER NOT NULL DEFAULT 0 CHECK (is_reverted IN (0, 1)),
    reverted_by_audit_id TEXT REFERENCES audit_logs(id),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_audit_record ON audit_logs(table_name, record_id);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_reverted ON audit_logs(is_reverted);

-- --------------------------------------------------------------------
-- 8. SYSTEM CONFIG & RBAC KEYS (Cryptographically Hashed)
-- --------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS agent_tokens (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    token_hash TEXT UNIQUE NOT NULL,
    token_prefix TEXT NOT NULL,
    scopes JSON NOT NULL DEFAULT '["*"]',
    rate_limit_per_min INTEGER NOT NULL DEFAULT 120,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS hitl_policies (
    tool_name TEXT PRIMARY KEY,
    requires_hitl INTEGER NOT NULL DEFAULT 1,
    risk_level TEXT NOT NULL DEFAULT 'high',
    auto_approve_threshold REAL DEFAULT NULL
);

-- Durable Rate Limiting Store
CREATE TABLE IF NOT EXISTS rate_limits (
    client_key TEXT NOT NULL,
    timestamp INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rate_limits_key_ts ON rate_limits(client_key, timestamp);

-- ====================================================================
-- IMMUTABLE LEDGER & WORKFLOW TRIGGERS
-- ====================================================================

-- Enforce Ledger Immutability: Prevent UPDATE on posted ledger entries
CREATE TRIGGER IF NOT EXISTS trg_ledger_immutable_update
BEFORE UPDATE ON ledger_entries
WHEN OLD.status = 'posted'
BEGIN
    SELECT RAISE(ABORT, 'Posted ledger entries are immutable. Create a reversing compensating journal entry instead.');
END;

-- Enforce Ledger Immutability: Prevent DELETE on posted ledger entries
CREATE TRIGGER IF NOT EXISTS trg_ledger_immutable_delete
BEFORE DELETE ON ledger_entries
WHEN OLD.status = 'posted'
BEGIN
    SELECT RAISE(ABORT, 'Posted ledger entries are immutable and cannot be deleted.');
END;

-- Trigger: Automatically draft a Purchase Order in staged_actions
-- when catalog_items stock falls to or below reorder_threshold
CREATE TRIGGER IF NOT EXISTS trg_auto_reorder_low_stock
AFTER UPDATE OF stock_qty, reorder_threshold ON catalog_items
WHEN NEW.stock_qty <= NEW.reorder_threshold
     AND (OLD.stock_qty > OLD.reorder_threshold OR OLD.stock_qty IS NULL)
BEGIN
    INSERT INTO staged_actions (
        id,
        agent_id,
        tool_name,
        parameters_json,
        proposed_payload_json,
        risk_level,
        reasoning,
        status,
        created_at
    ) VALUES (
        'stg_' || lower(hex(randomblob(8))),
        'system:inventory_daemon',
        'erp_draft_purchase_order',
        json_object(
            'sku', NEW.sku,
            'current_stock', NEW.stock_qty,
            'threshold', NEW.reorder_threshold,
            'supplier_id', NEW.supplier_entity_id
        ),
        json_object(
            'title', 'Auto Reorder: ' || NEW.name || ' (' || NEW.sku || ')',
            'suggested_quantity', (NEW.reorder_threshold * 2) - NEW.stock_qty + 10,
            'estimated_cost', ((NEW.reorder_threshold * 2) - NEW.stock_qty + 10) * NEW.cost_price,
            'supplier_id', NEW.supplier_entity_id
        ),
        'high',
        'Stock level for SKU [' || NEW.sku || '] dropped to ' || NEW.stock_qty || ' (threshold: ' || NEW.reorder_threshold || '). Staged autonomous PO for human approval.',
        'pending',
        CURRENT_TIMESTAMP
    );
END;

-- Mark Schema Migration Version 1
INSERT OR REPLACE INTO schema_migrations (version, name) VALUES
(1, 'initial_unified_schema_v2');

-- ====================================================================
-- SEED DATA (Enterprise Multi-Pillar Test Dataset)
-- Note: Raw production secrets are NEVER stored in seed files.
-- ====================================================================

-- Default Tool HITL Policies
INSERT OR REPLACE INTO hitl_policies (tool_name, requires_hitl, risk_level, auto_approve_threshold) VALUES
('erp_draft_purchase_order', 1, 'high', 1000.0),
('finance_issue_invoice', 1, 'high', 5000.0),
('hrms_stage_payroll_run', 1, 'critical', NULL),
('presence_publish_review_reply', 1, 'medium', NULL),
('presence_sync_nap_listings', 1, 'medium', NULL),
('crm_search_entities', 0, 'low', NULL),
('crm_move_deal_stage', 0, 'low', NULL),
('inventory_check_stock', 0, 'low', NULL),
('work_create_task', 0, 'low', NULL),
('docs_append_note', 0, 'low', NULL),
('reviews_fetch_unanswered', 0, 'low', NULL);

-- 1. Entities
INSERT OR REPLACE INTO entities (id, type, role, name, email, phone, status, metadata) VALUES
('ent_apex', 'organization', 'customer', 'Apex Global Technologies', 'procurement@apexcorp.io', '+1-415-555-0199', 'active', '{"tier": "enterprise", "mrr": 8500, "industry": "SaaS"}'),
('ent_acme', 'organization', 'customer', 'Acme Logistics Ltd', 'billing@acmelog.com', '+1-212-555-0144', 'active', '{"tier": "mid-market", "mrr": 3200, "industry": "Logistics"}'),
('ent_solis', 'organization', 'lead', 'Solis Energy Partners', 'sarah@solisenergy.com', '+1-512-555-0133', 'lead_hot', '{"estimated_arr": 45000, "source": "Outbound AI Agent"}'),
('ent_hyper', 'organization', 'vendor', 'HyperScale Cloud Hardware Inc', 'orders@hyperscalehw.com', '+1-800-555-0182', 'active', '{"payment_terms": "net_30", "currency": "USD"}'),
('ent_emp_alex', 'person', 'employee', 'Alex Mercer', 'alex.mercer@enterprise.io', '+1-415-555-0101', 'active', '{"title": "Head of Engineering", "department": "Tech", "salary": 14500, "shift": "Day"}'),
('ent_emp_priya', 'person', 'employee', 'Priya Sharma', 'priya.sharma@enterprise.io', '+1-415-555-0102', 'active', '{"title": "Operations Lead", "department": "Operations", "salary": 11500, "shift": "Day"}'),
('ent_cand_marcus', 'person', 'candidate', 'Marcus Vance', 'marcus.vance@gmail.com', '+1-650-555-0129', 'active', '{"target_role": "Senior Distributed Systems Engineer", "experience_yrs": 8}');

-- 2. Catalog Items
INSERT OR REPLACE INTO catalog_items (id, sku, name, type, stock_qty, reorder_threshold, unit_price, cost_price, currency, supplier_entity_id, metadata) VALUES
('cat_edge_node', 'HW-SRV-01', 'Edge Kubernetes Microserver Node', 'physical', 4, 10, 1850.00, 1100.00, 'USD', 'ent_hyper', '{"weight_kg": 4.2, "rack_unit": "1U"}'),
('cat_sensor_gw', 'HW-IOT-99', 'Telemetry Sensor Gateway Mesh', 'physical', 48, 20, 240.00, 115.00, 'USD', 'ent_hyper', '{"protocol": "Zigbee/LoRa"}'),
('cat_bos_cloud', 'SW-BOS-ANN', 'Enterprise BOS Private Dedicated Instance', 'digital', 9999, 0, 12000.00, 450.00, 'USD', NULL, '{"billing_period": "annual"}'),
('cat_audit_srv', 'SRV-ARCH-CONS', 'System Architecture & AI Security Audit', 'service', 9999, 0, 4500.00, 1500.00, 'USD', NULL, '{"delivered_by": "Alex Mercer"}');

-- 3. Pipeline States
INSERT OR REPLACE INTO pipeline_states (id, category, title, stage, entity_id, assigned_to, amount, priority, due_date, payload_json) VALUES
-- Deals
('pip_deal_apex', 'deal', 'Apex Multi-Region Expansion Contract', 'quoted', 'ent_apex', 'ent_emp_priya', 42000.00, 'high', '2026-11-15 18:00:00', '{"decision_maker": "VP Tech", "close_probability": 0.85}'),
('pip_deal_solis', 'deal', 'Solis Industrial IoT Pilot rollout', 'qualified', 'ent_solis', 'ent_emp_priya', 28500.00, 'urgent', '2026-11-01 18:00:00', '{"poc_status": "in_progress"}'),
-- Project Tasks
('pip_task_mcp', 'project_task', 'Upgrade MCP Transport layer to SSE streaming protocol', 'in_progress', NULL, 'ent_emp_alex', 0.0, 'urgent', '2026-10-25 17:00:00', '{"sprint": "Q4-W2", "estimation_pts": 5}'),
('pip_task_wal', 'project_task', 'Benchmark SQLite WAL mode on high-frequency IoT ingest', 'todo', NULL, 'ent_emp_alex', 0.0, 'medium', '2026-10-30 17:00:00', '{"target_tps": 5000}'),
-- Shifts
('pip_shift_alex', 'employee_shift', 'Engineering On-Call L3 Coverage', 'scheduled', 'ent_emp_alex', 'ent_emp_alex', 0.0, 'medium', '2026-10-20 22:00:00', '{"shift_hours": 8, "location": "Remote HQ"}'),
-- Candidate Application
('pip_app_marcus', 'candidate_application', 'Candidate Screening: Marcus Vance', 'offer', 'ent_cand_marcus', 'ent_emp_alex', 0.0, 'high', '2026-10-22 15:00:00', '{"proposed_comp": 175000, "interviews_completed": 4}');

-- 4. Ledger Entries (Double-Entry Balance Records)
-- Transaction 1: Customer Invoice Payment received from Apex ($8,500 subtotal + $700 tax = $9,200 cash)
-- Balanced Journal: Debit Cash $9,200 | Credit Revenue $8,500 | Credit Tax Payable $700
INSERT OR REPLACE INTO ledger_entries (id, transaction_group_id, type, account, category, amount, tax_amount, currency, status, reference_id, entity_id, description) VALUES
('led_101', 'tx_grp_inv_001', 'debit', 'cash', 'invoice', 9200.00, 0.0, 'USD', 'posted', 'INV-2026-089', 'ent_apex', 'Payment received - Apex Enterprise Platform Monthly (Incl Tax)'),
('led_102', 'tx_grp_inv_001', 'credit', 'revenue', 'invoice', 8500.00, 0.0, 'USD', 'posted', 'INV-2026-089', 'ent_apex', 'SaaS Platform Revenue recognized'),
('led_102b', 'tx_grp_inv_001', 'credit', 'tax_payable', 'invoice', 700.00, 0.0, 'USD', 'posted', 'INV-2026-089', 'ent_apex', 'Sales Tax collected payable');

-- Transaction 2: Hardware Supplier Inventory Purchase ($5,500)
-- Balanced Journal: Debit Inventory $5,500 | Credit Cash $5,500
INSERT OR REPLACE INTO ledger_entries (id, transaction_group_id, type, account, category, amount, tax_amount, currency, status, reference_id, entity_id, description) VALUES
('led_103', 'tx_grp_bill_002', 'debit', 'inventory', 'bill', 5500.00, 0.0, 'USD', 'posted', 'PO-2026-044', 'ent_hyper', 'Inventory asset addition - Microservers Batch 4'),
('led_104', 'tx_grp_bill_002', 'credit', 'cash', 'bill', 5500.00, 0.0, 'USD', 'posted', 'PO-2026-044', 'ent_hyper', 'Direct vendor settlement');

-- Transaction 3: Monthly Engineering Payroll ($14,500)
-- Balanced Journal: Debit Payroll Expense $14,500 | Credit Cash $14,500
INSERT OR REPLACE INTO ledger_entries (id, transaction_group_id, type, account, category, amount, tax_amount, currency, status, reference_id, entity_id, description) VALUES
('led_105', 'tx_grp_pay_003', 'debit', 'payroll_expense', 'payroll', 14500.00, 0.0, 'USD', 'posted', 'PAY-2026-OCT', 'ent_emp_alex', 'Monthly salary expense - Alex Mercer'),
('led_106', 'tx_grp_pay_003', 'credit', 'cash', 'payroll', 14500.00, 0.0, 'USD', 'posted', 'PAY-2026-OCT', 'ent_emp_alex', 'Payroll direct disbursement');

-- 5. Content Blocks (Docs, Chats, Reviews, NAP Profile)
-- Business NAP
INSERT OR REPLACE INTO content_blocks (id, block_type, channel_or_source, title, markdown_body, sentiment_score, sentiment_label, sync_status, metadata) VALUES
('blk_nap_master', 'business_nap', 'directory_hub', 'Master Business Profile (NAP)', 
'# Nexus Core Systems Inc.
- **Legal Name**: Nexus Core Systems Incorporated
- **Address**: 555 Mission St, Suite 2400, San Francisco, CA 94105
- **Phone**: +1 (415) 888-2900
- **Support**: support@nexuscore.systems
- **Operating Hours**: Mon-Fri 08:00 - 18:00 PST (24/7 AI Automated Agent Routing)
- **Primary Verticals**: High-Performance Cloud Edge & Autonomous Industrial Infrastructure', 
0.0, 'neutral', 'synced', '{"google_business_id": "GB-88419", "yelp_id": "nexus-core-sf"}');

-- Internal Doc
INSERT OR REPLACE INTO content_blocks (id, block_type, channel_or_source, title, markdown_body, sentiment_score, sentiment_label, author_entity_id, sync_status) VALUES
('blk_doc_runbook', 'doc', 'internal_wiki', 'Zero-Downtime SQLite & MCP Operations Runbook', 
'# Zero-Downtime SQLite & MCP Operations
### Principles
1. **Single Source of Truth**: All state transitions reside in `bos.db`.
2. **WAL Mode**: Never disable Write-Ahead Logging; run `PRAGMA wal_checkpoint(TRUNCATE)` on weekly cron.
3. **Double-Entry Integrity**: Sum of debits must match sum of credits for every `transaction_group_id`.
4. **Agent Guardrails**: Any action touching capital or public communications must pass through `staged_actions`.', 
0.8, 'positive', 'ent_emp_alex', 'synced');

-- Team Chat Messages
INSERT OR REPLACE INTO content_blocks (id, block_type, channel_or_source, title, markdown_body, author_entity_id, sync_status) VALUES
('blk_chat_01', 'chat_message', '#general', NULL, 'Edge Kubernetes node stock is down to 4 units after the Dallas deployment. We should approve the staged PO.', 'ent_emp_priya', 'synced'),
('blk_chat_02', 'chat_message', '#general', NULL, 'Agreed Priya. Autonomous agent just flagged the draft PO in our Inbox. Reviewing it now.', 'ent_emp_alex', 'synced');

-- Customer Reviews (One positive, One urgent negative)
INSERT OR REPLACE INTO content_blocks (id, block_type, channel_or_source, title, markdown_body, sentiment_score, sentiment_label, sync_status, metadata) VALUES
('blk_rev_01', 'customer_review', 'google_maps', 'Flawless edge reliability during Black Friday', 
'We migrated 35 warehouses to Nexus Core nodes. Zero packet drops and the MCP agent automated all our reorders smoothly. Outstanding product!', 
0.95, 'positive', 'synced', '{"rating": 5, "reviewer": "David Sterling (CTO, FastLogistics)"}'),

('blk_rev_02', 'customer_review', 'trustpilot', 'Delayed sensor delivery on Order #882', 
'Our shipment was delayed by 3 business days with no tracking update until Monday morning. Please check shipping SLAs.', 
-0.82, 'urgent_negative', 'pending', '{"rating": 2, "reviewer": "Elena Rostova (Operations VP)", "order_ref": "PO-2026-044"}');

-- 6. Staged Actions (Active HITL Items ready for Human Review in Inbox)
INSERT OR REPLACE INTO staged_actions (id, agent_id, tool_name, parameters_json, proposed_payload_json, risk_level, reasoning, status) VALUES
('stg_po_9912', 'agent_inventory', 'erp_draft_purchase_order', 
'{"sku": "HW-SRV-01", "supplier_id": "ent_hyper", "quantity": 16}', 
'{"supplier_name": "HyperScale Cloud Hardware Inc", "item_name": "Edge Kubernetes Microserver Node", "total_amount": 17600.00, "estimated_delivery_days": 4}', 
'high', 
'Inventory for Edge Microservers is at 4 units (Threshold: 10). Staged PO for 16 units totaling $17,600.00 to prevent stockout.', 
'pending'),

('stg_rev_4410', 'agent_support', 'presence_publish_review_reply', 
'{"review_id": "blk_rev_02", "platform": "trustpilot"}', 
'{"draft_reply": "Dear Elena, we sincerely apologize for the 3-day shipment delay on PO-2026-044. Our logistics team experienced regional carrier backlogs. We have expedited your telemetry sensors and credited $500 shipping fee to your account.", "channel": "trustpilot"}', 
'medium', 
'Urgent negative review detected on Trustpilot (-0.82 sentiment). Generated empathetic apology, credit explanation, and resolution pledge for human approval.', 
'pending'),

('stg_pay_7721', 'agent_hrms', 'hrms_stage_payroll_run', 
'{"batch_period": "2026-11", "department": "All"}', 
'{"total_disbursement": 26000.00, "employee_count": 2, "payroll_records": [{"employee_id": "ent_emp_alex", "amount": 14500}, {"employee_id": "ent_emp_priya", "amount": 11500}]}', 
'critical', 
'Scheduled batch payroll generation for November 2026. Staged ledger entry creation awaiting executive CFO sign-off.', 
'pending');

-- 7. Audit Logs (Time-Travel History)
INSERT OR REPLACE INTO audit_logs (id, actor_type, actor_id, tool_name, table_name, record_id, action, before_json, after_json, is_reverted) VALUES
('aud_001', 'agent', 'agent_inventory', 'inventory_update_stock', 'catalog_items', 'cat_edge_node', 'UPDATE', 
'{"stock_qty": 14, "sku": "HW-SRV-01"}', '{"stock_qty": 4, "sku": "HW-SRV-01"}', 0),
('aud_002', 'human', 'ent_emp_alex', 'crm_move_deal_stage', 'pipeline_states', 'pip_deal_apex', 'UPDATE', 
'{"stage": "qualified"}', '{"stage": "quoted"}', 0);
