/**
 * ====================================================================
 * BUSINESS OPERATING SYSTEM (BOS) - UNIFIED BACKEND & MCP SERVER
 * ====================================================================
 * Zero-bloat, MCP-Native Business OS powered by SQLite (WAL mode).
 * Exposes a Dual-Protocol Service Layer (REST API + MCP STDIO & SSE Transports)
 * with Human-in-the-Loop (HITL) Staging, Scoped RBAC, and 1-Click Rollback.
 */

import { Database } from "bun:sqlite";
import { readFileSync, existsSync } from "fs";
import { join } from "path";

// --------------------------------------------------------------------
// Database Initialization & WAL Mode Configuration
// --------------------------------------------------------------------
const DB_PATH = process.env.DATABASE_PATH || join(process.cwd(), "bos.db");
const PORT = parseInt(process.env.PORT || "8080", 10);
const SCHEMA_FILE = join(process.cwd(), "schema.sql");

const db = new Database(DB_PATH, { create: true });
db.exec("PRAGMA journal_mode = WAL;");
db.exec("PRAGMA synchronous = NORMAL;");
db.exec("PRAGMA foreign_keys = ON;");
db.exec("PRAGMA busy_timeout = 5000;");

// Initialize schema if empty
const tableCheck = db.query<{ count: number }, []>(
  "SELECT count(*) as count FROM sqlite_master WHERE type='table' AND name='entities'"
).get();

if (!tableCheck || tableCheck.count === 0) {
  console.log("[BOS Database] Initializing schema and seed data from schema.sql...");
  if (existsSync(SCHEMA_FILE)) {
    const schemaSql = readFileSync(SCHEMA_FILE, "utf-8");
    db.exec(schemaSql);
    console.log("[BOS Database] Schema & seed data initialized successfully.");
  } else {
    console.warn("[BOS Database] schema.sql not found at:", SCHEMA_FILE);
  }
}

// --------------------------------------------------------------------
// Type Definitions
// --------------------------------------------------------------------
export interface Entity {
  id: string;
  type: "person" | "organization";
  role: "customer" | "lead" | "vendor" | "employee" | "candidate";
  name: string;
  email?: string;
  phone?: string;
  status: string;
  metadata: string;
  created_at: string;
  updated_at: string;
}

export interface CatalogItem {
  id: string;
  sku: string;
  name: string;
  type: "physical" | "digital" | "service";
  stock_qty: number;
  reorder_threshold: number;
  unit_price: number;
  cost_price: number;
  currency: string;
  supplier_entity_id?: string;
  metadata: string;
}

export interface PipelineState {
  id: string;
  category: "deal" | "purchase_order" | "sales_order" | "project_task" | "employee_shift" | "candidate_application";
  title: string;
  stage: string;
  entity_id?: string;
  assigned_to?: string;
  amount: number;
  priority: "low" | "medium" | "high" | "urgent";
  due_date?: string;
  payload_json: string;
}

export interface LedgerEntry {
  id: string;
  transaction_group_id: string;
  type: "debit" | "credit";
  account: string;
  category: string;
  amount: number;
  tax_amount: number;
  currency: string;
  status: string;
  reference_id?: string;
  entity_id?: string;
  description: string;
  created_at: string;
}

export interface ContentBlock {
  id: string;
  block_type: "doc" | "chat_message" | "customer_review" | "business_nap";
  channel_or_source: string;
  title?: string;
  markdown_body: string;
  sentiment_score: number;
  sentiment_label: "positive" | "neutral" | "urgent_negative";
  author_entity_id?: string;
  parent_id?: string;
  sync_status: "synced" | "pending" | "failed";
  metadata: string;
}

export interface StagedAction {
  id: string;
  agent_id: string;
  tool_name: string;
  parameters_json: string;
  proposed_payload_json: string;
  risk_level: "low" | "medium" | "high" | "critical";
  reasoning: string;
  status: "pending" | "approved" | "rejected" | "edited";
  reviewed_by?: string;
  reviewed_at?: string;
  execution_result_json?: string;
  created_at: string;
}

export interface AuditLog {
  id: string;
  actor_type: "human" | "agent" | "system";
  actor_id: string;
  tool_name: string;
  table_name: string;
  record_id: string;
  action: "INSERT" | "UPDATE" | "DELETE" | "ROLLBACK";
  before_json?: string;
  after_json?: string;
  is_reverted: number;
  reverted_by_audit_id?: string;
  created_at: string;
}

// --------------------------------------------------------------------
// Audit & Time-Travel Rollback Engine
// --------------------------------------------------------------------
class AuditEngine {
  static record(
    actorType: "human" | "agent" | "system",
    actorId: string,
    toolName: string,
    tableName: string,
    recordId: string,
    action: "INSERT" | "UPDATE" | "DELETE" | "ROLLBACK",
    beforeData?: any,
    afterData?: any
  ): string {
    const auditId = "aud_" + Math.random().toString(36).substring(2, 10);
    const beforeJson = beforeData ? JSON.stringify(beforeData) : null;
    const afterJson = afterData ? JSON.stringify(afterData) : null;

    db.query(`
      INSERT INTO audit_logs (id, actor_type, actor_id, tool_name, table_name, record_id, action, before_json, after_json)
      VALUES ($id, $actor_type, $actor_id, $tool_name, $table_name, $record_id, $action, $before_json, $after_json)
    `).run({
      $id: auditId,
      $actor_type: actorType,
      $actor_id: actorId,
      $tool_name: toolName,
      $table_name: tableName,
      $record_id: recordId,
      $action: action,
      $before_json: beforeJson,
      $after_json: afterJson,
    });

    return auditId;
  }

  static rollback(auditId: string, operatorId: string = "human_operator"): { success: boolean; message: string; restoredRecord?: any } {
    const audit = db.query<AuditLog, { $id: string }>("SELECT * FROM audit_logs WHERE id = $id").get({ $id: auditId });
    if (!audit) {
      throw new Error(`Audit log entry not found: ${auditId}`);
    }
    if (audit.is_reverted === 1) {
      throw new Error(`Audit log entry ${auditId} has already been reverted.`);
    }

    const { table_name, record_id, action, before_json, after_json } = audit;
    let restoredData: any = null;

    if (action === "UPDATE") {
      if (!before_json) throw new Error("No previous state stored in audit log to revert to.");
      const previousState = JSON.parse(before_json);
      restoredData = previousState;

      // Update the record with previous state
      const keys = Object.keys(previousState).filter(k => k !== "id");
      const setClauses = keys.map(k => `"${k}" = $${k}`).join(", ");
      const params: Record<string, any> = { $id: record_id };
      for (const k of keys) {
        params[`$${k}`] = typeof previousState[k] === "object" ? JSON.stringify(previousState[k]) : previousState[k];
      }

      db.query(`UPDATE "${table_name}" SET ${setClauses}, updated_at = CURRENT_TIMESTAMP WHERE id = $id`).run(params);

    } else if (action === "INSERT") {
      // Reverting an insert means deleting the newly created record
      db.query(`DELETE FROM "${table_name}" WHERE id = $id`).run({ $id: record_id });
      restoredData = { deleted_record_id: record_id };

    } else if (action === "DELETE") {
      if (!before_json) throw new Error("No previous record found to restore.");
      const deletedState = JSON.parse(before_json);
      restoredData = deletedState;
      const keys = Object.keys(deletedState);
      const cols = keys.map(k => `"${k}"`).join(", ");
      const placeholders = keys.map(k => `$${k}`).join(", ");
      const params: Record<string, any> = {};
      for (const k of keys) {
        params[`$${k}`] = typeof deletedState[k] === "object" ? JSON.stringify(deletedState[k]) : deletedState[k];
      }
      db.query(`INSERT INTO "${table_name}" (${cols}) VALUES (${placeholders})`).run(params);
    }

    // Mark current audit log as reverted
    const rollbackLogId = this.record(
      "human",
      operatorId,
      "audit_rollback",
      table_name,
      record_id,
      "ROLLBACK",
      after_json ? JSON.parse(after_json) : null,
      restoredData
    );

    db.query(`UPDATE audit_logs SET is_reverted = 1, reverted_by_audit_id = $rev_id WHERE id = $id`).run({
      $rev_id: rollbackLogId,
      $id: auditId,
    });

    return {
      success: true,
      message: `Successfully rolled back ${action} on ${table_name} (${record_id}).`,
      restoredRecord: restoredData,
    };
  }
}

// --------------------------------------------------------------------
// Human-in-the-Loop (HITL) Staging Engine
// --------------------------------------------------------------------
class HitlEngine {
  static isToolStaged(toolName: string): boolean {
    const policy = db.query<{ requires_hitl: number; risk_level: string }, { $tool: string }>(
      "SELECT requires_hitl, risk_level FROM hitl_policies WHERE tool_name = $tool"
    ).get({ $tool: toolName });

    if (policy) {
      return policy.requires_hitl === 1;
    }
    // High-risk defaults
    const highRiskTools = [
      "erp_draft_purchase_order",
      "finance_issue_invoice",
      "hrms_stage_payroll_run",
      "presence_publish_review_reply",
      "presence_sync_nap_listings"
    ];
    return highRiskTools.includes(toolName);
  }

  static stageAction(
    agentId: string,
    toolName: string,
    parameters: any,
    proposedPayload: any,
    riskLevel: "low" | "medium" | "high" | "critical",
    reasoning: string
  ): StagedAction {
    const stagedId = "stg_" + Math.random().toString(36).substring(2, 9);
    db.query(`
      INSERT INTO staged_actions (id, agent_id, tool_name, parameters_json, proposed_payload_json, risk_level, reasoning, status)
      VALUES ($id, $agent_id, $tool_name, $parameters_json, $proposed_payload_json, $risk_level, $reasoning, 'pending')
    `).run({
      $id: stagedId,
      $agent_id: agentId,
      $tool_name: toolName,
      $parameters_json: JSON.stringify(parameters),
      $proposed_payload_json: JSON.stringify(proposedPayload),
      $risk_level: riskLevel,
      $reasoning: reasoning,
    });

    return db.query<StagedAction, { $id: string }>("SELECT * FROM staged_actions WHERE id = $id").get({ $id: stagedId })!;
  }

  static approveAction(stagedId: string, reviewerId: string = "human_operator"): any {
    const action = db.query<StagedAction, { $id: string }>("SELECT * FROM staged_actions WHERE id = $id").get({ $id: stagedId });
    if (!action) throw new Error(`Staged action ${stagedId} not found.`);
    if (action.status !== "pending") throw new Error(`Action is already ${action.status}.`);

    const params = JSON.parse(action.parameters_json);
    const proposed = JSON.parse(action.proposed_payload_json);

    // Execute the underlying high-stakes tool directly with human bypass
    const executionResult = BusinessCoreService.executeToolInternal(action.tool_name, { ...params, ...proposed }, reviewerId, true);

    db.query(`
      UPDATE staged_actions
      SET status = 'approved',
          reviewed_by = $reviewer,
          reviewed_at = CURRENT_TIMESTAMP,
          execution_result_json = $result
      WHERE id = $id
    `).run({
      $reviewer: reviewerId,
      $result: JSON.stringify(executionResult),
      $id: stagedId,
    });

    return {
      status: "approved",
      staged_id: stagedId,
      executionResult,
    };
  }

  static rejectAction(stagedId: string, reviewerId: string = "human_operator", note?: string): any {
    const action = db.query<StagedAction, { $id: string }>("SELECT * FROM staged_actions WHERE id = $id").get({ $id: stagedId });
    if (!action) throw new Error(`Staged action ${stagedId} not found.`);
    if (action.status !== "pending") throw new Error(`Action is already ${action.status}.`);

    db.query(`
      UPDATE staged_actions
      SET status = 'rejected',
          reviewed_by = $reviewer,
          reviewed_at = CURRENT_TIMESTAMP,
          execution_result_json = $result
      WHERE id = $id
    `).run({
      $reviewer: reviewerId,
      $result: JSON.stringify({ rejected: true, note: note || "Rejected by operator" }),
      $id: stagedId,
    });

    return { status: "rejected", staged_id: stagedId };
  }

  static editAndApproveAction(stagedId: string, updatedPayload: any, reviewerId: string = "human_operator"): any {
    const action = db.query<StagedAction, { $id: string }>("SELECT * FROM staged_actions WHERE id = $id").get({ $id: stagedId });
    if (!action) throw new Error(`Staged action ${stagedId} not found.`);
    if (action.status !== "pending") throw new Error(`Action is already ${action.status}.`);

    const executionResult = BusinessCoreService.executeToolInternal(action.tool_name, updatedPayload, reviewerId, true);

    db.query(`
      UPDATE staged_actions
      SET status = 'edited',
          proposed_payload_json = $payload,
          reviewed_by = $reviewer,
          reviewed_at = CURRENT_TIMESTAMP,
          execution_result_json = $result
      WHERE id = $id
    `).run({
      $payload: JSON.stringify(updatedPayload),
      $reviewer: reviewerId,
      $result: JSON.stringify(executionResult),
      $id: stagedId,
    });

    return { status: "edited_and_approved", staged_id: stagedId, executionResult };
  }
}

// --------------------------------------------------------------------
// Unified Core Business Service Layer
// Shared by both REST API and MCP Tool / Resource handlers
// --------------------------------------------------------------------
export class BusinessCoreService {
  // 1. Business Pulse Executive Summary
  static getBusinessPulse() {
    // Financial metrics from double-entry ledger
    const cashRow = db.query<{ cash_balance: number }, []>(`
      SELECT 
        COALESCE(SUM(CASE WHEN type = 'debit' THEN amount ELSE -amount END), 0) as cash_balance
      FROM ledger_entries 
      WHERE account = 'cash' AND status = 'posted'
    `).get();

    const pnlRow = db.query<{ total_revenue: number; total_expense: number }, []>(`
      SELECT 
        COALESCE(SUM(CASE WHEN account = 'revenue' AND type = 'credit' THEN amount ELSE 0 END), 0) as total_revenue,
        COALESCE(SUM(CASE WHEN account IN ('operating_expense', 'payroll_expense', 'cogs') AND type = 'debit' THEN amount ELSE 0 END), 0) as total_expense
      FROM ledger_entries
      WHERE status = 'posted'
    `).get();

    const cashBalance = cashRow?.cash_balance ?? 0;
    const revenue = pnlRow?.total_revenue ?? 0;
    const expenses = pnlRow?.total_expense ?? 0;
    const netPnL = revenue - expenses;

    // Inventory metrics
    const lowStockItems = db.query<CatalogItem, []>(`
      SELECT * FROM catalog_items 
      WHERE stock_qty <= reorder_threshold
    `).all();

    // CRM Deals Pipeline Velocity
    const pipelineSummary = db.query<{ stage: string; count: number; total_amount: number }, []>(`
      SELECT stage, count(*) as count, COALESCE(SUM(amount), 0) as total_amount
      FROM pipeline_states
      WHERE category = 'deal'
      GROUP BY stage
    `).all();

    // Reputation: Unanswered negative reviews
    const urgentReviews = db.query<ContentBlock, []>(`
      SELECT * FROM content_blocks
      WHERE block_type = 'customer_review' 
        AND sentiment_label = 'urgent_negative'
        AND sync_status != 'resolved'
    `).all();

    // Pending Staged Actions
    const pendingActionsCount = db.query<{ count: number }, []>(
      "SELECT count(*) as count FROM staged_actions WHERE status = 'pending'"
    ).get()?.count ?? 0;

    return {
      timestamp: new Date().toISOString(),
      cash_balance: cashBalance,
      revenue,
      expenses,
      net_pnl: netPnL,
      low_stock_count: lowStockItems.length,
      low_stock_skus: lowStockItems.map(i => ({ sku: i.sku, name: i.name, stock: i.stock_qty, threshold: i.reorder_threshold })),
      pipeline_summary: pipelineSummary,
      urgent_reviews_count: urgentReviews.length,
      urgent_reviews: urgentReviews.map(r => ({ id: r.id, source: r.channel_or_source, title: r.title, sentiment: r.sentiment_score })),
      pending_approvals_count: pendingActionsCount,
    };
  }

  // 2. 360-Degree Entity Profile
  static getEntity360(entityId: string) {
    const entity = db.query<Entity, { $id: string }>("SELECT * FROM entities WHERE id = $id").get({ $id: entityId });
    if (!entity) throw new Error(`Entity not found: ${entityId}`);

    const deals = db.query<PipelineState, { $id: string }>(
      "SELECT * FROM pipeline_states WHERE entity_id = $id OR assigned_to = $id ORDER BY created_at DESC"
    ).all({ $id: entityId });

    const ledger = db.query<LedgerEntry, { $id: string }>(
      "SELECT * FROM ledger_entries WHERE entity_id = $id ORDER BY created_at DESC LIMIT 50"
    ).all({ $id: entityId });

    const content = db.query<ContentBlock, { $id: string }>(
      "SELECT * FROM content_blocks WHERE author_entity_id = $id ORDER BY created_at DESC LIMIT 20"
    ).all({ $id: entityId });

    return {
      entity: { ...entity, metadata: JSON.parse(entity.metadata || "{}") },
      pipeline_records: deals.map(d => ({ ...d, payload_json: JSON.parse(d.payload_json || "{}") })),
      financial_transactions: ledger,
      communications_and_notes: content,
    };
  }

  // 3. Low Stock Inventory Query
  static getLowStock() {
    return db.query(`
      SELECT c.*, e.name as supplier_name, e.email as supplier_email
      FROM catalog_items c
      LEFT JOIN entities e ON c.supplier_entity_id = e.id
      WHERE c.stock_qty <= c.reorder_threshold
    `).all();
  }

  // Safe Tools Implementation
  static crmSearchEntities(query: string, role?: string, status?: string) {
    let sql = `SELECT * FROM entities WHERE (name LIKE $q OR email LIKE $q)`;
    const params: Record<string, any> = { $q: `%${query}%` };
    if (role) {
      sql += ` AND role = $role`;
      params.$role = role;
    }
    if (status) {
      sql += ` AND status = $status`;
      params.$status = status;
    }
    sql += ` LIMIT 20`;
    return db.query(sql).all(params);
  }

  static crmMoveDealStage(dealId: string, newStage: string, actorId: string = "system") {
    const before = db.query<PipelineState, { $id: string }>("SELECT * FROM pipeline_states WHERE id = $id").get({ $id: dealId });
    if (!before) throw new Error(`Deal ${dealId} not found.`);

    db.query(`UPDATE pipeline_states SET stage = $stage, updated_at = CURRENT_TIMESTAMP WHERE id = $id`).run({
      $stage: newStage,
      $id: dealId,
    });

    const after = db.query<PipelineState, { $id: string }>("SELECT * FROM pipeline_states WHERE id = $id").get({ $id: dealId });
    AuditEngine.record(actorId.startsWith("agent") ? "agent" : "human", actorId, "crm_move_deal_stage", "pipeline_states", dealId, "UPDATE", before, after);

    return { deal_id: dealId, previous_stage: before.stage, new_stage: newStage };
  }

  static inventoryCheckStock(sku?: string) {
    if (sku) {
      const item = db.query<CatalogItem, { $sku: string }>("SELECT * FROM catalog_items WHERE sku = $sku").get({ $sku: sku });
      if (!item) throw new Error(`SKU ${sku} not found.`);
      return { ...item, is_low_stock: item.stock_qty <= item.reorder_threshold };
    }
    return db.query("SELECT * FROM catalog_items ORDER BY stock_qty ASC").all();
  }

  static workCreateTask(title: string, priority: "low" | "medium" | "high" | "urgent", assignedTo?: string, dueDate?: string, payload?: any, actorId: string = "system") {
    const taskId = "pip_tsk_" + Math.random().toString(36).substring(2, 8);
    db.query(`
      INSERT INTO pipeline_states (id, category, title, stage, assigned_to, priority, due_date, payload_json)
      VALUES ($id, 'project_task', $title, 'todo', $assigned_to, $priority, $due_date, $payload)
    `).run({
      $id: taskId,
      $title: title,
      $assigned_to: assignedTo || null,
      $priority: priority,
      $due_date: dueDate || null,
      $payload: JSON.stringify(payload || {}),
    });

    const after = db.query("SELECT * FROM pipeline_states WHERE id = $id").get({ $id: taskId });
    AuditEngine.record(actorId.startsWith("agent") ? "agent" : "human", actorId, "work_create_task", "pipeline_states", taskId, "INSERT", null, after);

    return after;
  }

  static docsAppendNote(title: string, markdownBody: string, channel: string = "internal_wiki", authorId?: string, actorId: string = "system") {
    const docId = "blk_doc_" + Math.random().toString(36).substring(2, 8);
    db.query(`
      INSERT INTO content_blocks (id, block_type, channel_or_source, title, markdown_body, author_entity_id, sync_status)
      VALUES ($id, 'doc', $channel, $title, $body, $author, 'synced')
    `).run({
      $id: docId,
      $channel: channel,
      $title: title,
      $body: markdownBody,
      $author: authorId || null,
    });

    const created = db.query("SELECT * FROM content_blocks WHERE id = $id").get({ $id: docId });
    AuditEngine.record(actorId.startsWith("agent") ? "agent" : "human", actorId, "docs_append_note", "content_blocks", docId, "INSERT", null, created);

    return created;
  }

  static reviewsFetchUnanswered() {
    return db.query(`
      SELECT * FROM content_blocks
      WHERE block_type = 'customer_review' AND sync_status != 'resolved'
      ORDER BY sentiment_score ASC
    `).all();
  }

  // High-Stakes Tools (Routed to HITL unless approved/bypassed)
  static erpDraftPurchaseOrder(sku: string, quantity: number, supplierId?: string, actorId: string = "system", bypassHitl: boolean = false) {
    const item = db.query<CatalogItem, { $sku: string }>("SELECT * FROM catalog_items WHERE sku = $sku").get({ $sku: sku });
    if (!item) throw new Error(`SKU ${sku} not found.`);

    const effectiveSupplier = supplierId || item.supplier_entity_id;
    const estCost = quantity * item.cost_price;

    if (!bypassHitl && HitlEngine.isToolStaged("erp_draft_purchase_order")) {
      return HitlEngine.stageAction(
        actorId,
        "erp_draft_purchase_order",
        { sku, quantity, supplierId: effectiveSupplier },
        {
          sku,
          quantity,
          item_name: item.name,
          estimated_cost: estCost,
          supplier_id: effectiveSupplier,
        },
        "high",
        `Autonomous request to issue PO for ${quantity} units of ${item.name} ($${estCost.toFixed(2)}).`
      );
    }

    // Direct execution
    const poId = "pip_po_" + Math.random().toString(36).substring(2, 8);
    db.query(`
      INSERT INTO pipeline_states (id, category, title, stage, entity_id, amount, priority, payload_json)
      VALUES ($id, 'purchase_order', $title, 'approved', $supplier_id, $amount, 'high', $payload)
    `).run({
      $id: poId,
      $title: `Purchase Order: ${item.name} (${quantity} units)`,
      $supplier_id: effectiveSupplier || null,
      $amount: estCost,
      $payload: JSON.stringify({ sku, quantity, unit_cost: item.cost_price }),
    });

    // Update stock inventory
    db.query(`UPDATE catalog_items SET stock_qty = stock_qty + $qty WHERE sku = $sku`).run({
      $qty: quantity,
      $sku: sku,
    });

    const po = db.query("SELECT * FROM pipeline_states WHERE id = $id").get({ $id: poId });
    AuditEngine.record(actorId.startsWith("agent") ? "agent" : "human", actorId, "erp_draft_purchase_order", "pipeline_states", poId, "INSERT", null, po);

    return { executed: true, purchase_order: po };
  }

  static financeIssueInvoice(customerId: string, amount: number, description: string, taxAmount: number = 0, actorId: string = "system", bypassHitl: boolean = false) {
    if (!bypassHitl && HitlEngine.isToolStaged("finance_issue_invoice")) {
      return HitlEngine.stageAction(
        actorId,
        "finance_issue_invoice",
        { customerId, amount, description, taxAmount },
        { customerId, amount, description, taxAmount, netTotal: amount + taxAmount },
        "high",
        `Staged outbound invoice of $${(amount + taxAmount).toFixed(2)} for entity ${customerId}.`
      );
    }

    const txGroup = "tx_grp_inv_" + Math.random().toString(36).substring(2, 8);
    const invoiceRef = "INV-" + new Date().getFullYear() + "-" + Math.floor(1000 + Math.random() * 9000);

    // Double Entry: Debit Accounts Receivable, Credit Revenue
    const ledDebitId = "led_" + Math.random().toString(36).substring(2, 8);
    const ledCreditId = "led_" + Math.random().toString(36).substring(2, 8);

    db.query(`
      INSERT INTO ledger_entries (id, transaction_group_id, type, account, category, amount, tax_amount, status, reference_id, entity_id, description)
      VALUES 
        ($id1, $txGroup, 'debit', 'accounts_receivable', 'invoice', $amount, 0, 'posted', $ref, $entityId, $desc1),
        ($id2, $txGroup, 'credit', 'revenue', 'invoice', $amount, $taxAmount, 'posted', $ref, $entityId, $desc2)
    `).run({
      $id1: ledDebitId,
      $id2: ledCreditId,
      $txGroup: txGroup,
      $amount: amount,
      $taxAmount: taxAmount,
      $ref: invoiceRef,
      $entityId: customerId,
      $desc1: `AR: ${description} (${invoiceRef})`,
      $desc2: `Revenue: ${description} (${invoiceRef})`,
    });

    AuditEngine.record(actorId.startsWith("agent") ? "agent" : "human", actorId, "finance_issue_invoice", "ledger_entries", txGroup, "INSERT", null, {
      invoiceRef,
      amount,
      taxAmount,
      customerId,
    });

    return { executed: true, invoice_ref: invoiceRef, transaction_group_id: txGroup, amount, taxAmount };
  }

  static hrmsStagePayrollRun(batchPeriod: string, actorId: string = "system", bypassHitl: boolean = false) {
    const employees = db.query<Entity, []>("SELECT * FROM entities WHERE role = 'employee' AND status = 'active'").all();
    let totalPayroll = 0;
    const payouts: any[] = [];

    for (const emp of employees) {
      const meta = JSON.parse(emp.metadata || "{}");
      const salary = meta.salary || 5000;
      totalPayroll += salary;
      payouts.push({ employee_id: emp.id, name: emp.name, salary });
    }

    if (!bypassHitl && HitlEngine.isToolStaged("hrms_stage_payroll_run")) {
      return HitlEngine.stageAction(
        actorId,
        "hrms_stage_payroll_run",
        { batchPeriod },
        { batchPeriod, total_disbursement: totalPayroll, employee_count: employees.length, payouts },
        "critical",
        `High-stakes payroll disbursement of $${totalPayroll.toFixed(2)} across ${employees.length} employees for ${batchPeriod}.`
      );
    }

    // Direct execution: Double-entry ledger disbursement
    const txGroup = "tx_grp_pay_" + Math.random().toString(36).substring(2, 8);
    for (const p of payouts) {
      const dId = "led_" + Math.random().toString(36).substring(2, 8);
      const cId = "led_" + Math.random().toString(36).substring(2, 8);
      db.query(`
        INSERT INTO ledger_entries (id, transaction_group_id, type, account, category, amount, status, reference_id, entity_id, description)
        VALUES
          ($dId, $txGroup, 'debit', 'payroll_expense', 'payroll', $amount, 'posted', $ref, $entityId, $desc1),
          ($cId, $txGroup, 'credit', 'cash', 'payroll', $amount, 'posted', $ref, $entityId, $desc2)
      `).run({
        $dId: dId,
        $cId: cId,
        $txGroup: txGroup,
        $amount: p.salary,
        $ref: `PAY-${batchPeriod}`,
        $entityId: p.employee_id,
        $desc1: `Salary Expense: ${p.name}`,
        $desc2: `Payroll direct deposit payout: ${p.name}`,
      });
    }

    AuditEngine.record(actorId.startsWith("agent") ? "agent" : "human", actorId, "hrms_stage_payroll_run", "ledger_entries", txGroup, "INSERT", null, {
      totalPayroll,
      payouts,
    });

    return { executed: true, batchPeriod, total_disbursed: totalPayroll, transaction_group_id: txGroup };
  }

  static presencePublishReviewReply(reviewId: string, replyText: string, platform?: string, actorId: string = "system", bypassHitl: boolean = false) {
    const review = db.query<ContentBlock, { $id: string }>("SELECT * FROM content_blocks WHERE id = $id").get({ $id: reviewId });
    if (!review) throw new Error(`Review ${reviewId} not found.`);

    if (!bypassHitl && HitlEngine.isToolStaged("presence_publish_review_reply")) {
      return HitlEngine.stageAction(
        actorId,
        "presence_publish_review_reply",
        { reviewId, platform: platform || review.channel_or_source },
        { reviewId, draft_reply: replyText, platform: platform || review.channel_or_source },
        "medium",
        `Staged public response to customer review on ${review.channel_or_source} to ensure brand compliance.`
      );
    }

    const replyBlockId = "blk_rep_" + Math.random().toString(36).substring(2, 8);
    db.query(`
      INSERT INTO content_blocks (id, block_type, channel_or_source, title, markdown_body, parent_id, sync_status)
      VALUES ($id, 'customer_review', $channel, 'Public Response', $body, $parent, 'synced')
    `).run({
      $id: replyBlockId,
      $channel: review.channel_or_source,
      $body: replyText,
      $parent: reviewId,
    });

    // Mark original review resolved
    db.query(`UPDATE content_blocks SET sync_status = 'resolved' WHERE id = $id`).run({ $id: reviewId });

    AuditEngine.record(actorId.startsWith("agent") ? "agent" : "human", actorId, "presence_publish_review_reply", "content_blocks", replyBlockId, "INSERT", null, {
      reviewId,
      replyText,
    });

    return { executed: true, reply_id: replyBlockId, status: "published_to_platform" };
  }

  static presenceSyncNapListings(directories: string[] = ["google_maps", "yelp", "apple_maps"], actorId: string = "system", bypassHitl: boolean = false) {
    const nap = db.query<ContentBlock, []>("SELECT * FROM content_blocks WHERE block_type = 'business_nap' LIMIT 1").get();
    if (!nap) throw new Error("Master NAP profile not found in content_blocks.");

    if (!bypassHitl && HitlEngine.isToolStaged("presence_sync_nap_listings")) {
      return HitlEngine.stageAction(
        actorId,
        "presence_sync_nap_listings",
        { directories },
        { directories, nap_summary: nap.markdown_body },
        "medium",
        `Staged global NAP sync to external local directories (${directories.join(", ")}).`
      );
    }

    // Direct execution
    db.query(`UPDATE content_blocks SET sync_status = 'synced', updated_at = CURRENT_TIMESTAMP WHERE id = $id`).run({
      $id: nap.id,
    });

    AuditEngine.record(actorId.startsWith("agent") ? "agent" : "human", actorId, "presence_sync_nap_listings", "content_blocks", nap.id, "UPDATE", null, {
      directories,
      sync_status: "synced",
    });

    return { executed: true, synced_directories: directories, timestamp: new Date().toISOString() };
  }

  // Internal dispatcher supporting human approval bypass
  static executeToolInternal(toolName: string, args: any, actorId: string, bypassHitl: boolean): any {
    switch (toolName) {
      case "crm_search_entities":
        return this.crmSearchEntities(args.query || "", args.role, args.status);
      case "crm_move_deal_stage":
        return this.crmMoveDealStage(args.deal_id, args.stage, actorId);
      case "inventory_check_stock":
        return this.inventoryCheckStock(args.sku);
      case "work_create_task":
        return this.workCreateTask(args.title, args.priority || "medium", args.assigned_to, args.due_date, args.payload, actorId);
      case "docs_append_note":
        return this.docsAppendNote(args.title, args.markdown_body, args.channel, args.author_id, actorId);
      case "reviews_fetch_unanswered":
        return this.reviewsFetchUnanswered();
      case "erp_draft_purchase_order":
        return this.erpDraftPurchaseOrder(args.sku, args.quantity, args.supplier_id, actorId, bypassHitl);
      case "finance_issue_invoice":
        return this.financeIssueInvoice(args.customer_id || args.customerId, args.amount, args.description, args.tax_amount || args.taxAmount || 0, actorId, bypassHitl);
      case "hrms_stage_payroll_run":
        return this.hrmsStagePayrollRun(args.batch_period || args.batchPeriod || "2026-11", actorId, bypassHitl);
      case "presence_publish_review_reply":
        return this.presencePublishReviewReply(args.review_id || args.reviewId, args.reply_text || args.replyText || args.draft_reply, args.platform, actorId, bypassHitl);
      case "presence_sync_nap_listings":
        return this.presenceSyncNapListings(args.directories, actorId, bypassHitl);
      default:
        throw new Error(`Unknown MCP Tool: ${toolName}`);
    }
  }
}

// --------------------------------------------------------------------
// Scoped RBAC Middleware
// --------------------------------------------------------------------
function verifyAgentToken(authHeader: string | null, requiredTool: string): { authorized: boolean; agentId: string; error?: string } {
  if (!authHeader) {
    // Local / unauthenticated requests in development default to system
    return { authorized: true, agentId: "operator:local" };
  }

  const token = authHeader.replace(/^Bearer\s+/i, "").trim();
  const agentKey = db.query<{ id: string; name: string; scopes: string; is_active: number }, { $token: string }>(
    "SELECT * FROM agent_tokens WHERE token = $token"
  ).get({ $token: token });

  if (!agentKey || agentKey.is_active === 0) {
    return { authorized: false, agentId: "anonymous", error: "Invalid or inactive Agent API Token." };
  }

  const scopes: string[] = JSON.parse(agentKey.scopes || "[]");
  if (scopes.includes("*")) {
    return { authorized: true, agentId: agentKey.id };
  }

  // Check matching scope prefix (e.g. "crm:*" matches "crm_search_entities")
  const prefix = requiredTool.split("_")[0];
  const hasScope = scopes.some(s => s === requiredTool || s === `${prefix}:*` || s === `${prefix}_*`);

  if (!hasScope) {
    return {
      authorized: false,
      agentId: agentKey.id,
      error: `Scope forbidden: Token '${agentKey.name}' lacks scope for tool '${requiredTool}'. Allowed: [${scopes.join(", ")}]`,
    };
  }

  return { authorized: true, agentId: agentKey.id };
}

// --------------------------------------------------------------------
// MCP Protocol Definitions (JSON Schemas)
// --------------------------------------------------------------------
const MCP_TOOLS = [
  {
    name: "crm_search_entities",
    description: "Search customers, leads, vendors, or employees by name, email, or status.",
    inputSchema: {
      type: "object",
      properties: {
        query: { type: "string", description: "Search keyword" },
        role: { type: "string", enum: ["customer", "lead", "vendor", "employee", "candidate"] },
        status: { type: "string", description: "Filter by status" },
      },
      required: ["query"],
    },
  },
  {
    name: "crm_move_deal_stage",
    description: "Advance or update the pipeline stage of a CRM deal.",
    inputSchema: {
      type: "object",
      properties: {
        deal_id: { type: "string", description: "Pipeline deal ID" },
        stage: { type: "string", description: "Target stage (lead, qualified, quoted, won, lost)" },
      },
      required: ["deal_id", "stage"],
    },
  },
  {
    name: "inventory_check_stock",
    description: "Check on-hand stock and reorder thresholds for physical catalog SKUs.",
    inputSchema: {
      type: "object",
      properties: {
        sku: { type: "string", description: "Optional specific SKU to check" },
      },
    },
  },
  {
    name: "work_create_task",
    description: "Create a new project delivery task or shift assignment.",
    inputSchema: {
      type: "object",
      properties: {
        title: { type: "string", description: "Task title" },
        priority: { type: "string", enum: ["low", "medium", "high", "urgent"] },
        assigned_to: { type: "string", description: "Entity ID of assignee" },
        due_date: { type: "string", description: "ISO date string" },
        payload: { type: "object", description: "Additional task metadata" },
      },
      required: ["title"],
    },
  },
  {
    name: "docs_append_note",
    description: "Create or append documentation or knowledge-base notes.",
    inputSchema: {
      type: "object",
      properties: {
        title: { type: "string", description: "Document title" },
        markdown_body: { type: "string", description: "Markdown text content" },
        channel: { type: "string", description: "Topic channel or wiki folder" },
        author_id: { type: "string", description: "Entity ID of author" },
      },
      required: ["title", "markdown_body"],
    },
  },
  {
    name: "reviews_fetch_unanswered",
    description: "Fetch pending, unreplied customer reviews across Google Maps and Trustpilot.",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  // High-Stakes / Staged Tools
  {
    name: "erp_draft_purchase_order",
    description: "HIGH-STAKES: Stages a Purchase Order to restock low-inventory SKUs. Routes to HITL queue.",
    inputSchema: {
      type: "object",
      properties: {
        sku: { type: "string", description: "Catalog item SKU" },
        quantity: { type: "number", description: "Units to order" },
        supplier_id: { type: "string", description: "Optional vendor entity ID" },
      },
      required: ["sku", "quantity"],
    },
  },
  {
    name: "finance_issue_invoice",
    description: "HIGH-STAKES: Stages an outbound invoice in the double-entry financial ledger. Routes to HITL queue.",
    inputSchema: {
      type: "object",
      properties: {
        customer_id: { type: "string", description: "Customer entity ID" },
        amount: { type: "number", description: "Invoice subtotal" },
        description: { type: "string", description: "Invoice line description" },
        tax_amount: { type: "number", description: "Applicable sales/VAT tax" },
      },
      required: ["customer_id", "amount", "description"],
    },
  },
  {
    name: "hrms_stage_payroll_run",
    description: "CRITICAL: Stages scheduled batch salary disbursements for active employees. Routes to HITL queue.",
    inputSchema: {
      type: "object",
      properties: {
        batch_period: { type: "string", description: "Billing period, e.g. '2026-11'" },
      },
      required: ["batch_period"],
    },
  },
  {
    name: "presence_publish_review_reply",
    description: "HIGH-STAKES: Publishes a public business reply to a customer review. Routes to HITL queue.",
    inputSchema: {
      type: "object",
      properties: {
        review_id: { type: "string", description: "Target customer review content block ID" },
        reply_text: { type: "string", description: "Brand-aligned public response text" },
        platform: { type: "string", description: "Target directory platform" },
      },
      required: ["review_id", "reply_text"],
    },
  },
  {
    name: "presence_sync_nap_listings",
    description: "HIGH-STAKES: Broadcasts updated business NAP (Name, Address, Phone) to external directories.",
    inputSchema: {
      type: "object",
      properties: {
        directories: {
          type: "array",
          items: { type: "string" },
          description: "List of directories: google_maps, yelp, apple_maps",
        },
      },
    },
  },
];

const MCP_RESOURCES = [
  {
    uri: "mcp://business/pulse",
    name: "Business Pulse Executive Summary",
    mimeType: "application/json",
    description: "Compact real-time executive health metrics (Cash, Net P&L, Low Stock, Unanswered Reviews).",
  },
  {
    uri: "mcp://entities/{id}/360",
    name: "Entity 360 Relationship Graph",
    mimeType: "application/json",
    description: "Comprehensive 360-degree relationship view of any customer, vendor, or employee.",
  },
  {
    uri: "mcp://inventory/low-stock",
    name: "Low-Stock SKU Alerts",
    mimeType: "application/json",
    description: "Real-time list of all SKUs currently at or below their automated reorder thresholds.",
  },
];

// --------------------------------------------------------------------
// MCP STDIO Server Protocol Handler
// Enables local agents (e.g. Claude Desktop, Cursor) to connect via STDIO
// --------------------------------------------------------------------
export function startMcpStdioServer() {
  process.stdin.setEncoding("utf-8");
  let buffer = "";

  process.stdin.on("data", (chunk: string) => {
    buffer += chunk;
    const lines = buffer.split("\n");
    buffer = lines.pop() || "";

    for (const line of lines) {
      if (!line.trim()) continue;
      try {
        const message = JSON.parse(line.trim());
        const response = handleMcpJsonRpc(message, "stdio:agent");
        if (response) {
          process.stdout.write(JSON.stringify(response) + "\n");
        }
      } catch (err: any) {
        process.stdout.write(
          JSON.stringify({
            jsonrpc: "2.0",
            id: null,
            error: { code: -32700, message: "Parse error: " + err.message },
          }) + "\n"
        );
      }
    }
  });
}

function handleMcpJsonRpc(message: any, callerId: string): any {
  const { id, method, params } = message;

  switch (method) {
    case "initialize":
      return {
        jsonrpc: "2.0",
        id,
        result: {
          protocolVersion: "2024-11-05",
          serverInfo: {
            name: "BOS Unified Core MCP Server",
            version: "2.0.0",
          },
          capabilities: {
            tools: { listChanged: false },
            resources: { subscribe: false, listChanged: false },
          },
        },
      };

    case "resources/list":
      return {
        jsonrpc: "2.0",
        id,
        result: { resources: MCP_RESOURCES },
      };

    case "resources/read": {
      const uri = params?.uri as string;
      if (!uri) throw new Error("Missing uri parameter");

      if (uri === "mcp://business/pulse") {
        const pulse = BusinessCoreService.getBusinessPulse();
        return {
          jsonrpc: "2.0",
          id,
          result: {
            contents: [
              {
                uri,
                mimeType: "application/json",
                text: JSON.stringify(pulse, null, 2),
              },
            ],
          },
        };
      }

      if (uri === "mcp://inventory/low-stock") {
        const lowStock = BusinessCoreService.getLowStock();
        return {
          jsonrpc: "2.0",
          id,
          result: {
            contents: [
              {
                uri,
                mimeType: "application/json",
                text: JSON.stringify(lowStock, null, 2),
              },
            ],
          },
        };
      }

      if (uri.startsWith("mcp://entities/")) {
        const parts = uri.replace("mcp://entities/", "").split("/");
        const entityId = parts[0];
        const profile = BusinessCoreService.getEntity360(entityId);
        return {
          jsonrpc: "2.0",
          id,
          result: {
            contents: [
              {
                uri,
                mimeType: "application/json",
                text: JSON.stringify(profile, null, 2),
              },
            ],
          },
        };
      }

      return {
        jsonrpc: "2.0",
        id,
        error: { code: -32602, message: `Resource URI not supported: ${uri}` },
      };
    }

    case "tools/list":
      return {
        jsonrpc: "2.0",
        id,
        result: { tools: MCP_TOOLS },
      };

    case "tools/call": {
      const toolName = params?.name;
      const toolArgs = params?.arguments || {};

      try {
        const result = BusinessCoreService.executeToolInternal(toolName, toolArgs, callerId, false);
        return {
          jsonrpc: "2.0",
          id,
          result: {
            content: [
              {
                type: "text",
                text: JSON.stringify(result, null, 2),
              },
            ],
          },
        };
      } catch (err: any) {
        return {
          jsonrpc: "2.0",
          id,
          result: {
            isError: true,
            content: [{ type: "text", text: `Error executing tool '${toolName}': ${err.message}` }],
          },
        };
      }
    }

    case "notifications/initialized":
      return null;

    default:
      return {
        jsonrpc: "2.0",
        id,
        error: { code: -32601, message: `Method not found: ${method}` },
      };
  }
}

// --------------------------------------------------------------------
// Unified HTTP Server & REST API + MCP SSE Streaming
// --------------------------------------------------------------------
const sseClients = new Map<string, (data: string) => void>();

function jsonResponse(data: any, status: number = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
    },
  });
}

export function startHttpServer() {
  Bun.serve({
    port: PORT,
    async fetch(req) {
      const url = new URL(req.url);
      const path = url.pathname;
      const method = req.method;

      // Handle CORS Preflight
      if (method === "OPTIONS") {
        return new Response(null, {
          headers: {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
          },
        });
      }

      // --------------------------------------------------------------
      // MCP Streamable HTTP / Server-Sent Events (SSE) Protocol
      // --------------------------------------------------------------
      if (path === "/mcp/sse" && method === "GET") {
        const sessionId = "sess_" + Math.random().toString(36).substring(2, 10);
        let sendEvent: ((data: string) => void) | null = null;

        const stream = new ReadableStream({
          start(controller) {
            sendEvent = (data: string) => {
              controller.enqueue(new TextEncoder().encode(`event: message\ndata: ${data}\n\n`));
            };
            sseClients.set(sessionId, sendEvent);

            // Announce endpoint
            controller.enqueue(
              new TextEncoder().encode(
                `event: endpoint\ndata: /mcp/messages?sessionId=${sessionId}\n\n`
              )
            );
          },
          cancel() {
            sseClients.delete(sessionId);
          },
        });

        return new Response(stream, {
          headers: {
            "Content-Type": "text/event-stream",
            "Cache-Control": "no-cache",
            Connection: "keep-alive",
            "Access-Control-Allow-Origin": "*",
          },
        });
      }

      if (path === "/mcp/messages" && method === "POST") {
        const sessionId = url.searchParams.get("sessionId");
        const body = await req.json();
        const auth = verifyAgentToken(req.headers.get("Authorization"), body?.params?.name || "");

        if (!auth.authorized) {
          return jsonResponse({ error: auth.error }, 403);
        }

        const response = handleMcpJsonRpc(body, auth.agentId);

        // If client is listening on SSE, push to their stream
        if (sessionId && sseClients.has(sessionId)) {
          sseClients.get(sessionId)!(JSON.stringify(response));
        }

        return jsonResponse(response);
      }

      // --------------------------------------------------------------
      // REST API: Business Pulse & Executive Overview
      // --------------------------------------------------------------
      if (path === "/api/pulse" && method === "GET") {
        return jsonResponse(BusinessCoreService.getBusinessPulse());
      }

      // --------------------------------------------------------------
      // REST API: Human-in-the-Loop Action Approval Stream (Inbox)
      // --------------------------------------------------------------
      if (path === "/api/staged-actions" && method === "GET") {
        const status = url.searchParams.get("status") || "pending";
        const actions = db.query<StagedAction, { $st: string }>(
          "SELECT * FROM staged_actions WHERE status = $st ORDER BY created_at DESC"
        ).all({ $st: status });
        return jsonResponse(actions.map(a => ({
          ...a,
          parameters: JSON.parse(a.parameters_json),
          proposed_payload: JSON.parse(a.proposed_payload_json),
          execution_result: a.execution_result_json ? JSON.parse(a.execution_result_json) : null,
        })));
      }

      if (path.match(/^\/api\/staged-actions\/([^/]+)\/approve$/) && method === "POST") {
        const stagedId = path.split("/")[3];
        const res = HitlEngine.approveAction(stagedId, "human_operator");
        return jsonResponse(res);
      }

      if (path.match(/^\/api\/staged-actions\/([^/]+)\/reject$/) && method === "POST") {
        const stagedId = path.split("/")[3];
        const body = await req.json().catch(() => ({}));
        const res = HitlEngine.rejectAction(stagedId, "human_operator", body.note);
        return jsonResponse(res);
      }

      if (path.match(/^\/api\/staged-actions\/([^/]+)\/edit$/) && method === "POST") {
        const stagedId = path.split("/")[3];
        const body = await req.json();
        const res = HitlEngine.editAndApproveAction(stagedId, body.updated_payload, "human_operator");
        return jsonResponse(res);
      }

      // --------------------------------------------------------------
      // REST API: Universal Canvas (Deals, SKUs, Tasks, Shifts, Ledger)
      // --------------------------------------------------------------
      if (path === "/api/canvas" && method === "GET") {
        const category = url.searchParams.get("category");
        let results: any[] = [];

        if (!category || category === "all" || category === "deals" || category === "tasks" || category === "shifts" || category === "applications") {
          const catFilter = category === "deals" ? "deal" :
                            category === "tasks" ? "project_task" :
                            category === "shifts" ? "employee_shift" :
                            category === "applications" ? "candidate_application" : null;

          let sql = `
            SELECT p.*, e.name as entity_name, a.name as assignee_name
            FROM pipeline_states p
            LEFT JOIN entities e ON p.entity_id = e.id
            LEFT JOIN entities a ON p.assigned_to = a.id
          `;
          if (catFilter) sql += ` WHERE p.category = '${catFilter}'`;
          sql += ` ORDER BY p.updated_at DESC`;
          results = db.query(sql).all();
        } else if (category === "inventory") {
          results = db.query(`
            SELECT c.*, e.name as supplier_name 
            FROM catalog_items c
            LEFT JOIN entities e ON c.supplier_entity_id = e.id
            ORDER BY c.stock_qty ASC
          `).all();
        } else if (category === "invoices" || category === "ledger") {
          results = db.query(`
            SELECT l.*, e.name as entity_name
            FROM ledger_entries l
            LEFT JOIN entities e ON l.entity_id = e.id
            ORDER BY l.created_at DESC LIMIT 100
          `).all();
        } else if (category === "entities") {
          results = db.query("SELECT * FROM entities ORDER BY name ASC").all();
        }

        return jsonResponse(results);
      }

      if (path === "/api/canvas/item" && method === "POST") {
        const body = await req.json();
        const { category, title, stage, entity_id, assigned_to, amount, priority, due_date, payload } = body;
        const itemId = "pip_" + Math.random().toString(36).substring(2, 8);

        db.query(`
          INSERT INTO pipeline_states (id, category, title, stage, entity_id, assigned_to, amount, priority, due_date, payload_json)
          VALUES ($id, $category, $title, $stage, $entity_id, $amount, $priority, $due_date, $payload)
        `).run({
          $id: itemId,
          $category: category || "deal",
          $title: title,
          $stage: stage || "lead",
          $entity_id: entity_id || null,
          $assigned_to: assigned_to || null,
          $amount: amount || 0,
          $priority: priority || "medium",
          $due_date: due_date || null,
          $payload: JSON.stringify(payload || {}),
        });

        const created = db.query("SELECT * FROM pipeline_states WHERE id = $id").get({ $id: itemId });
        AuditEngine.record("human", "operator", "canvas_create_item", "pipeline_states", itemId, "INSERT", null, created);
        return jsonResponse(created, 201);
      }

      // --------------------------------------------------------------
      // REST API: 360-Degree Entity Slide-Over Profile
      // --------------------------------------------------------------
      if (path.match(/^\/api\/entities\/([^/]+)\/360$/) && method === "GET") {
        const entityId = path.split("/")[3];
        const profile = BusinessCoreService.getEntity360(entityId);
        return jsonResponse(profile);
      }

      // --------------------------------------------------------------
      // REST API: Content Blocks (Docs & Channels)
      // --------------------------------------------------------------
      if (path === "/api/content" && method === "GET") {
        const type = url.searchParams.get("type");
        const channel = url.searchParams.get("channel");
        let sql = `SELECT c.*, e.name as author_name FROM content_blocks c LEFT JOIN entities e ON c.author_entity_id = e.id WHERE 1=1`;
        const params: Record<string, any> = {};

        if (type) {
          sql += ` AND c.block_type = $type`;
          params.$type = type;
        }
        if (channel) {
          sql += ` AND c.channel_or_source = $channel`;
          params.$channel = channel;
        }
        sql += ` ORDER BY c.created_at ASC`;

        const blocks = db.query(sql).all(params);
        return jsonResponse(blocks);
      }

      if (path === "/api/content" && method === "POST") {
        const body = await req.json();
        const blockId = "blk_" + Math.random().toString(36).substring(2, 8);

        db.query(`
          INSERT INTO content_blocks (id, block_type, channel_or_source, title, markdown_body, author_entity_id, sync_status)
          VALUES ($id, $block_type, $channel, $title, $body, $author, 'synced')
        `).run({
          $id: blockId,
          $block_type: body.block_type || "chat_message",
          $channel: body.channel_or_source || "#general",
          $title: body.title || null,
          $body: body.markdown_body || "",
          $author: body.author_entity_id || null,
        });

        const created = db.query("SELECT * FROM content_blocks WHERE id = $id").get({ $id: blockId });
        return jsonResponse(created, 201);
      }

      // --------------------------------------------------------------
      // REST API: E-Commerce Unified Ingestion Webhook
      // --------------------------------------------------------------
      if (path === "/api/webhooks/order" && method === "POST") {
        const order = await req.json();
        // 1. Ensure entity exists
        let customer = db.query<Entity, { $email: string }>("SELECT * FROM entities WHERE email = $email").get({ $email: order.customer_email });
        if (!customer) {
          const custId = "ent_cust_" + Math.random().toString(36).substring(2, 8);
          db.query(`
            INSERT INTO entities (id, type, role, name, email, phone, status)
            VALUES ($id, 'person', 'customer', $name, $email, $phone, 'active')
          `).run({
            $id: custId,
            $name: order.customer_name || "Online Shopper",
            $email: order.customer_email,
            $phone: order.customer_phone || null,
          });
          customer = db.query<Entity, { $id: string }>("SELECT * FROM entities WHERE id = $id").get({ $id: custId })!;
        }

        // 2. Insert sales order pipeline state
        const orderId = "pip_ord_" + (order.order_number || Math.random().toString(36).substring(2, 8));
        db.query(`
          INSERT INTO pipeline_states (id, category, title, stage, entity_id, amount, payload_json)
          VALUES ($id, 'sales_order', $title, 'paid', $entity_id, $amount, $payload)
        `).run({
          $id: orderId,
          $title: `E-commerce Order #${order.order_number || "WEB"}`,
          $entity_id: customer.id,
          $amount: order.total_amount || 0,
          $payload: JSON.stringify(order),
        });

        // 3. Post to double-entry ledger (Debit Cash, Credit Revenue)
        const txGroup = "tx_grp_ecom_" + Math.random().toString(36).substring(2, 8);
        db.query(`
          INSERT INTO ledger_entries (id, transaction_group_id, type, account, category, amount, status, reference_id, entity_id, description)
          VALUES 
            ($id1, $tx, 'debit', 'cash', 'ecommerce', $amt, 'posted', $ref, $ent, $d1),
            ($id2, $tx, 'credit', 'revenue', 'ecommerce', $amt, 'posted', $ref, $ent, $d2)
        `).run({
          $id1: "led_" + Math.random().toString(36).substring(2, 8),
          $id2: "led_" + Math.random().toString(36).substring(2, 8),
          $tx: txGroup,
          $amt: order.total_amount || 0,
          $ref: orderId,
          $ent: customer.id,
          $d1: `E-commerce settlement for order #${order.order_number}`,
          $d2: `E-commerce revenue recognition`,
        });

        // 4. Update catalog item stock levels
        if (order.items && Array.isArray(order.items)) {
          for (const item of order.items) {
            db.query("UPDATE catalog_items SET stock_qty = MAX(0, stock_qty - $qty) WHERE sku = $sku").run({
              $qty: item.quantity || 1,
              $sku: item.sku,
            });
          }
        }

        AuditEngine.record("system", "ecom_webhook", "webhook_order_ingest", "pipeline_states", orderId, "INSERT", null, order);
        return jsonResponse({ success: true, order_id: orderId, transaction_group_id: txGroup });
      }

      // --------------------------------------------------------------
      // REST API: Audit Logs Stream & 1-Click Rollback
      // --------------------------------------------------------------
      if (path === "/api/audit-logs" && method === "GET") {
        const logs = db.query<AuditLog, []>(
          "SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 50"
        ).all();
        return jsonResponse(logs);
      }

      if (path.match(/^\/api\/audit-logs\/([^/]+)\/rollback$/) && method === "POST") {
        const auditId = path.split("/")[3];
        try {
          const res = AuditEngine.rollback(auditId, "human_operator");
          return jsonResponse(res);
        } catch (err: any) {
          return jsonResponse({ success: false, error: err.message }, 400);
        }
      }

      // --------------------------------------------------------------
      // REST API: Scoped Agent Tokens & HITL Configuration Hub
      // --------------------------------------------------------------
      if (path === "/api/tokens" && method === "GET") {
        const tokens = db.query("SELECT id, name, token, scopes, rate_limit_per_min, is_active, created_at FROM agent_tokens").all();
        const policies = db.query("SELECT * FROM hitl_policies").all();
        return jsonResponse({ tokens, policies });
      }

      if (path === "/api/tokens" && method === "POST") {
        const body = await req.json();
        const tokenId = "tok_" + Math.random().toString(36).substring(2, 8);
        const secret = "bos_agent_" + Math.random().toString(36).substring(2, 12);

        db.query(`
          INSERT INTO agent_tokens (id, name, token, scopes, rate_limit_per_min, is_active)
          VALUES ($id, $name, $token, $scopes, $rate, 1)
        `).run({
          $id: tokenId,
          $name: body.name || "Agent Key",
          $token: secret,
          $scopes: JSON.stringify(body.scopes || ["crm:*"]),
          $rate: body.rate_limit_per_min || 120,
        });

        return jsonResponse({ id: tokenId, name: body.name, token: secret, scopes: body.scopes }, 201);
      }

      if (path.match(/^\/api\/hitl-policies\/([^/]+)$/) && method === "POST") {
        const toolName = path.split("/")[3];
        const body = await req.json();
        db.query(`
          INSERT INTO hitl_policies (tool_name, requires_hitl, risk_level)
          VALUES ($tool, $req, $risk)
          ON CONFLICT(tool_name) DO UPDATE SET requires_hitl = $req, risk_level = $risk
        `).run({
          $tool: toolName,
          $req: body.requires_hitl ? 1 : 0,
          $risk: body.risk_level || "high",
        });

        return jsonResponse({ tool_name: toolName, requires_hitl: body.requires_hitl });
      }

      // --------------------------------------------------------------
      // Frontend Static Files (SPA)
      // --------------------------------------------------------------
      if (path === "/" || path === "/index.html") {
        const htmlPath = join(process.cwd(), "index.html");
        if (existsSync(htmlPath)) {
          return new Response(readFileSync(htmlPath, "utf-8"), {
            headers: { "Content-Type": "text/html; charset=utf-8" },
          });
        }
        return new Response("BOS index.html not found.", { status: 404 });
      }

      return new Response("Not Found", { status: 404 });
    },
  });

  console.log(`[BOS Server] HTTP & MCP Server online at http://localhost:${PORT}`);
}

// --------------------------------------------------------------------
// Server Entrypoint
// --------------------------------------------------------------------
if (process.argv.includes("--stdio")) {
  startMcpStdioServer();
} else {
  startHttpServer();
}
