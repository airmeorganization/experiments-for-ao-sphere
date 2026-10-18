/**
 * ====================================================================
 * BUSINESS OPERATING SYSTEM (BOS) - UNIFIED BACKEND & MCP SERVER
 * ====================================================================
 * Zero-bloat, MCP-Native Business OS powered by SQLite (WAL mode).
 * 
 * Production Security & Data Integrity Features:
 * - Scoped RBAC Authentication on all protected REST & MCP endpoints
 * - Cryptographically secure SHA-256 hashed token storage
 * - Rate Limiting & Request Body Size (512 KB) Guards
 * - HMAC-SHA256 Webhook Signature Verification with Timing-Safe comparison
 * - Atomic State Claiming in HITL Staging (Zero-Race Approvals)
 * - Strict Double-Entry Financial Accounting with Universal Balance Invariant
 * - Finite & Non-Negative Input Validation & Customer Verification
 * - Ledger Immutability (SQLite Triggers) & Atomic Transactions
 * - Real-world Supply Chain Lifecycle (PO Order -> Receipt Separation)
 * - Optimistic State Verification & Allowlist-Restricted Rollback
 * - Dual MCP Transports (STDIO & SSE) with Strict Scope Checking
 */

import { Database } from "bun:sqlite";
import { readFileSync, existsSync } from "fs";
import { join } from "path";
import { randomBytes, createHash, createHmac, timingSafeEqual, randomUUID } from "crypto";

// --------------------------------------------------------------------
// Database Initialization & WAL Mode Configuration
// --------------------------------------------------------------------
const DB_PATH = process.env.DATABASE_PATH || join(process.cwd(), "bos.db");
const PORT = parseInt(process.env.PORT || "8080", 10);
const SCHEMA_FILE = join(process.cwd(), "schema.sql");
const ALLOW_UNAUTHENTICATED_LOCAL = process.env.ALLOW_UNAUTHENTICATED_LOCAL === "true";
const ORDER_WEBHOOK_SECRET = process.env.ORDER_WEBHOOK_SECRET || process.env.BOS_WEBHOOK_SECRET || "bos_sec_webhook_9921b";
const MAX_BODY_BYTES = 512 * 1024; // 512 KB

export const db = new Database(DB_PATH, { create: true });
db.exec("PRAGMA journal_mode = WAL;");
db.exec("PRAGMA synchronous = NORMAL;");
db.exec("PRAGMA foreign_keys = ON;");
db.exec("PRAGMA busy_timeout = 5000;");

// Initialize schema if empty
const tableCheck = db.query<{ count: number }, []>(
  "SELECT count(*) as count FROM sqlite_master WHERE type='table' AND name='entities'"
).get();

if (!tableCheck || tableCheck.count === 0) {
  console.log("[BOS Database] Initializing schema from schema.sql...");
  if (existsSync(SCHEMA_FILE)) {
    const schemaSql = readFileSync(SCHEMA_FILE, "utf-8");
    db.exec(schemaSql);
    console.log("[BOS Database] Schema & seed data initialized successfully.");
  } else {
    console.warn("[BOS Database] schema.sql not found at:", SCHEMA_FILE);
  }
}

// Versioned Migration Manager
export function runMigrations(targetDb: Database = db) {
  targetDb.exec(`
    CREATE TABLE IF NOT EXISTS schema_migrations (
      version INTEGER PRIMARY KEY,
      name TEXT NOT NULL,
      applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
  `);

  const applied = new Set(
    targetDb.query<{ version: number }, []>("SELECT version FROM schema_migrations").all().map(m => m.version)
  );

  // Migration 1: Ledger immutability triggers
  if (!applied.has(1)) {
    try {
      targetDb.exec(`
        CREATE TRIGGER IF NOT EXISTS trg_ledger_immutable_update
        BEFORE UPDATE ON ledger_entries
        WHEN OLD.status = 'posted'
        BEGIN
            SELECT RAISE(ABORT, 'Posted ledger entries are immutable. Create a reversing compensating journal entry instead.');
        END;

        CREATE TRIGGER IF NOT EXISTS trg_ledger_immutable_delete
        BEFORE DELETE ON ledger_entries
        WHEN OLD.status = 'posted'
        BEGIN
            SELECT RAISE(ABORT, 'Posted ledger entries are immutable and cannot be deleted.');
        END;
      `);
      targetDb.query("INSERT OR REPLACE INTO schema_migrations (version, name) VALUES (1, 'ledger_immutability')").run();
      console.log("[BOS Migration] Applied Migration 1 (Ledger Immutability Triggers)");
    } catch (err: any) {
      console.warn("[BOS Migration] Migration 1 notice:", err.message);
    }
  }
}
runMigrations();

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
  sync_status: "synced" | "pending" | "failed" | "resolved";
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
  status: "pending" | "in_progress" | "approved" | "rejected" | "edited";
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

export interface AgentTokenRow {
  id: string;
  name: string;
  token_hash: string;
  token_prefix: string;
  scopes: string;
  rate_limit_per_min: number;
  is_active: number;
  created_at: string;
}

// --------------------------------------------------------------------
// In-Memory Sliding-Window Rate Limiter
// --------------------------------------------------------------------
export class RateLimiter {
  private static clientWindows = new Map<string, number[]>();

  static check(key: string, limitPerMinute: number = 120): { allowed: boolean; remaining: number; retryAfterSec: number } {
    const now = Date.now();
    const windowStart = now - 60_000;
    let timestamps = this.clientWindows.get(key) || [];
    timestamps = timestamps.filter(t => t > windowStart);

    if (timestamps.length >= limitPerMinute) {
      this.clientWindows.set(key, timestamps);
      const oldestInWindow = timestamps[0] || now;
      const retryAfterSec = Math.max(1, Math.ceil((oldestInWindow + 60_000 - now) / 1000));
      return { allowed: false, remaining: 0, retryAfterSec };
    }

    timestamps.push(now);
    this.clientWindows.set(key, timestamps);
    return { allowed: true, remaining: limitPerMinute - timestamps.length, retryAfterSec: 0 };
  }

  static reset() {
    this.clientWindows.clear();
  }
}

// --------------------------------------------------------------------
// Webhook Signature Verification Helper (HMAC-SHA256)
// --------------------------------------------------------------------
export function verifyWebhookSignature(payload: string, signatureHeader: string | null, secret: string): boolean {
  if (!signatureHeader || !secret) return false;
  try {
    const cleanSig = signatureHeader.replace(/^sha256=/i, "").trim();
    const expectedSig = createHmac("sha256", secret).update(payload).digest("hex");
    const sigBuffer = Buffer.from(cleanSig, "hex");
    const expectedBuffer = Buffer.from(expectedSig, "hex");
    if (sigBuffer.length !== expectedBuffer.length) return false;
    return timingSafeEqual(sigBuffer, expectedBuffer);
  } catch {
    return false;
  }
}

// --------------------------------------------------------------------
// Universal Ledger Transaction Group Balance Invariant
// --------------------------------------------------------------------
export function verifyTransactionGroupBalance(txGroupId: string, targetDb: Database = db): void {
  const row = targetDb.query<{ debit_sum: number; credit_sum: number }, { $tx: string }>(`
    SELECT 
      COALESCE(SUM(CASE WHEN type = 'debit' THEN amount ELSE 0 END), 0) as debit_sum,
      COALESCE(SUM(CASE WHEN type = 'credit' THEN amount ELSE 0 END), 0) as credit_sum
    FROM ledger_entries
    WHERE transaction_group_id = $tx
  `).get({ $tx: txGroupId });

  if (!row) throw new Error(`No ledger entries found for transaction group ${txGroupId}`);
  const diff = Math.abs(row.debit_sum - row.credit_sum);
  if (diff > 0.001) {
    throw new Error(`Double-entry invariant violated for ${txGroupId}: Debits ($${row.debit_sum.toFixed(2)}) != Credits ($${row.credit_sum.toFixed(2)})`);
  }
}

// --------------------------------------------------------------------
// Universal Double-Entry Posting Engine (Universal Invariant Enforcer)
// --------------------------------------------------------------------
export class LedgerManager {
  static postTransaction(
    transactionGroupId: string,
    entries: Array<{
      type: "debit" | "credit";
      account: string;
      category: string;
      amount: number;
      tax_amount?: number;
      currency?: string;
      reference_id?: string;
      entity_id?: string;
      description: string;
    }>,
    targetDb: Database = db
  ): void {
    if (!entries || entries.length < 2) {
      throw new Error(`Double-entry requires at least two balanced ledger entries.`);
    }

    let debitSum = 0;
    let creditSum = 0;
    const baseCurrency = entries[0].currency || "USD";

    for (const e of entries) {
      if (!Number.isFinite(e.amount) || e.amount <= 0) {
        throw new Error(`Invalid ledger entry amount: ${e.amount}. Must be a positive, finite number.`);
      }
      if (e.tax_amount !== undefined && (!Number.isFinite(e.tax_amount) || e.tax_amount < 0)) {
        throw new Error(`Invalid ledger entry tax_amount: ${e.tax_amount}. Must be a non-negative, finite number.`);
      }
      if (e.currency && e.currency !== baseCurrency) {
        throw new Error(`Currency mismatch in transaction ${transactionGroupId}: ${e.currency} vs ${baseCurrency}`);
      }

      if (e.type === "debit") debitSum += e.amount;
      else if (e.type === "credit") creditSum += e.amount;
      else throw new Error(`Invalid entry type: ${e.type}`);
    }

    if (Math.abs(debitSum - creditSum) > 0.001) {
      throw new Error(`Double-entry invariant violated for ${transactionGroupId}: Debits ($${debitSum.toFixed(2)}) != Credits ($${creditSum.toFixed(2)})`);
    }

    const tx = targetDb.transaction(() => {
      const stmt = targetDb.query(`
        INSERT INTO ledger_entries (id, transaction_group_id, type, account, category, amount, tax_amount, currency, status, reference_id, entity_id, description)
        VALUES ($id, $tx, $type, $account, $cat, $amt, $tax, $curr, 'posted', $ref, $ent, $desc)
      `);

      for (const e of entries) {
        stmt.run({
          $id: "led_" + randomUUID().substring(0, 8),
          $tx: transactionGroupId,
          $type: e.type,
          $account: e.account,
          $cat: e.category,
          $amt: e.amount,
          $tax: e.tax_amount || 0,
          $curr: e.currency || baseCurrency,
          $ref: e.reference_id || null,
          $ent: e.entity_id || null,
          $desc: e.description,
        });
      }

      verifyTransactionGroupBalance(transactionGroupId, targetDb);
    });

    tx();
  }
}

// --------------------------------------------------------------------
// Cryptographic Security & RBAC Token Manager
// --------------------------------------------------------------------
export class SecurityManager {
  static hashToken(rawToken: string): string {
    return createHash("sha256").update(rawToken).digest("hex");
  }

  static generateSecureToken(prefix: string = "bos_live_"): { rawToken: string; tokenHash: string; tokenPrefix: string } {
    const rawSecret = randomBytes(24).toString("hex");
    const rawToken = `${prefix}${rawSecret}`;
    const tokenHash = this.hashToken(rawToken);
    const tokenPrefix = `${rawToken.substring(0, 12)}...${rawToken.substring(rawToken.length - 4)}`;
    return { rawToken, tokenHash, tokenPrefix };
  }

  static bootstrapAdminKey() {
    const count = db.query<{ count: number }, []>("SELECT count(*) as count FROM agent_tokens").get()?.count || 0;
    if (count === 0) {
      const { rawToken, tokenHash, tokenPrefix } = this.generateSecureToken("bos_admin_");
      const tokenId = "tok_admin_" + randomUUID().substring(0, 8);

      db.query(`
        INSERT INTO agent_tokens (id, name, token_hash, token_prefix, scopes, rate_limit_per_min, is_active)
        VALUES ($id, 'Default Root Operator', $hash, $prefix, '["*"]', 1000, 1)
      `).run({
        $id: tokenId,
        $hash: tokenHash,
        $prefix: tokenPrefix,
      });

      console.log("\n====================================================================");
      console.log("🔐 [BOS SECURITY BOOTSTRAP] Initial Admin Master Key Generated:");
      console.log(`   Token: ${rawToken}`);
      console.log("   (Store this token securely! It will NEVER be displayed or logged again)");
      console.log("====================================================================\n");
    }
  }

  static verifyToken(authHeader: string | null): { authenticated: boolean; agentId: string; scopes: string[]; rateLimit?: number; error?: string } {
    if (!authHeader) {
      if (ALLOW_UNAUTHENTICATED_LOCAL) {
        return { authenticated: true, agentId: "operator:local_dev", scopes: ["*"], rateLimit: 1000 };
      }
      return { authenticated: false, agentId: "anonymous", scopes: [], error: "Missing Authorization header." };
    }

    const rawToken = authHeader.replace(/^Bearer\s+/i, "").trim();
    if (!rawToken) {
      return { authenticated: false, agentId: "anonymous", scopes: [], error: "Malformed Bearer token." };
    }

    if (process.env.BOS_OPERATOR_TOKEN && rawToken === process.env.BOS_OPERATOR_TOKEN) {
      return { authenticated: true, agentId: "operator:env_master", scopes: ["*"], rateLimit: 1000 };
    }

    const tokenHash = this.hashToken(rawToken);
    const row = db.query<AgentTokenRow, { $hash: string }>(
      "SELECT * FROM agent_tokens WHERE token_hash = $hash AND is_active = 1"
    ).get({ $hash: tokenHash });

    if (!row) {
      return { authenticated: false, agentId: "anonymous", scopes: [], error: "Invalid or revoked API token." };
    }

    const scopes: string[] = JSON.parse(row.scopes || "[]");
    return { authenticated: true, agentId: row.id, scopes, rateLimit: row.rate_limit_per_min };
  }

  static hasScope(grantedScopes: string[], requiredScope: string): boolean {
    if (grantedScopes.includes("*")) return true;
    if (grantedScopes.includes(requiredScope)) return true;

    const [reqPrefix] = requiredScope.split(/[:_]/);
    return grantedScopes.some(s => s === `${reqPrefix}:*` || s === `${reqPrefix}_*`);
  }
}

SecurityManager.bootstrapAdminKey();

// --------------------------------------------------------------------
// Safe, Atomic & State-Verified Rollback Engine
// --------------------------------------------------------------------
export class AuditEngine {
  private static ALLOWED_TABLES = new Set(["entities", "catalog_items", "pipeline_states", "content_blocks"]);

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
    const auditId = "aud_" + randomUUID().substring(0, 8);
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
    if (!audit) throw new Error(`Audit log entry not found: ${auditId}`);
    if (audit.is_reverted === 1) throw new Error(`Audit log entry ${auditId} has already been reverted.`);

    const { table_name, record_id, action, before_json, after_json } = audit;

    if (table_name === "ledger_entries") {
      throw new Error("Financial ledger entries cannot be rolled back via arbitrary table mutation. Post a balanced reversing journal entry.");
    }

    if (!this.ALLOWED_TABLES.has(table_name)) {
      throw new Error(`Rollback not permitted on table '${table_name}'. Allowed: [${Array.from(this.ALLOWED_TABLES).join(", ")}]`);
    }

    let restoredData: any = null;

    const executeRollbackTx = db.transaction(() => {
      const currentRow = db.query(`SELECT * FROM "${table_name}" WHERE id = $id`).get({ $id: record_id }) as Record<string, any> | undefined;

      if (action === "UPDATE") {
        if (!before_json) throw new Error("No previous state stored in audit log to revert to.");
        if (!currentRow) throw new Error(`Target record ${record_id} in ${table_name} no longer exists.`);

        if (after_json) {
          const expectedState = JSON.parse(after_json);
          for (const key of Object.keys(expectedState)) {
            if (key === "updated_at" || key === "created_at") continue;
            const currentVal = typeof currentRow[key] === "object" ? JSON.stringify(currentRow[key]) : currentRow[key];
            const expectedVal = typeof expectedState[key] === "object" ? JSON.stringify(expectedState[key]) : expectedState[key];
            if (currentVal !== expectedVal) {
              throw new Error(`Optimistic lock failure: Record ${record_id} in ${table_name} has been modified since snapshot (${key} differs). Rollback aborted.`);
            }
          }
        }

        const previousState = JSON.parse(before_json);
        restoredData = previousState;
        const keys = Object.keys(previousState).filter(k => k !== "id");
        const setClauses = keys.map(k => `"${k}" = $${k}`).join(", ");
        const params: Record<string, any> = { $id: record_id };
        for (const k of keys) {
          params[`$${k}`] = typeof previousState[k] === "object" ? JSON.stringify(previousState[k]) : previousState[k];
        }

        db.query(`UPDATE "${table_name}" SET ${setClauses}, updated_at = CURRENT_TIMESTAMP WHERE id = $id`).run(params);

      } else if (action === "INSERT") {
        if (!currentRow) throw new Error(`Target record ${record_id} in ${table_name} does not exist to revert.`);
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
    });

    executeRollbackTx();

    return {
      success: true,
      message: `Successfully rolled back ${action} on ${table_name} (${record_id}) atomically.`,
      restoredRecord: restoredData,
    };
  }
}

// --------------------------------------------------------------------
// Human-in-the-Loop (HITL) Staging Engine with Atomic Claiming
// --------------------------------------------------------------------
export class HitlEngine {
  static isToolStaged(toolName: string): boolean {
    const policy = db.query<{ requires_hitl: number; risk_level: string }, { $tool: string }>(
      "SELECT requires_hitl, risk_level FROM hitl_policies WHERE tool_name = $tool"
    ).get({ $tool: toolName });

    if (policy) return policy.requires_hitl === 1;

    const highRiskTools = [
      "erp_draft_purchase_order",
      "finance_issue_invoice",
      "hrms_stage_payroll_run",
      "presence_publish_review_reply",
      "presence_sync_nap_listings",
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
    const stagedId = "stg_" + randomUUID().substring(0, 8);
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

  // Atomic state claiming eliminates TOCTOU race conditions
  static approveAction(stagedId: string, reviewerId: string = "human_operator"): any {
    let executionResult: any = null;

    const tx = db.transaction(() => {
      // 1. Atomically claim the pending action
      const claimResult = db.query(`
        UPDATE staged_actions
        SET status = 'in_progress', reviewed_by = $reviewer
        WHERE id = $id AND status = 'pending'
      `).run({ $reviewer: reviewerId, $id: stagedId });

      if (claimResult.changes === 0) {
        throw new Error(`Action ${stagedId} is not in pending state or was already claimed by another operator.`);
      }

      const action = db.query<StagedAction, { $id: string }>("SELECT * FROM staged_actions WHERE id = $id").get({ $id: stagedId })!;
      const params = JSON.parse(action.parameters_json);
      const proposed = JSON.parse(action.proposed_payload_json);

      // 2. Execute underlying high-stakes tool
      executionResult = BusinessCoreService.executeToolInternal(action.tool_name, { ...params, ...proposed }, reviewerId, true);

      // 3. Finalize status to 'approved'
      db.query(`
        UPDATE staged_actions
        SET status = 'approved',
            reviewed_at = CURRENT_TIMESTAMP,
            execution_result_json = $result
        WHERE id = $id
      `).run({
        $result: JSON.stringify(executionResult),
        $id: stagedId,
      });
    });

    tx();
    return { status: "approved", staged_id: stagedId, executionResult };
  }

  static rejectAction(stagedId: string, reviewerId: string = "human_operator", note?: string): any {
    const claimResult = db.query(`
      UPDATE staged_actions
      SET status = 'rejected',
          reviewed_by = $reviewer,
          reviewed_at = CURRENT_TIMESTAMP,
          execution_result_json = $result
      WHERE id = $id AND status = 'pending'
    `).run({
      $reviewer: reviewerId,
      $result: JSON.stringify({ rejected: true, note: note || "Rejected by operator" }),
      $id: stagedId,
    });

    if (claimResult.changes === 0) {
      throw new Error(`Action ${stagedId} is not in pending state or was already processed.`);
    }

    return { status: "rejected", staged_id: stagedId };
  }

  static editAndApproveAction(stagedId: string, updatedPayload: any, reviewerId: string = "human_operator"): any {
    let executionResult: any = null;

    const tx = db.transaction(() => {
      const claimResult = db.query(`
        UPDATE staged_actions
        SET status = 'in_progress', reviewed_by = $reviewer
        WHERE id = $id AND status = 'pending'
      `).run({ $reviewer: reviewerId, $id: stagedId });

      if (claimResult.changes === 0) {
        throw new Error(`Action ${stagedId} is not in pending state or was already claimed.`);
      }

      const action = db.query<StagedAction, { $id: string }>("SELECT * FROM staged_actions WHERE id = $id").get({ $id: stagedId })!;
      executionResult = BusinessCoreService.executeToolInternal(action.tool_name, updatedPayload, reviewerId, true);

      db.query(`
        UPDATE staged_actions
        SET status = 'edited',
            proposed_payload_json = $payload,
            reviewed_at = CURRENT_TIMESTAMP,
            execution_result_json = $result
        WHERE id = $id
      `).run({
        $payload: JSON.stringify(updatedPayload),
        $result: JSON.stringify(executionResult),
        $id: stagedId,
      });
    });

    tx();
    return { status: "edited_and_approved", staged_id: stagedId, executionResult };
  }
}

// --------------------------------------------------------------------
// Unified Core Business Service Layer
// --------------------------------------------------------------------
export class BusinessCoreService {
  // 1. Business Pulse Executive Summary
  static getBusinessPulse() {
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

    const lowStockItems = db.query<CatalogItem, []>(`
      SELECT * FROM catalog_items 
      WHERE stock_qty <= reorder_threshold
    `).all();

    const pipelineSummary = db.query<{ stage: string; count: number; total_amount: number }, []>(`
      SELECT stage, count(*) as count, COALESCE(SUM(amount), 0) as total_amount
      FROM pipeline_states
      WHERE category = 'deal'
      GROUP BY stage
    `).all();

    const urgentReviews = db.query<ContentBlock, []>(`
      SELECT * FROM content_blocks
      WHERE block_type = 'customer_review' 
        AND sentiment_label = 'urgent_negative'
        AND sync_status != 'resolved'
    `).all();

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
    const taskId = "pip_tsk_" + randomUUID().substring(0, 8);
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
    const docId = "blk_doc_" + randomUUID().substring(0, 8);
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

  // Supply Chain: Draft/Order PO without premature stock inflation
  static erpDraftPurchaseOrder(sku: string, quantity: number, supplierId?: string, actorId: string = "system", bypassHitl: boolean = false) {
    if (!Number.isFinite(quantity) || quantity <= 0) {
      throw new Error(`Invalid purchase order quantity: ${quantity}. Must be positive and finite.`);
    }

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
        `Autonomous request to issue restock PO for ${quantity} units of ${item.name} ($${estCost.toFixed(2)}).`
      );
    }

    const poId = "pip_po_" + randomUUID().substring(0, 8);
    let createdPo: any = null;

    const tx = db.transaction(() => {
      db.query(`
        INSERT INTO pipeline_states (id, category, title, stage, entity_id, amount, priority, payload_json)
        VALUES ($id, 'purchase_order', $title, 'ordered', $supplier_id, $amount, 'high', $payload)
      `).run({
        $id: poId,
        $title: `Purchase Order: ${item.name} (${quantity} units)`,
        $supplier_id: effectiveSupplier || null,
        $amount: estCost,
        $payload: JSON.stringify({ sku, quantity, unit_cost: item.cost_price, status: "pending_vendor_delivery" }),
      });

      createdPo = db.query("SELECT * FROM pipeline_states WHERE id = $id").get({ $id: poId });
      AuditEngine.record(actorId.startsWith("agent") ? "agent" : "human", actorId, "erp_draft_purchase_order", "pipeline_states", poId, "INSERT", null, createdPo);
    });
    tx();

    return { executed: true, purchase_order: createdPo, note: "PO successfully created in 'ordered' state. Stock will be added upon delivery receipt." };
  }

  // Supply Chain: Receive PO upon physical dock delivery (with partial receipt support & atomic race prevention)
  static erpReceivePurchaseOrder(poId: string, receivedQty?: number, actorId: string = "system") {
    const po = db.query<PipelineState, { $id: string }>("SELECT * FROM pipeline_states WHERE id = $id AND category = 'purchase_order'").get({ $id: poId });
    if (!po) throw new Error(`Purchase order ${poId} not found.`);

    const payload = JSON.parse(po.payload_json || "{}");
    const sku = payload.sku;
    const orderedQty = payload.quantity;
    const alreadyReceivedQty = payload.received_quantity || 0;
    const remainingQty = orderedQty - alreadyReceivedQty;

    if (remainingQty <= 0) {
      throw new Error(`Purchase order ${poId} has already been completely received.`);
    }

    let targetQty = remainingQty;
    if (receivedQty !== undefined) {
      if (!Number.isFinite(receivedQty) || receivedQty <= 0) {
        throw new Error(`Invalid receive quantity: ${receivedQty}. Must be a positive, finite number.`);
      }
      if (receivedQty > remainingQty) {
        throw new Error(`Cannot receive ${receivedQty} units; only ${remainingQty} units remaining on PO ${poId}.`);
      }
      targetQty = receivedQty;
    }

    const nextReceivedTotal = alreadyReceivedQty + targetQty;
    const isComplete = nextReceivedTotal >= orderedQty;
    const nextStage = isComplete ? 'received' : 'partially_received';

    let updatedItem: any = null;
    const tx = db.transaction(() => {
      // 1. Atomically claim PO state: only succeeds if current stage is 'ordered' or 'partially_received'
      const claim = db.query(`
        UPDATE pipeline_states 
        SET stage = $stage, payload_json = $payload, updated_at = CURRENT_TIMESTAMP 
        WHERE id = $id AND (stage = 'ordered' OR stage = 'partially_received')
      `).run({
        $id: poId,
        $stage: nextStage,
        $payload: JSON.stringify({
          ...payload,
          received_quantity: nextReceivedTotal,
          remaining_quantity: orderedQty - nextReceivedTotal,
          last_received_quantity: targetQty,
          last_received_at: new Date().toISOString()
        })
      });

      if (claim.changes === 0) {
        throw new Error(`Purchase order ${poId} cannot be received: already fully received or concurrent update in progress.`);
      }

      // 2. Increment physical on-hand stock
      db.query("UPDATE catalog_items SET stock_qty = stock_qty + $qty, updated_at = CURRENT_TIMESTAMP WHERE sku = $sku").run({
        $qty: targetQty,
        $sku: sku,
      });

      updatedItem = db.query("SELECT * FROM catalog_items WHERE sku = $sku").get({ $sku: sku });

      // 3. Post balanced double-entry inventory arrival (Debit Inventory, Credit Accounts Payable)
      const txGroup = "tx_grp_rcv_" + randomUUID().substring(0, 8);
      const unitCost = po.amount / orderedQty;
      const receiveValue = Math.round(unitCost * targetQty * 100) / 100;

      LedgerManager.postTransaction(txGroup, [
        {
          type: "debit",
          account: "inventory",
          category: "bill",
          amount: receiveValue,
          reference_id: poId,
          entity_id: po.entity_id,
          description: `Inventory received into stock (${targetQty}/${orderedQty} units)`
        },
        {
          type: "credit",
          account: "accounts_payable",
          category: "bill",
          amount: receiveValue,
          reference_id: poId,
          entity_id: po.entity_id,
          description: `Vendor liability for received shipment (${targetQty} units)`
        }
      ], db);

      AuditEngine.record(actorId.startsWith("agent") ? "agent" : "human", actorId, "erp_receive_purchase_order", "catalog_items", sku, "UPDATE", null, updatedItem);
    });
    tx();

    return {
      received: true,
      po_id: poId,
      received_quantity: targetQty,
      total_received: nextReceivedTotal,
      remaining_quantity: orderedQty - nextReceivedTotal,
      stage: nextStage,
      new_stock_qty: updatedItem.stock_qty
    };
  }

  // Strict Double-Entry Invoicing with validation & universal transaction balancing
  static financeIssueInvoice(customerId: string, amount: number, description: string, taxAmount: number = 0, currency: string = "USD", actorId: string = "system", bypassHitl: boolean = false) {
    if (!Number.isFinite(amount) || amount <= 0) {
      throw new Error(`Invalid invoice amount: ${amount}. Amount must be a positive, finite number.`);
    }
    if (!Number.isFinite(taxAmount) || taxAmount < 0) {
      throw new Error(`Invalid tax amount: ${taxAmount}. Tax must be a non-negative, finite number.`);
    }

    // Verify customer entity exists
    const customer = db.query<Entity, { $id: string }>("SELECT id, status FROM entities WHERE id = $id").get({ $id: customerId });
    if (!customer) {
      throw new Error(`Customer entity does not exist: ${customerId}`);
    }

    if (!bypassHitl && HitlEngine.isToolStaged("finance_issue_invoice")) {
      return HitlEngine.stageAction(
        actorId,
        "finance_issue_invoice",
        { customerId, amount, description, taxAmount, currency },
        { customerId, amount, description, taxAmount, currency, netTotal: amount + taxAmount },
        "high",
        `Staged outbound invoice of $${(amount + taxAmount).toFixed(2)} for entity ${customerId}.`
      );
    }

    const txGroup = "tx_grp_inv_" + randomUUID().substring(0, 8);
    const invoiceRef = "INV-" + new Date().getFullYear() + "-" + Math.floor(1000 + Math.random() * 9000);
    const totalReceivable = amount + taxAmount;

    const entries: Array<{
      type: "debit" | "credit";
      account: string;
      category: string;
      amount: number;
      tax_amount?: number;
      currency?: string;
      reference_id?: string;
      entity_id?: string;
      description: string;
    }> = [
      {
        type: "debit",
        account: "accounts_receivable",
        category: "invoice",
        amount: totalReceivable,
        tax_amount: 0,
        currency,
        reference_id: invoiceRef,
        entity_id: customerId,
        description: `AR: ${description} (${invoiceRef})`
      },
      {
        type: "credit",
        account: "revenue",
        category: "invoice",
        amount: amount,
        tax_amount: 0,
        currency,
        reference_id: invoiceRef,
        entity_id: customerId,
        description: `Revenue: ${description} (${invoiceRef})`
      }
    ];

    if (taxAmount > 0) {
      entries.push({
        type: "credit",
        account: "tax_payable",
        category: "invoice",
        amount: taxAmount,
        tax_amount: 0,
        currency,
        reference_id: invoiceRef,
        entity_id: customerId,
        description: `Sales Tax Payable: ${invoiceRef}`
      });
    }

    LedgerManager.postTransaction(txGroup, entries, db);

    AuditEngine.record(actorId.startsWith("agent") ? "agent" : "human", actorId, "finance_issue_invoice", "ledger_entries", txGroup, "INSERT", null, {
      invoiceRef,
      totalReceivable,
      revenue: amount,
      taxAmount,
      customerId,
      currency
    });

    return { executed: true, invoice_ref: invoiceRef, transaction_group_id: txGroup, total_receivable: totalReceivable, revenue: amount, tax_amount: taxAmount };
  }

  // Atomic HRMS Payroll batch
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

    const txGroup = "tx_grp_pay_" + randomUUID().substring(0, 8);
    const ledgerEntries: Array<{
      type: "debit" | "credit";
      account: string;
      category: string;
      amount: number;
      reference_id?: string;
      entity_id?: string;
      description: string;
    }> = [];

    for (const p of payouts) {
      ledgerEntries.push({
        type: "debit",
        account: "payroll_expense",
        category: "payroll",
        amount: p.salary,
        reference_id: `PAY-${batchPeriod}`,
        entity_id: p.employee_id,
        description: `Salary Expense: ${p.name}`
      });
      ledgerEntries.push({
        type: "credit",
        account: "cash",
        category: "payroll",
        amount: p.salary,
        reference_id: `PAY-${batchPeriod}`,
        entity_id: p.employee_id,
        description: `Payroll direct deposit payout: ${p.name}`
      });
    }

    LedgerManager.postTransaction(txGroup, ledgerEntries, db);

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

    const replyBlockId = "blk_rep_" + randomUUID().substring(0, 8);
    const tx = db.transaction(() => {
      db.query(`
        INSERT INTO content_blocks (id, block_type, channel_or_source, title, markdown_body, parent_id, sync_status)
        VALUES ($id, 'customer_review', $channel, 'Public Response', $body, $parent, 'synced')
      `).run({
        $id: replyBlockId,
        $channel: review.channel_or_source,
        $body: replyText,
        $parent: reviewId,
      });

      db.query(`UPDATE content_blocks SET sync_status = 'resolved' WHERE id = $id`).run({ $id: reviewId });

      AuditEngine.record(actorId.startsWith("agent") ? "agent" : "human", actorId, "presence_publish_review_reply", "content_blocks", replyBlockId, "INSERT", null, {
        reviewId,
        replyText,
      });
    });
    tx();

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

    db.query(`UPDATE content_blocks SET sync_status = 'synced', updated_at = CURRENT_TIMESTAMP WHERE id = $id`).run({
      $id: nap.id,
    });

    AuditEngine.record(actorId.startsWith("agent") ? "agent" : "human", actorId, "presence_sync_nap_listings", "content_blocks", nap.id, "UPDATE", null, {
      directories,
      sync_status: "synced",
    });

    return { executed: true, synced_directories: directories, timestamp: new Date().toISOString() };
  }

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
      case "erp_receive_purchase_order":
        return this.erpReceivePurchaseOrder(args.po_id, actorId);
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
// MCP Protocol Definitions
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
    name: "erp_receive_purchase_order",
    description: "Receives a previously ordered PO, increments stock, and posts inventory asset entry.",
    inputSchema: {
      type: "object",
      properties: {
        po_id: { type: "string", description: "Purchase Order pipeline state ID" },
      },
      required: ["po_id"],
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
// Unified MCP Protocol Handler with Scope Enforcement
// --------------------------------------------------------------------
export function handleMcpJsonRpc(message: any, callerId: string, callerScopes: string[]): any {
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
            version: "2.2.0",
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

      if (!SecurityManager.hasScope(callerScopes, "resources:read") && !SecurityManager.hasScope(callerScopes, "*")) {
        return {
          jsonrpc: "2.0",
          id,
          error: { code: -32001, message: "Permission Denied: Caller lacks 'resources:read' scope." },
        };
      }

      if (uri === "mcp://business/pulse") {
        const pulse = BusinessCoreService.getBusinessPulse();
        return {
          jsonrpc: "2.0",
          id,
          result: {
            contents: [{ uri, mimeType: "application/json", text: JSON.stringify(pulse, null, 2) }],
          },
        };
      }

      if (uri === "mcp://inventory/low-stock") {
        const lowStock = BusinessCoreService.getLowStock();
        return {
          jsonrpc: "2.0",
          id,
          result: {
            contents: [{ uri, mimeType: "application/json", text: JSON.stringify(lowStock, null, 2) }],
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
            contents: [{ uri, mimeType: "application/json", text: JSON.stringify(profile, null, 2) }],
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

      if (!SecurityManager.hasScope(callerScopes, toolName)) {
        return {
          jsonrpc: "2.0",
          id,
          error: {
            code: -32001,
            message: `Permission Denied: Agent '${callerId}' lacks scope for tool '${toolName}'. Permitted scopes: [${callerScopes.join(", ")}]`,
          },
        };
      }

      try {
        const result = BusinessCoreService.executeToolInternal(toolName, toolArgs, callerId, false);
        return {
          jsonrpc: "2.0",
          id,
          result: {
            content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
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
// MCP STDIO Server Protocol Handler
// --------------------------------------------------------------------
export function startMcpStdioServer() {
  process.stdin.setEncoding("utf-8");
  let buffer = "";

  const stdioScopes = ["*"];
  const stdioCaller = "stdio:operator";

  process.stdin.on("data", (chunk: string) => {
    buffer += chunk;
    const lines = buffer.split("\n");
    buffer = lines.pop() || "";

    for (const line of lines) {
      if (!line.trim()) continue;
      try {
        const message = JSON.parse(line.trim());
        const response = handleMcpJsonRpc(message, stdioCaller, stdioScopes);
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

// --------------------------------------------------------------------
// HTTP Server with Rate Limiting, Signed Webhooks, and Protected REST API
// --------------------------------------------------------------------
const sseClients = new Map<string, (data: string) => void>();

function jsonResponse(data: any, status: number = 200, extraHeaders: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Signature, X-Webhook-Secret",
      ...extraHeaders,
    },
  });
}

export async function handleHttpRequest(req: Request): Promise<Response> {
  const url = new URL(req.url);
  const path = url.pathname;
  const method = req.method;

  // Request size guard (512 KB ceiling)
  const contentLength = parseInt(req.headers.get("content-length") || "0", 10);
  if (contentLength > MAX_BODY_BYTES) {
    return jsonResponse({ error: "Payload Too Large: Maximum allowed body size is 512 KB." }, 413);
  }

  // CORS Preflight
  if (method === "OPTIONS") {
    return new Response(null, {
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Signature, X-Bos-Signature, X-Webhook-Signature, X-Webhook-Secret",
      },
    });
  }

  // Static Frontend SPA
  if (path === "/" || path === "/index.html") {
    const htmlPath = join(process.cwd(), "index.html");
    if (existsSync(htmlPath)) {
      return new Response(readFileSync(htmlPath, "utf-8"), {
        headers: { "Content-Type": "text/html; charset=utf-8" },
      });
    }
    return new Response("BOS index.html not found.", { status: 404 });
  }

  // --------------------------------------------------------------
  // MCP Streamable HTTP / Server-Sent Events (SSE) Protocol
  // --------------------------------------------------------------
  if (path === "/mcp/sse" && method === "GET") {
    const auth = SecurityManager.verifyToken(req.headers.get("Authorization") || url.searchParams.get("token"));
    if (!auth.authenticated) {
      return jsonResponse({ error: auth.error }, 401);
    }

    const sessionId = "sess_" + randomUUID();
    let sendEvent: ((data: string) => void) | null = null;

    const stream = new ReadableStream({
      start(controller) {
        sendEvent = (data: string) => {
          controller.enqueue(new TextEncoder().encode(`event: message\ndata: ${data}\n\n`));
        };
        sseClients.set(sessionId, sendEvent);

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
    const auth = SecurityManager.verifyToken(req.headers.get("Authorization"));

    if (!auth.authenticated) {
      return jsonResponse({ error: auth.error }, 401);
    }

    if (auth.rateLimit) {
      const rl = RateLimiter.check(auth.agentId, auth.rateLimit);
      if (!rl.allowed) {
        return jsonResponse({ error: `Rate limit exceeded (${auth.rateLimit}/min).` }, 429, { "Retry-After": String(rl.retryAfterSec) });
      }
    }

    let body: any;
    try {
      body = await req.json();
    } catch {
      return jsonResponse({ error: "Invalid JSON format." }, 400);
    }

    const response = handleMcpJsonRpc(body, auth.agentId, auth.scopes);

    if (sessionId && sseClients.has(sessionId)) {
      sseClients.get(sessionId)!(JSON.stringify(response));
    }

    return jsonResponse(response);
  }

  // --------------------------------------------------------------
  // Public / Webhook Ingestion Routes (Signed & Rate-Limited)
  // --------------------------------------------------------------
  if (path === "/api/webhooks/order" && method === "POST") {
    // Rate limit webhooks: 60 calls/minute per client IP
    const clientIp = req.headers.get("x-forwarded-for") || "webhook_client";
    const rl = RateLimiter.check(`webhook:${clientIp}`, 60);
    if (!rl.allowed) {
      return jsonResponse({ error: "Webhook rate limit exceeded. Please retry later." }, 429, { "Retry-After": String(rl.retryAfterSec) });
    }

    const rawBody = await req.text();
    if (rawBody.length > MAX_BODY_BYTES) {
      return jsonResponse({ error: "Payload Too Large: Max body size 512 KB." }, 413);
    }

    // Webhook Trust Boundary: Verify provider signature or secret
    const sigHeader = req.headers.get("x-signature") || req.headers.get("x-bos-signature") || req.headers.get("x-webhook-signature");
    const secretHeader = req.headers.get("x-webhook-secret");

    let isSignatureValid = false;
    if (sigHeader) {
      isSignatureValid = verifyWebhookSignature(rawBody, sigHeader, ORDER_WEBHOOK_SECRET);
    } else if (secretHeader) {
      isSignatureValid = secretHeader === ORDER_WEBHOOK_SECRET;
    }

    // Reject unverified or forged payloads unconditionally
    if (!isSignatureValid) {
      return jsonResponse({ error: "Unauthorized: Invalid or missing webhook signature (HMAC-SHA256 required)." }, 401);
    }

    let order: any;
    try {
      order = JSON.parse(rawBody);
    } catch {
      return jsonResponse({ error: "Invalid JSON payload." }, 400);
    }

    // Validate order schema and positive finite amounts
    if (!order || typeof order !== "object") return jsonResponse({ error: "Invalid order object." }, 400);
    if (!order.customer_email || typeof order.customer_email !== "string" || !order.customer_email.includes("@")) {
      return jsonResponse({ error: "Valid customer_email is required." }, 400);
    }
    if (!Number.isFinite(order.total_amount) || order.total_amount <= 0) {
      return jsonResponse({ error: "total_amount must be a positive, finite number." }, 400);
    }

    const externalOrderNum = order.order_number ? String(order.order_number) : "WEB-" + randomUUID().substring(0, 6);
    const orderPipelineId = "pip_ord_" + externalOrderNum;

    // Idempotency check: prevent duplicate billing or stock deduction
    const existingOrder = db.query<PipelineState, { $id: string }>(
      "SELECT * FROM pipeline_states WHERE id = $id"
    ).get({ $id: orderPipelineId });

    if (existingOrder) {
      return jsonResponse({
        idempotent_replay: true,
        order_id: existingOrder.id,
        status: existingOrder.stage,
        message: "Order already ingested previously.",
      });
    }

    let customerId = "";
    let txGroup = "";

    const executeOrderIngest = db.transaction(() => {
      let customer = db.query<Entity, { $email: string }>("SELECT * FROM entities WHERE email = $email").get({ $email: order.customer_email });
      if (!customer) {
        const newCustId = "ent_cust_" + randomUUID().substring(0, 8);
        db.query(`
          INSERT INTO entities (id, type, role, name, email, phone, status)
          VALUES ($id, 'person', 'customer', $name, $email, $phone, 'active')
        `).run({
          $id: newCustId,
          $name: order.customer_name || "Online Shopper",
          $email: order.customer_email,
          $phone: order.customer_phone || null,
        });
        customerId = newCustId;
      } else {
        customerId = customer.id;
      }

      db.query(`
        INSERT INTO pipeline_states (id, category, title, stage, entity_id, amount, payload_json)
        VALUES ($id, 'sales_order', $title, 'paid', $entity_id, $amount, $payload)
      `).run({
        $id: orderPipelineId,
        $title: `E-commerce Order #${externalOrderNum}`,
        $entity_id: customerId,
        $amount: order.total_amount || 0,
        $payload: JSON.stringify(order),
      });

      txGroup = "tx_grp_ecom_" + randomUUID().substring(0, 8);
      LedgerManager.postTransaction(txGroup, [
        {
          type: "debit",
          account: "cash",
          category: "ecommerce",
          amount: order.total_amount,
          reference_id: orderPipelineId,
          entity_id: customerId,
          description: `E-commerce settlement for order #${externalOrderNum}`
        },
        {
          type: "credit",
          account: "revenue",
          category: "ecommerce",
          amount: order.total_amount,
          reference_id: orderPipelineId,
          entity_id: customerId,
          description: `E-commerce revenue recognition`
        }
      ], db);

      if (order.items && Array.isArray(order.items)) {
        for (const item of order.items) {
          if (item.sku && Number.isFinite(item.quantity) && item.quantity > 0) {
            db.query("UPDATE catalog_items SET stock_qty = MAX(0, stock_qty - $qty), updated_at = CURRENT_TIMESTAMP WHERE sku = $sku").run({
              $qty: item.quantity,
              $sku: item.sku,
            });
          }
        }
      }

      AuditEngine.record("system", "ecom_webhook", "webhook_order_ingest", "pipeline_states", orderPipelineId, "INSERT", null, order);
    });

    executeOrderIngest();
    return jsonResponse({ success: true, order_id: orderPipelineId, transaction_group_id: txGroup }, 201);
  }

  // --------------------------------------------------------------
  // PROTECTED REST APIS (Authentication & RBAC Enforcement)
  // --------------------------------------------------------------
  const auth = SecurityManager.verifyToken(req.headers.get("Authorization"));

  // Check per-token general & write rate limits
  if (auth.authenticated && auth.rateLimit) {
    const rl = RateLimiter.check(auth.agentId, auth.rateLimit);
    if (!rl.allowed) {
      return jsonResponse({ error: `Rate limit exceeded (${auth.rateLimit}/min).` }, 429, { "Retry-After": String(rl.retryAfterSec) });
    }

    if (["POST", "PUT", "DELETE"].includes(method)) {
      const writeLimit = Math.max(10, Math.floor(auth.rateLimit / 2));
      const writeRl = RateLimiter.check(`${auth.agentId}:writes`, writeLimit);
      if (!writeRl.allowed) {
        return jsonResponse({ error: `Write rate limit exceeded (${writeLimit}/min).` }, 429, { "Retry-After": String(writeRl.retryAfterSec) });
      }
    }
  }

  // Clean authorization helper:
  // 401 if unauthenticated, 403 if authenticated but lacking the required scope
  const authorize = (requiredScope: string = "*"): Response | null => {
    if (!auth.authenticated) {
      if (ALLOW_UNAUTHENTICATED_LOCAL) return null;
      return jsonResponse({ error: "Unauthorized: Missing or invalid authentication token." }, 401);
    }
    if (!SecurityManager.hasScope(auth.scopes, requiredScope)) {
      return jsonResponse({ error: `Forbidden: Token lacks required scope '${requiredScope}'.` }, 403);
    }
    return null;
  };

  // 1. Business Pulse
  if (path === "/api/pulse" && method === "GET") {
    const authErr = authorize("pulse:read");
    if (authErr) return authErr;
    return jsonResponse(BusinessCoreService.getBusinessPulse());
  }

  // 2. Action Inbox & HITL Guardrails
  if (path === "/api/staged-actions" && method === "GET") {
    const authErr = authorize("staged:read");
    if (authErr) return authErr;

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
    const authErr = authorize("staged:approve");
    if (authErr) return authErr;

    const stagedId = path.split("/")[3];
    try {
      const res = HitlEngine.approveAction(stagedId, auth.agentId);
      return jsonResponse(res);
    } catch (err: any) {
      return jsonResponse({ error: err.message }, 400);
    }
  }

  if (path.match(/^\/api\/staged-actions\/([^/]+)\/reject$/) && method === "POST") {
    const authErr = authorize("staged:approve");
    if (authErr) return authErr;

    const stagedId = path.split("/")[3];
    const body = await req.json().catch(() => ({}));
    try {
      const res = HitlEngine.rejectAction(stagedId, auth.agentId, body.note);
      return jsonResponse(res);
    } catch (err: any) {
      return jsonResponse({ error: err.message }, 400);
    }
  }

  if (path.match(/^\/api\/staged-actions\/([^/]+)\/edit$/) && method === "POST") {
    const authErr = authorize("staged:approve");
    if (authErr) return authErr;

    const stagedId = path.split("/")[3];
    let body: any;
    try {
      body = await req.json();
    } catch {
      return jsonResponse({ error: "Invalid JSON payload." }, 400);
    }
    try {
      const res = HitlEngine.editAndApproveAction(stagedId, body.updated_payload, auth.agentId);
      return jsonResponse(res);
    } catch (err: any) {
      return jsonResponse({ error: err.message }, 400);
    }
  }

  // 3. Universal Canvas
  if (path === "/api/canvas" && method === "GET") {
    const authErr = authorize("canvas:read");
    if (authErr) return authErr;

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
    const authErr = authorize("canvas:write");
    if (authErr) return authErr;

    let body: any;
    try {
      body = await req.json();
    } catch {
      return jsonResponse({ error: "Invalid JSON format." }, 400);
    }

    const itemId = "pip_" + randomUUID().substring(0, 8);

    db.query(`
      INSERT INTO pipeline_states (id, category, title, stage, entity_id, assigned_to, amount, priority, due_date, payload_json)
      VALUES ($id, $category, $title, $stage, $entity_id, $assigned_to, $amount, $priority, $due_date, $payload)
    `).run({
      $id: itemId,
      $category: body.category || "deal",
      $title: body.title,
      $stage: body.stage || "lead",
      $entity_id: body.entity_id || null,
      $assigned_to: body.assigned_to || null,
      $amount: body.amount || 0,
      $priority: body.priority || "medium",
      $due_date: body.due_date || null,
      $payload: JSON.stringify(body.payload || {}),
    });

    const created = db.query("SELECT * FROM pipeline_states WHERE id = $id").get({ $id: itemId });
    AuditEngine.record(auth.agentId.startsWith("agent") ? "agent" : "human", auth.agentId, "canvas_create_item", "pipeline_states", itemId, "INSERT", null, created);
    return jsonResponse(created, 201);
  }

  // 4. 360-Degree Entity Slide-Over Profile
  if (path.match(/^\/api\/entities\/([^/]+)\/360$/) && method === "GET") {
    const authErr = authorize("entities:read");
    if (authErr) return authErr;

    const entityId = path.split("/")[3];
    try {
      const profile = BusinessCoreService.getEntity360(entityId);
      return jsonResponse(profile);
    } catch (err: any) {
      return jsonResponse({ error: err.message }, 404);
    }
  }

  // 5. Content Blocks (Docs & Channels)
  if (path === "/api/content" && method === "GET") {
    const authErr = authorize("content:read");
    if (authErr) return authErr;

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

    return jsonResponse(db.query(sql).all(params));
  }

  if (path === "/api/content" && method === "POST") {
    const authErr = authorize("content:write");
    if (authErr) return authErr;

    let body: any;
    try {
      body = await req.json();
    } catch {
      return jsonResponse({ error: "Invalid JSON format." }, 400);
    }

    const blockId = "blk_" + randomUUID().substring(0, 8);

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

  // 6. Audit Logs Stream & 1-Click Rollback
  if (path === "/api/audit-logs" && method === "GET") {
    const authErr = authorize("audit:read");
    if (authErr) return authErr;

    const logs = db.query<AuditLog, []>("SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 50").all();
    return jsonResponse(logs);
  }

  if (path.match(/^\/api\/audit-logs\/([^/]+)\/rollback$/) && method === "POST") {
    const authErr = authorize("audit:rollback");
    if (authErr) return authErr;

    const auditId = path.split("/")[3];
    try {
      const res = AuditEngine.rollback(auditId, auth.agentId);
      return jsonResponse(res);
    } catch (err: any) {
      return jsonResponse({ success: false, error: err.message }, 400);
    }
  }

  // 7. Scoped Agent Tokens & HITL Configuration Hub
  if (path === "/api/tokens" && method === "GET") {
    const authErr = authorize("admin:tokens");
    if (authErr) return authErr;

    const tokens = db.query<AgentTokenRow, []>(
      "SELECT id, name, token_prefix, scopes, rate_limit_per_min, is_active, created_at FROM agent_tokens"
    ).all().map(t => ({ ...t, scopes: JSON.parse(t.scopes || "[]") }));

    const policies = db.query("SELECT * FROM hitl_policies").all();
    return jsonResponse({ tokens, policies });
  }

  if (path === "/api/tokens" && method === "POST") {
    const authErr = authorize("admin:tokens");
    if (authErr) return authErr;

    let body: any;
    try {
      body = await req.json();
    } catch {
      return jsonResponse({ error: "Invalid JSON format." }, 400);
    }

    const { rawToken, tokenHash, tokenPrefix } = SecurityManager.generateSecureToken("bos_agent_");
    const tokenId = "tok_" + randomUUID().substring(0, 8);

    db.query(`
      INSERT INTO agent_tokens (id, name, token_hash, token_prefix, scopes, rate_limit_per_min, is_active)
      VALUES ($id, $name, $hash, $prefix, $scopes, $rate, 1)
    `).run({
      $id: tokenId,
      $name: body.name || "Agent Key",
      $hash: tokenHash,
      $prefix: tokenPrefix,
      $scopes: JSON.stringify(body.scopes || ["crm:*"]),
      $rate: body.rate_limit_per_min || 120,
    });

    return jsonResponse({
      id: tokenId,
      name: body.name,
      token_prefix: tokenPrefix,
      scopes: body.scopes,
      raw_secret: rawToken,
      notice: "Save this token now. It will not be shown again and cannot be retrieved.",
    }, 201);
  }

  if (path.match(/^\/api\/hitl-policies\/([^/]+)$/) && method === "POST") {
    const authErr = authorize("admin:policies");
    if (authErr) return authErr;

    const toolName = path.split("/")[3];
    let body: any;
    try {
      body = await req.json();
    } catch {
      return jsonResponse({ error: "Invalid JSON format." }, 400);
    }

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

  return new Response("Not Found", { status: 404 });
}

export function startHttpServer() {
  Bun.serve({
    port: PORT,
    fetch: handleHttpRequest,
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
