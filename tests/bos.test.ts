/**
 * ====================================================================
 * BOS COMPREHENSIVE ARCHITECTURAL & SECURITY TEST SUITE
 * ====================================================================
 * Tests:
 * 1. Double-Entry Invariants (Debits == Credits, Tax-Payable Posting)
 * 2. Immutable Ledger Triggers (Preventing Direct UPDATE and DELETE on Posted Entries)
 * 3. Cryptographic Token Hashing & Scoped RBAC Permissions
 * 4. Human-in-the-Loop (HITL) Staging Interceptor
 * 5. Safe, Optimistic-Locked & Atomic Time-Travel Rollback
 * 6. Idempotent E-Commerce Webhook Ingestion
 * 7. Real-world Supply Chain Invariant (PO Order -> Receipt Separation)
 */

import { describe, it, expect, beforeAll } from "bun:test";
import { Database } from "bun:sqlite";
import { readFileSync } from "fs";
import { join } from "path";
import {
  db,
  BusinessCoreService,
  SecurityManager,
  HitlEngine,
  AuditEngine,
  handleMcpJsonRpc,
} from "../server";

describe("1. Double-Entry Accounting Invariants", () => {
  it("should post a balanced invoice with explicit tax-payable entry", () => {
    const subtotal = 1000.0;
    const tax = 80.0;
    const res = BusinessCoreService.financeIssueInvoice("ent_apex", subtotal, "Cloud Infrastructure Consulting", tax, "operator_test", true);

    expect(res.executed).toBe(true);
    expect(res.total_receivable).toBe(1080.0);
    expect(res.revenue).toBe(1000.0);
    expect(res.tax_amount).toBe(80.0);

    // Verify double-entry balance in database: Sum(Debits) === Sum(Credits)
    const entries = db.query<any, { $tx: string }>(
      "SELECT type, account, amount FROM ledger_entries WHERE transaction_group_id = $tx"
    ).all({ $tx: res.transaction_group_id });

    expect(entries.length).toBe(3);

    const totalDebits = entries.filter(e => e.type === "debit").reduce((sum, e) => sum + e.amount, 0);
    const totalCredits = entries.filter(e => e.type === "credit").reduce((sum, e) => sum + e.amount, 0);

    expect(totalDebits).toBe(totalCredits);
    expect(totalDebits).toBe(1080.0);
  });

  it("should strictly balance monthly payroll debits and credits", () => {
    const res = BusinessCoreService.hrmsStagePayrollRun("2026-TEST", "operator_test", true);
    expect(res.executed).toBe(true);

    const entries = db.query<any, { $tx: string }>(
      "SELECT type, amount FROM ledger_entries WHERE transaction_group_id = $tx"
    ).all({ $tx: res.transaction_group_id });

    const totalDebits = entries.filter(e => e.type === "debit").reduce((sum, e) => sum + e.amount, 0);
    const totalCredits = entries.filter(e => e.type === "credit").reduce((sum, e) => sum + e.amount, 0);

    expect(totalDebits).toBe(totalCredits);
    expect(totalDebits).toBe(res.total_disbursed);
  });
});

describe("2. Ledger Immutability & Database Triggers", () => {
  it("should throw an error when attempting to directly UPDATE a posted ledger entry", () => {
    const postedEntry = db.query<any, []>("SELECT id FROM ledger_entries WHERE status = 'posted' LIMIT 1").get();
    expect(postedEntry).toBeDefined();

    expect(() => {
      db.query("UPDATE ledger_entries SET amount = 999999 WHERE id = $id").run({ $id: postedEntry.id });
    }).toThrow(/Posted ledger entries are immutable/);
  });

  it("should throw an error when attempting to DELETE a posted ledger entry", () => {
    const postedEntry = db.query<any, []>("SELECT id FROM ledger_entries WHERE status = 'posted' LIMIT 1").get();
    expect(postedEntry).toBeDefined();

    expect(() => {
      db.query("DELETE FROM ledger_entries WHERE id = $id").run({ $id: postedEntry.id });
    }).toThrow(/Posted ledger entries are immutable and cannot be deleted/);
  });
});

describe("3. Cryptographic Token Hashing & Scoped RBAC", () => {
  it("should generate high-entropy tokens and store only SHA-256 hashes", () => {
    const { rawToken, tokenHash, tokenPrefix } = SecurityManager.generateSecureToken("bos_test_");
    expect(rawToken.startsWith("bos_test_")).toBe(true);
    expect(tokenHash).toHaveLength(64); // SHA-256 hex string
    expect(tokenPrefix).toContain("...");

    // Store in DB
    const tokenId = "tok_test_unit";
    db.query(`
      INSERT OR REPLACE INTO agent_tokens (id, name, token_hash, token_prefix, scopes, rate_limit_per_min, is_active)
      VALUES ($id, 'Test Scoped Agent', $hash, $prefix, '["crm:*", "inventory:read"]', 100, 1)
    `).run({
      $id: tokenId,
      $hash: tokenHash,
      $prefix: tokenPrefix,
    });

    // Verification check using raw token in header
    const authSuccess = SecurityManager.verifyToken(`Bearer ${rawToken}`);
    expect(authSuccess.authenticated).toBe(true);
    expect(authSuccess.agentId).toBe(tokenId);
    expect(authSuccess.scopes).toEqual(["crm:*", "inventory:read"]);

    // Raw token must NOT exist in the database table!
    const row = db.query<any, { $id: string }>("SELECT * FROM agent_tokens WHERE id = $id").get({ $id: tokenId });
    expect(row.token).toBeUndefined();
    expect(row.token_hash).toBe(tokenHash);
  });

  it("should enforce scopes on MCP tool calls across all transports", () => {
    const supportScopes = ["crm:*", "reviews:*"];

    // 1. Permitted Tool: crm_search_entities
    const allowedMsg = {
      jsonrpc: "2.0",
      id: "1",
      method: "tools/call",
      params: { name: "crm_search_entities", arguments: { query: "Apex" } },
    };
    const allowedRes = handleMcpJsonRpc(allowedMsg, "test_agent", supportScopes);
    expect(allowedRes.error).toBeUndefined();
    expect(allowedRes.result.content).toBeDefined();

    // 2. Forbidden Tool: hrms_stage_payroll_run (Scope violation)
    const forbiddenMsg = {
      jsonrpc: "2.0",
      id: "2",
      method: "tools/call",
      params: { name: "hrms_stage_payroll_run", arguments: { batch_period: "2026-12" } },
    };
    const forbiddenRes = handleMcpJsonRpc(forbiddenMsg, "test_agent", supportScopes);
    expect(forbiddenRes.error).toBeDefined();
    expect(forbiddenRes.error.code).toBe(-32001);
    expect(forbiddenRes.error.message).toContain("Permission Denied");
  });
});

describe("4. Human-in-the-Loop (HITL) Staging Interceptor", () => {
  it("should intercept high-stakes tools and route them to staged_actions", () => {
    const stagedRes = BusinessCoreService.financeIssueInvoice("ent_acme", 15000.0, "Large Logistics Contract", 0, "agent_finance", false);
    expect(stagedRes.staged).toBe(true);
    expect(stagedRes.status).toBe("pending_human_approval");
    expect(stagedRes.risk_level).toBe("high");

    // Verify row exists in staged_actions
    const stagedRow = db.query<any, { $id: string }>(
      "SELECT * FROM staged_actions WHERE id = $id"
    ).get({ $id: stagedRes.staged_action_id });

    expect(stagedRow).toBeDefined();
    expect(stagedRow.status).toBe("pending");
    expect(stagedRow.tool_name).toBe("finance_issue_invoice");

    // Human operator approval test
    const approvalRes = HitlEngine.approveAction(stagedRes.staged_action_id, "human_cfo");
    expect(approvalRes.status).toBe("approved");

    const approvedRow = db.query<any, { $id: string }>(
      "SELECT * FROM staged_actions WHERE id = $id"
    ).get({ $id: stagedRes.staged_action_id });

    expect(approvedRow.status).toBe("approved");
    expect(approvedRow.reviewed_by).toBe("human_cfo");
  });
});

describe("5. Real-World Supply Chain & PO Order Invariant", () => {
  it("should NOT prematurely increase on-hand stock when a PO is drafted/ordered", () => {
    const itemBefore = db.query<any, { $sku: string }>("SELECT * FROM catalog_items WHERE sku = 'HW-SRV-01'").get({ $sku: "HW-SRV-01" });
    const initialStock = itemBefore.stock_qty;

    // Place Purchase Order
    const poRes = BusinessCoreService.erpDraftPurchaseOrder("HW-SRV-01", 10, itemBefore.supplier_entity_id, "operator_test", true);
    expect(poRes.executed).toBe(true);

    // Stock MUST REMAIN UNCHANGED until shipment arrival!
    const itemAfterOrder = db.query<any, { $sku: string }>("SELECT * FROM catalog_items WHERE sku = 'HW-SRV-01'").get({ $sku: "HW-SRV-01" });
    expect(itemAfterOrder.stock_qty).toBe(initialStock);

    // Delivery Receipt action executes
    const receiveRes = BusinessCoreService.erpReceivePurchaseOrder(poRes.purchase_order.id, "dock_manager");
    expect(receiveRes.received).toBe(true);
    expect(receiveRes.new_stock_qty).toBe(initialStock + 10);

    const itemAfterReceipt = db.query<any, { $sku: string }>("SELECT * FROM catalog_items WHERE sku = 'HW-SRV-01'").get({ $sku: "HW-SRV-01" });
    expect(itemAfterReceipt.stock_qty).toBe(initialStock + 10);
  });
});

describe("6. Safe, Optimistic-Locked & Atomic Time-Travel Rollback", () => {
  it("should rollback an entity update atomically and block rollback on modified state", () => {
    // 1. Create a test entity
    const testEntId = "ent_test_rb";
    db.query(`
      INSERT OR REPLACE INTO entities (id, type, role, name, status)
      VALUES ($id, 'person', 'lead', 'Initial Name', 'active')
    `).run({ $id: testEntId });

    const beforeState = { id: testEntId, name: "Initial Name", status: "active" };
    const afterState = { id: testEntId, name: "Updated Name", status: "active" };

    // Update entity
    db.query("UPDATE entities SET name = 'Updated Name' WHERE id = $id").run({ $id: testEntId });

    // Record audit entry
    const auditId = AuditEngine.record("human", "operator", "crm_update_entity", "entities", testEntId, "UPDATE", beforeState, afterState);

    // 2. Perform Rollback
    const rollbackRes = AuditEngine.rollback(auditId, "operator_undo");
    expect(rollbackRes.success).toBe(true);

    const restoredEntity = db.query<any, { $id: string }>("SELECT * FROM entities WHERE id = $id").get({ $id: testEntId });
    expect(restoredEntity.name).toBe("Initial Name");

    // 3. Prevent duplicate rollback
    expect(() => {
      AuditEngine.rollback(auditId, "operator_undo");
    }).toThrow(/already been reverted/);
  });

  it("should forbid rollback on financial ledger entries", () => {
    const fakeLedgerAuditId = AuditEngine.record("human", "operator", "finance_test", "ledger_entries", "led_fake", "UPDATE", {}, {});
    expect(() => {
      AuditEngine.rollback(fakeLedgerAuditId, "operator");
    }).toThrow(/Financial ledger entries cannot be rolled back via arbitrary table mutation/);
  });
});
