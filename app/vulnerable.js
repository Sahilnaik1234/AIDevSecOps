// app/vulnerable.js
//
// ⚠️  INTENTIONALLY VULNERABLE — FOR TESTING ONLY
// Triggers:
//   SAST (Semgrep) → eval injection, XSS, prototype pollution,
//                    hardcoded secrets, insecure regex, path traversal
//   Dependabot     → old packages in package.json

const express = require("express");
const fs = require("fs");
const exec = require("child_process").exec;
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ---------------------------------------------------------------
// 🔑 GITLEAKS TRIGGER — Hardcoded credentials (generic patterns)
// ---------------------------------------------------------------
// These trigger Gitleaks generic password/key rules in CI
const DB_PASSWORD = "password=Hardcoded$ecret!99";
const PAYMENT_KEY = "api_key=paymentServiceKey_TestValue_9876";
const INTERNAL_TOKEN = "token=internalSvcToken_DoNotShare_XyZ123";

// ---------------------------------------------------------------
// 💉 SEMGREP SAST TRIGGERS
// ---------------------------------------------------------------

// [VULN-1] eval() with user input — Remote Code Execution
app.get("/eval", (req, res) => {
  const code = req.query.code;
  // semgrep: javascript.lang.security.audit.unsafe-eval
  const result = eval(code);
  res.send(String(result));
});

// [VULN-2] Command Injection via child_process.exec
app.get("/run", (req, res) => {
  const cmd = req.query.cmd;
  // semgrep: javascript.lang.security.detect-child-process
  exec(cmd, (err, stdout) => {
    res.send(stdout || err?.message);
  });
});

// [VULN-3] Path Traversal — reading arbitrary files
app.get("/file", (req, res) => {
  const filename = req.query.name;
  // No path sanitization — can escape web root
  // semgrep: javascript.lang.security.audit.path-traversal
  const content = fs.readFileSync("/var/www/" + filename, "utf8");
  res.send(content);
});

// [VULN-4] XSS — user input injected into HTML response
app.get("/greet", (req, res) => {
  const name = req.query.name || "World";
  // semgrep: javascript.lang.security.audit.xss
  res.send(`<h1>Hello, ${name}!</h1>`);
});

// [VULN-5] Prototype Pollution — merging user-controlled object
function merge(target, source) {
  for (let key in source) {
    // semgrep: javascript.lang.security.audit.prototype-pollution
    target[key] = source[key];
  }
  return target;
}

app.post("/merge", (req, res) => {
  const result = merge({}, req.body);
  res.json(result);
});

// [VULN-6] SQL Injection via string concatenation
app.get("/user", (req, res) => {
  const username = req.query.name;
  const db = require("better-sqlite3")("app.db");
  // semgrep: javascript.lang.security.audit.sqli
  const rows = db.prepare(`SELECT * FROM users WHERE name = '${username}'`).all();
  res.json(rows);
});

// [VULN-7] Insecure Regex — ReDoS vulnerability
app.get("/validate", (req, res) => {
  const input = req.query.email;
  // Catastrophic backtracking regex (ReDoS)
  // semgrep: javascript.lang.security.audit.regex-injection
  const emailRegex = /^([a-zA-Z0-9]+)*@([a-zA-Z0-9]+\.)+[a-zA-Z]{2,}$/;
  res.json({ valid: emailRegex.test(input) });
});

// [VULN-8] Hardcoded JWT secret — easily guessable
const jwt = require("jsonwebtoken");
app.post("/login", (req, res) => {
  const { user } = req.body;
  // semgrep: javascript.jsonwebtoken.security.jwt-hardcoded-secret
  const token = jwt.sign({ user }, "supersecretkey123");
  res.json({ token });
});

app.listen(3000, () => console.log("Server running on port 3000"));
