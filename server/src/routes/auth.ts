import crypto from "node:crypto";
import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import { db, type UserRow } from "../lib/db.js";
import {
  consumeV8Handoff,
  createAuthToken,
  clearSessionCookie,
  deleteAuthToken,
  hashPassword,
  issueV8Handoff,
  newId,
  requireUser,
  setSessionCookie,
  userFromRequest,
  verifyPassword,
} from "../lib/auth.js";

const credentialsSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8).max(200),
});

const registerSchema = credentialsSchema.extend({
  name: z.string().min(1).max(100),
});

function publicUser(user: UserRow) {
  return { id: user.id, email: user.email, name: user.name };
}

function secretMatches(presented: string): boolean {
  const secret = process.env.TRIBUTARY_V8_SSO_SECRET ?? "";
  const a = Buffer.from(presented);
  const b = Buffer.from(secret);
  return secret.length > 0 && a.length === b.length && crypto.timingSafeEqual(a, b);
}

function ensureV8User(email: string, name: string): UserRow {
  const normalized = email.toLowerCase();
  const existing = db.prepare("SELECT * FROM users WHERE email = ?").get(normalized) as UserRow | undefined;
  if (existing) {
    if (name && existing.name !== name) {
      db.prepare("UPDATE users SET name = ? WHERE id = ?").run(name, existing.id);
      existing.name = name;
    }
    return existing;
  }
  const user: UserRow = {
    id: newId(),
    email: normalized,
    name: name || normalized,
    password_hash: hashPassword(crypto.randomBytes(32).toString("hex")),
    created_at: Date.now(),
  };
  db.prepare(
    "INSERT INTO users (id, email, name, password_hash, created_at) VALUES (?, ?, ?, ?, ?)"
  ).run(user.id, user.email, user.name, user.password_hash, user.created_at);
  const membership = db.prepare("SELECT 1 FROM studio_members WHERE user_id = ?").get(user.id);
  if (!membership) {
    const studioId = newId();
    const now = Date.now();
    db.prepare("INSERT INTO studios (id, user_id, name, created_at) VALUES (?, ?, ?, ?)").run(
      studioId, user.id, "BDCbox", now
    );
    db.prepare(
      "INSERT INTO studio_members (studio_id, user_id, role, created_at) VALUES (?, ?, 'owner', ?)"
    ).run(studioId, user.id, now);
  }
  return user;
}

async function userFromV8Password(email: string, password: string): Promise<UserRow | null> {
  const url = process.env.TRIBUTARY_V8_LOGIN_URL;
  if (!url) return null;
  let res: Response;
  try {
    res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
  } catch {
    return null;
  }
  if (!res.ok) return null;
  const body = (await res.json().catch(() => ({}))) as { user?: { email?: string; name?: string } };
  const user = ensureV8User(body.user?.email || email, body.user?.name || email);
  const hash = hashPassword(password);
  db.prepare("UPDATE users SET password_hash = ? WHERE id = ?").run(hash, user.id);
  user.password_hash = hash;
  return user;
}

function finishLogin(reply: FastifyReply, user: UserRow, req: FastifyRequest) {
  const token = createAuthToken(user.id);
  const secure = process.env.NODE_ENV === "production" || req.headers["x-forwarded-proto"] === "https";
  setSessionCookie(reply, token, { secure });
  return { user: publicUser(user), token };
}

// Simple in-memory rate limit for credential endpoints (per-IP, sliding minute).
const attempts = new Map<string, number[]>();
function rateLimited(ip: string, max = 10): boolean {
  const now = Date.now();
  const recent = (attempts.get(ip) ?? []).filter((t) => now - t < 60_000);
  recent.push(now);
  attempts.set(ip, recent);
  if (attempts.size > 10_000) attempts.clear(); // bound memory under abuse
  return recent.length > max;
}

export function registerAuthRoutes(app: FastifyInstance): void {
  app.post("/api/auth/register", async (req, reply) => {
    if (rateLimited(req.ip)) return reply.code(429).send({ error: "Too many attempts — try again in a minute" });
    const parsed = registerSchema.safeParse(req.body);
    if (!parsed.success) {
      return reply.code(400).send({ error: "Invalid email, name, or password (min 8 chars)" });
    }
    const { email, name, password } = parsed.data;
    const existing = db.prepare("SELECT id FROM users WHERE email = ?").get(email.toLowerCase());
    if (existing) return reply.code(409).send({ error: "An account with that email already exists" });

    const user: UserRow = {
      id: newId(),
      email: email.toLowerCase(),
      name,
      password_hash: hashPassword(password),
      created_at: Date.now(),
    };
    db.prepare(
      "INSERT INTO users (id, email, name, password_hash, created_at) VALUES (?, ?, ?, ?, ?)"
    ).run(user.id, user.email, user.name, user.password_hash, user.created_at);

    setSessionCookie(reply, createAuthToken(user.id));
    return { user: publicUser(user) };
  });

  app.post("/api/auth/login", async (req, reply) => {
    if (rateLimited(req.ip)) return reply.code(429).send({ error: "Too many attempts — try again in a minute" });
    const parsed = credentialsSchema.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: "Invalid credentials" });
    const local = db
      .prepare("SELECT * FROM users WHERE email = ?")
      .get(parsed.data.email.toLowerCase()) as UserRow | undefined;
    const user =
      local && verifyPassword(parsed.data.password, local.password_hash)
        ? local
        : await userFromV8Password(parsed.data.email, parsed.data.password);
    if (!user) return reply.code(401).send({ error: "Incorrect email or password" });
    // token in the body lets CLI/agents authenticate with Authorization: Bearer
    return finishLogin(reply, user, req);
  });

  // V8 already authenticated this person. Mint a one-time code; the browser
  // trades it for the session cookie so the embedded studio does not ask again.
  app.post("/api/auth/v8-session", async (req, reply) => {
    const presented = String(req.headers["x-v8-sso-secret"] ?? "");
    if (!secretMatches(presented)) return reply.code(401).send({ error: "Not authorized" });
    const parsed = z.object({ email: z.string().email(), name: z.string().min(1).max(100) }).safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: "Email and name are required" });
    const user = ensureV8User(parsed.data.email, parsed.data.name);
    return { code: issueV8Handoff(user.id) };
  });

  app.get("/api/auth/v8-handoff", async (req, reply) => {
    const code = String((req.query as { code?: string }).code ?? "");
    const token = consumeV8Handoff(code);
    if (!token) return reply.code(401).send({ error: "This sign-in link has expired. Reload the studio." });
    const secure = process.env.NODE_ENV === "production" || req.headers["x-forwarded-proto"] === "https";
    setSessionCookie(reply, token, { secure });
    return reply.redirect("/");
  });

  app.post("/api/auth/logout", async (req, reply) => {
    deleteAuthToken(req);
    clearSessionCookie(reply);
    return { ok: true };
  });

  app.get("/api/auth/me", async (req) => {
    const user = userFromRequest(req);
    return { user: user ? publicUser(user) : null };
  });

  // convenience: 401 helper used by client bootstrapping
  app.get("/api/auth/require", async (req, reply) => {
    const user = requireUser(req, reply);
    if (!user) return;
    return { user: publicUser(user) };
  });
}
