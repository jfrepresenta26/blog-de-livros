import { currentUser, dbUnavailable, json, validEmail, validPassword, hashPassword, randomHex, sameOrigin } from "../../_shared/auth.js";

export async function onRequestGet({ request, env }) {
  const unavailable = dbUnavailable(env);
  if (unavailable) return unavailable;
  const user = await currentUser(request, env);
  if (!user || user.role !== "owner") return json({ error: "Acesso restrito à conta administradora." }, 403);
  const { results = [] } = await env.DB.prepare("SELECT id,email,blog_id,role,created_at FROM users ORDER BY created_at").all();
  return json({ accounts: results });
}

export async function onRequestPost({ request, env }) {
  const unavailable = dbUnavailable(env);
  if (unavailable) return unavailable;
  if (!sameOrigin(request)) return json({ error: "Origem da solicitação inválida." }, 403);
  const user = await currentUser(request, env);
  if (!user || user.role !== "owner") return json({ error: "Acesso restrito à conta administradora." }, 403);
  let body;
  try { body = await request.json(); } catch { return json({ error: "Confira os dados informados." }, 400); }
  const email = String(body?.email || "").trim().toLowerCase();
  const password = body?.password;
  const blogId = body?.blogId;
  if (!validEmail(email) || !validPassword(password) || !["gabriel", "debora"].includes(blogId)) {
    return json({ error: "Informe e-mail válido, senha com pelo menos 12 caracteres e um dos blogs." }, 400);
  }
  const { salt, hash } = await hashPassword(password);
  const now = Math.floor(Date.now() / 1000);
  try {
    await env.DB.prepare("INSERT INTO users(id,email,password_salt,password_hash,blog_id,role,created_at) VALUES(?,?,?,?,?,'member',?)")
      .bind(randomHex(16), email, salt, hash, blogId, now).run();
  } catch (error) {
    if (String(error).toLowerCase().includes("unique")) return json({ error: "Já existe uma conta com esse e-mail." }, 409);
    throw error;
  }
  return json({ ok: true }, 201);
}
