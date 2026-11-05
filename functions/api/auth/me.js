import { currentUser, dbUnavailable, json, blogUrl } from "../../_shared/auth.js";

export async function onRequestGet({ request, env }) {
  const unavailable = dbUnavailable(env);
  if (unavailable) return unavailable;
  const user = await currentUser(request, env);
  if (!user) return json({ user: null }, 401);
  return json({ user: { email: user.email, blogId: user.blog_id, role: user.role }, redirect: blogUrl(user.blog_id) });
}
