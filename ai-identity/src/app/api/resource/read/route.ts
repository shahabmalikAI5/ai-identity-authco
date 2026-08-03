import { verifyTokenScope } from "@/lib/introspect"

export async function GET(request: Request) {
  const authHeader = request.headers.get("authorization")
  if (!authHeader?.startsWith("Bearer ")) {
    return Response.json({ error: "missing_token", detail: "Provide an Authorization: Bearer <token> header" }, { status: 401 })
  }

  const token = authHeader.slice(7)
  const result = await verifyTokenScope(token, "notes.read")

  if (!result.authorized) {
    if (result.status === 401) {
      return Response.json({ error: "invalid_token", detail: "Token is missing, expired, or revoked" }, { status: 401 })
    }
    return Response.json({ error: "insufficient_scope", detail: "Token lacks the notes.read scope", scopes: result.scopes }, { status: 403 })
  }

  return Response.json({ message: "read access granted", scopes: result.scopes })
}
