
function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store"
    }
  });
}

function base64UrlToBytes(value) {
  const base64 = value
    .replace(/-/g, "+")
    .replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - base64.length % 4) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

async function verificarSesion(request, env) {
  const cookie = request.headers.get("Cookie") || "";
  const token = cookie
    .split(";")
    .map((item) => item.trim())
    .find((item) => item.startsWith("educapro_admin="))
    ?.slice("educapro_admin=".length);

  if (!token || !env.ADMIN_SESSION_SECRET) return false;

  const partes = token.split(".");
  if (partes.length !== 2) return false;

  const [payload, firma] = partes;

  try {
    const clave = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(env.ADMIN_SESSION_SECRET),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );

    const firmaBytes = new Uint8Array(
      await crypto.subtle.sign(
        "HMAC",
        clave,
        new TextEncoder().encode(payload)
      )
    );

    const firmaEsperada = btoa(
      String.fromCharCode(...firmaBytes)
    )
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");

    if (firma !== firmaEsperada) return false;

    const datos = JSON.parse(
      new TextDecoder().decode(base64UrlToBytes(payload))
    );

    if (!datos.exp || Date.now() >= Number(datos.exp) * 1000) {
      return false;
    }

    return true;
  } catch {
    return false;
  }
}

export async function onRequest(context) {
  const { request, env } = context;

  if (request.method !== "POST") {
    return json({ ok: false, mensaje: "Método no permitido." }, 405);
  }

  if (!(await verificarSesion(request, env))) {
    return json({ ok: false, mensaje: "Sesión no válida." }, 401);
  }

  if (!env.FINANZAS_API_URL || !env.FINANZAS_API_SECRET) {
    return json({
      ok: false,
      mensaje: "Falta configurar la conexión financiera."
    }, 500);
  }

  let solicitud;

  try {
    solicitud = await request.json();
  } catch {
    return json({ ok: false, mensaje: "Solicitud JSON inválida." }, 400);
  }

  if (
    solicitud?.accion !== "registrarPago" ||
    !solicitud?.datos ||
    typeof solicitud.datos !== "object"
  ) {
    return json({ ok: false, mensaje: "Datos de solicitud inválidos." }, 400);
  }

  try {
    const respuestaGoogle = await fetch(env.FINANZAS_API_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        secreto: env.FINANZAS_API_SECRET,
        accion: "registrarPago",
        datos: solicitud.datos
      })
    });

    const resultado = await respuestaGoogle.json();

    if (!resultado.ok) {
      return json({
        ok: false,
        mensaje: resultado.mensaje || "No se pudo registrar el pago."
      }, 400);
    }

    return json(resultado);
  } catch {
    return json({
      ok: false,
      mensaje: "No se pudo conectar con Google Apps Script."
    }, 502);
  }
}
