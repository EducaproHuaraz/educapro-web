export async function onRequestGet(context) {

  try {

    const cookieHeader =
      context.request.headers.get("Cookie") || "";

    const token = obtenerCookie(
      cookieHeader,
      "educapro_admin"
    );

    if (!token) {
      return respuestaNoAutorizado();
    }

    const partes = token.split(".");

    if (partes.length !== 2) {
      return respuestaNoAutorizado();
    }

    const payloadBase64 = partes[0];
    const firmaRecibida = partes[1];

    const sessionSecret =
      context.env.ADMIN_SESSION_SECRET;

    if (!sessionSecret) {
      return new Response(
        JSON.stringify({
          success: false,
          message: "Configuración de sesión incompleta."
        }),
        {
          status: 500,
          headers: {
            "Content-Type": "application/json"
          }
        }
      );
    }

    const firmaEsperada = await firmar(
      payloadBase64,
      sessionSecret
    );

    if (firmaRecibida !== firmaEsperada) {
      return respuestaNoAutorizado();
    }

    const payload = JSON.parse(
      base64urlDecode(payloadBase64)
    );

    if (!payload.exp) {
      return respuestaNoAutorizado();
    }

    if (
      Math.floor(Date.now() / 1000) >=
      Number(payload.exp)
    ) {
      return respuestaNoAutorizado();
    }

    return new Response(
      JSON.stringify({
        success: true,
        usuario: payload.usuario
      }),
      {
        status: 200,
        headers: {
          "Content-Type": "application/json"
        }
      }
    );

  } catch (error) {

    return respuestaNoAutorizado();

  }

}


function obtenerCookie(cookieHeader, nombre) {

  const cookies = cookieHeader
    .split(";")
    .map(cookie => cookie.trim());

  for (const cookie of cookies) {

    const separador = cookie.indexOf("=");

    if (separador === -1) continue;

    const clave =
      cookie.substring(0, separador);

    const valor =
      cookie.substring(separador + 1);

    if (clave === nombre) {
      return valor;
    }

  }

  return null;
}


async function firmar(texto, secreto) {

  const encoder = new TextEncoder();

  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secreto),
    {
      name: "HMAC",
      hash: "SHA-256"
    },
    false,
    ["sign"]
  );

  const firma = await crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(texto)
  );

  return base64urlEncodeBytes(
    new Uint8Array(firma)
  );
}


function base64urlDecode(texto) {

  let base64 = texto
    .replace(/-/g, "+")
    .replace(/_/g, "/");

  while (base64.length % 4) {
    base64 += "=";
  }

  const binary = atob(base64);

  const bytes = Uint8Array.from(
    binary,
    caracter => caracter.charCodeAt(0)
  );

  return new TextDecoder().decode(bytes);
}


function base64urlEncodeBytes(bytes) {

  let binary = "";

  bytes.forEach(byte => {
    binary += String.fromCharCode(byte);
  });

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}


function respuestaNoAutorizado() {

  return new Response(
    JSON.stringify({
      success: false,
      message: "Sesión no válida."
    }),
    {
      status: 401,
      headers: {
        "Content-Type": "application/json"
      }
    }
  );

}