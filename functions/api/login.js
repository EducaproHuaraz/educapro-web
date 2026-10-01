export async function onRequestPost(context) {

  try {

    const data = await context.request.json();

    const usuario = String(data.usuario || "").trim();
    const password = String(data.password || "");

    const usuarioCorrecto = context.env.ADMIN_USUARIO;
    const passwordCorrecta = context.env.ADMIN_PASSWORD;
    const sessionSecret = context.env.ADMIN_SESSION_SECRET;

    if (!usuarioCorrecto || !passwordCorrecta || !sessionSecret) {
      return new Response(
        JSON.stringify({
          success: false,
          message: "Configuración de seguridad incompleta."
        }),
        {
          status: 500,
          headers: {
            "Content-Type": "application/json"
          }
        }
      );
    }

    if (
      usuario !== usuarioCorrecto ||
      password !== passwordCorrecta
    ) {

      return new Response(
        JSON.stringify({
          success: false,
          message: "Usuario o contraseña incorrectos."
        }),
        {
          status: 401,
          headers: {
            "Content-Type": "application/json"
          }
        }
      );

    }

    const expiracion =
      Math.floor(Date.now() / 1000) + (8 * 60 * 60);

    const payload = {
      usuario: usuario,
      exp: expiracion
    };

    const payloadBase64 = base64urlEncode(
      JSON.stringify(payload)
    );

    const firma = await firmar(
      payloadBase64,
      sessionSecret
    );

    const token = payloadBase64 + "." + firma;

    const headers = new Headers();

    headers.set(
      "Content-Type",
      "application/json"
    );

    headers.append(
      "Set-Cookie",
      [
        `educapro_admin=${token}`,
        "Path=/",
        "HttpOnly",
        "Secure",
        "SameSite=Lax",
        "Max-Age=28800"
      ].join("; ")
    );

    return new Response(
      JSON.stringify({
        success: true,
        message: "Inicio de sesión correcto."
      }),
      {
        status: 200,
        headers: headers
      }
    );

  } catch (error) {

    return new Response(
      JSON.stringify({
        success: false,
        message: "Solicitud inválida."
      }),
      {
        status: 400,
        headers: {
          "Content-Type": "application/json"
        }
      }
    );

  }

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


function base64urlEncode(texto) {

  const bytes = new TextEncoder().encode(texto);

  return base64urlEncodeBytes(bytes);
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