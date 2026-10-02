export async function onRequestPost(context) {

  const resultado = {
    ADMIN_USUARIO: !!context.env.ADMIN_USUARIO,
    ADMIN_PASSWORD: !!context.env.ADMIN_PASSWORD,
    ADMIN_SESSION_SECRET: !!context.env.ADMIN_SESSION_SECRET
  };

  return new Response(
    JSON.stringify(resultado),
    {
      status: 200,
      headers: {
        "Content-Type": "application/json"
      }
    }
  );
}