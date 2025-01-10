const context = {
  issuer: "https://luau.org",
};

type IdTokenClaims = {
  /**
   * Obrigatório. Tempo de expiração do token.
   */
  exp: number;

  /**
   * Obrigatório. Tempo de emissão do token.
   */
  iat: number;

  /**
   * Obrigatório. Identificador único do usuário.
   */
  sub: string;

  /**
   * Obrigatório. Identificador do cliente.
   */
  aud: string | string[];

  /**
   * Obrigatório. URL de emissão do token (issuer).
   */
  iss: string;

  /**
   * Opcional. Tempo de autenticação (não deve ser mais antigo que max_age).
   */
  auth_time?: number;

  /**
   * Opcional. Dados de nonce, para vincular o token de ID a uma autenticação específica.
   */
  nonce?: string;

  /**
   * Opcional. Informações sobre a autenticação realizada.
   */
  acr?: string;

  /**
   * Opcional. Lista de métodos de autenticação realizados.
   */
  amr?: string[];

  atHash?: string;

  /**
   * Opcional. Nome de usuário, pode ser o e-mail.
   */
  email?: string;

  /**
   * Opcional. Indica se o endereço de e-mail foi verificado.
   */
  email_verified?: boolean;

  /**
   * Opcional. Nome completo do usuário.
   */
  name?: string;

  /**
   * Opcional. Sobrenome do usuário.
   */
  family_name?: string;

  /**
   * Opcional. Nome dado do usuário.
   */
  given_name?: string;

  /**
   * Opcional. Imagem de perfil do usuário.
   */
  picture?: string;

  /**
   * Opcional. URL para o perfil do usuário.
   */
  profile?: string;

  /**
   * Opcional. Gênero do usuário.
   */
  gender?: string;

  /**
   * Opcional. Zona de tempo preferida do usuário.
   */
  preferred_username?: string;

  /**
   * Opcional. Localização (time zone) do usuário.
   */
  zoneinfo?: string;

  /**
   * Opcional. Data de nascimento do usuário.
   */
  birthdate?: string;

  /**
   * Opcional. Endereço do usuário.
   */
  address?: {
    street_address?: string;
    locality?: string;
    region?: string;
    postal_code?: string;
    country?: string;
  };
};

type AuthenticationRequest = {
  /**
   * Obrigatório. URL do servidor de autorização.
   */
  issuer: string;

  /**
   * Obrigatório. Nome do cliente (client_id).
   */
  clientId: string;

  /**
   * Obrigatório. URI de redirecionamento para onde o usuário será enviado após a autenticação.
   */
  redirectUri: string;

  /**
   * Obrigatório. Escopos solicitados (scope).
   */
  scope: string | string[];

  /**
   * Obrigatório. Tipo de resposta (response_type). Normalmente 'code' para fluxo de autorização ou 'token' para fluxo implícito.
   */
  responseType:
    | "code"
    | "id_token"
    | "id_token token"
    | "code id_token"
    | "code token"
    | "code id_token token";

  /**
   * Opcional. Estado para manter o estado entre as solicitações de autenticação e redirecionamentos (state).
   */
  state?: string;

  /**
   * Opcional. Dica para o servidor de autorização sobre o tipo de token de ID esperado (response_mode).
   */
  responseMode?: "query" | "fragment" | "form_post";

  /**
   * Opcional. Pode ser usado para controlar o comportamento de login (prompt).
   */
  prompt?: "login" | "select_account" | "none" | "consent" | "create";

  /**
   * Opcional. Solicita um valor específico para o nonce.
   */
  nonce?: string;

  /**
   * Opcional. Dica de login para solicitar autenticação específica de um usuário.
   */
  loginHint?: string;

  /**
   * Opcional. Indica que o cliente não quer que o servidor de autorização solicite autenticação baseada em senha.
   */
  maxAge?: number;

  /**
   * Opcional. Força o servidor de autorização a incluir certos claims no token de ID.
   */
  idTokenHint?: string;

  /**
   * Opcional. Contém uma lista de claims solicitados além dos claims padrão.
   */
  claims?: {
    id_token?: Record<string, any>;
    userinfo?: Record<string, any>;
    // Adicionar outros tipos de tokens se necessário, como 'userinfo' ou 'token'
  };

  /**
   * Opcional. Pode ser usado para solicitar que o servidor de autorização apresente a página de autenticação em um determinado idioma.
   */
  uiLocales?: string;

  /**
   * Opcional. Uma solicitação de autenticação assinada por JWT conforme a especificação OIDC.
   */
  request?: string;

  /**
   * Opcional. Um URI que referencia uma solicitação de autenticação assinada por JWT.
   */
  requestUri?: string;
};

class Client {
  public id: string;

  public validateRedirectUri(redirectUri: string) {
    return true;
  }

  public validateRequestUri(requestUri: string) {
    return true;
  }

  public isRequestSupported() {
    return true;
  }
}

function getClientByID(clientId: string) {
  return new Client();
}

async function auth(request: AuthenticationRequest) {
  const client = getClientByID(request.clientId);
  if (!client) {
    throw new Error("401");
  }

  if (!client.validateRedirectUri(request.redirectUri)) {
    throw new Error("401");
  }

  if (request.request && request.requestUri) {
    throw new Error("invalid_request");
  }

  if (request.request) {
    request = overwriteAuthWithRequest(request, client);
  }
  if (request.requestUri) {
    request = await overwriteAuthWithRequestUri(request, client);
  }

  const session = new Map<string, object>();

  if (request.idTokenHint) {
    return authIdTokenHint(request, client, session);
  }

  if (request.prompt) {
    const prompts = request.prompt.split(" ");
    if (prompts.includes("login")) {
      return renderLogin(request, client, session);
    }

    if (prompts.includes("select_account")) {
      // select_account with account hint is weird
      if (request.loginHint && request.claims?.id_token?.sub) {
        throw new Error("invalid_request");
      }
      return renderSelectAccount(request, client, session);
    }

    if (request.prompt.includes("consent")) {
      if (request.loginHint && session.has(request.loginHint)) {
        return renderConsentForUser(request.loginHint);
      }

      if (
        request.claims?.id_token?.sub &&
        session.has(request.claims?.id_token?.sub)
      ) {
        return renderConsentForUser(request.claims.id_token.sub);
      }
    }
  }

  return renderSelectAccount(request, client, session);
}

function renderLogin(
  request: AuthenticationRequest,
  client: Client,
  session: Map<string, object>
) {
  return "";
}

function renderConsentForUser(user: string) {
  return "";
}

function renderSelectAccount(
  request: AuthenticationRequest,
  client: Client,
  session: Map<string, object>
) {
  if (session.size === 0) {
    return renderLogin(request, client, session);
  }
  return "";
}

function authIdTokenHint(
  request: AuthenticationRequest,
  client: Client,
  session: Map<string, object>
) {
  if (request.prompt) {
    if (request.prompt === "login" || request.prompt === "select_account") {
      throw new Error("login_required");
    }
  }

  const payload = decodeJWT<IdTokenClaims>(request.idTokenHint!);

  if (
    (Array.isArray(payload.aud) && payload.aud.includes(context.issuer)) ||
    payload.aud === context.issuer
  ) {
    throw new Error("login_required");
  }

  if (
    (Array.isArray(payload.aud) && !payload.aud.includes(client.id)) ||
    payload.aud !== client.id
  ) {
    throw new Error("login_required");
  }

  if (payload.iss !== context.issuer) {
    throw new Error("login_required");
  }

  if (session.has(payload.sub)) {
    if (request.prompt && request.prompt === "consent") {
      return renderConsentForUser(payload.sub);
    }

    return redirectCodeToClient(request);
  }

  // authenticated by id_token_hint
  if (payload.exp < new Date().getTime()) {
    return redirectCodeToClient(request);
  }

  throw new Error("login_required");
}

function redirectCodeToClient(request: AuthenticationRequest) {
  return "";
}

function decodeJWT<T>(jwt: string): T {
  return {} as T;
}

function overwriteAuthWithRequest(
  request: AuthenticationRequest,
  client: Client
) {
  if (!client.isRequestSupported()) {
    throw new Error("invalid_request");
  }
  const payload = decodeJWT<AuthenticationRequest>(request.request!);
  if (payload.request || payload.requestUri) {
    throw new Error("invalid_request");
  }
  return { ...request, ...payload };
}

async function overwriteAuthWithRequestUri(
  request: AuthenticationRequest,
  client: Client
) {
  if (!client.validateRequestUri(request.requestUri!)) {
    throw new Error("invalid_request");
  }

  const response = await fetch(request.redirectUri);
  const payload = decodeJWT<AuthenticationRequest>(await response.text());
  if (payload.request || payload.requestUri) {
    throw new Error("invalid_request");
  }
  return { ...request, ...payload };
}
