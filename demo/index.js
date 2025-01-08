const acrValuesInput = document.getElementById("acr_values");
const clientIdInput = document.getElementById("client_id");
const codeChallengeInput = document.getElementById("code_challenge");
const codeChallengeMethodInput = document.getElementById(
  "code_challenge_method"
);
const codeVerifierInput = document.getElementById("code_verifier");
const displayInput = document.getElementById("display");
const hostInput = document.getElementById("host");
const idTokenHintInput = document.getElementById("id_token_hint");
const loginHintInput = document.getElementById("login_hint");
const maxAgeInput = document.getElementById("max_age");
const nonceInput = document.getElementById("nonce");
const promptInput = document.getElementById("prompt");
const redirectUriInput = document.getElementById("redirect_uri");
const responseModeInput = document.getElementById("response_mode");
const responseTypeInput = document.getElementById("response_type");
const scopeInput = document.getElementById("scope");
const stateInput = document.getElementById("state");
const uiLocalesInput = document.getElementById("ui_locales");
const urlDiv = document.getElementById("url");

[
  [hostInput, "host"],
  [acrValuesInput, "acr_values"],
  [clientIdInput, "client_id"],
  [codeChallengeInput, "code_challenge"],
  [codeChallengeMethodInput, "code_challenge_method"],
  [codeVerifierInput, "code_verifier"],
  [displayInput, "display"],
  [idTokenHintInput, "id_token_hint"],
  [loginHintInput, "login_hint"],
  [maxAgeInput, "max_age"],
  [nonceInput, "nonce"],
  [promptInput, "prompt"],
  [redirectUriInput, "redirect_uri"],
  [responseModeInput, "response_mode"],
  [responseTypeInput, "response_type"],
  [scopeInput, "scope"],
  [stateInput, "state"],
  [uiLocalesInput, "ui_locales"],
].forEach(([input, name]) => {
  input.value = localStorage.getItem(name) || "";
  input.addEventListener("change", () => {
    localStorage.setItem(name, input.value);
  });
});

async function fillCodeChallenge() {
  let value = codeVerifierInput.value;
  if (codeChallengeMethodInput.value === "S256") {
    const digest = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(value)
    );
    value = btoa(String.fromCharCode(...new Uint8Array(digest)))
      .replaceAll("+", "-")
      .replaceAll("/", "_")
      .replaceAll("=", "");
  }
  codeChallengeInput.value = value;
  codeChallengeInput.dispatchEvent(new Event("change"));
}

codeVerifierInput.addEventListener("change", fillCodeChallenge);
codeChallengeMethodInput.addEventListener("change", fillCodeChallenge);

function genuuid() {
  uuidInput.value = crypto.randomUUID();
  uuidInput.dispatchEvent(new Event("change"));
}

function copyuuid() {
  // Select the text field
  uuidInput.select();
  uuidInput.setSelectionRange(0, 99999); // For mobile devices

  // Copy the text inside the text field
  navigator.clipboard.writeText(uuidInput.value);
}

function fillLocation() {
  redirectUriInput.value = location.href;
  redirectUriInput.dispatchEvent(new Event("change"));
}

function fillOpenID() {
  scopeInput.value = "openid";
  scopeInput.dispatchEvent(new Event("change"));
}

function fillStateRandomUUID() {
  stateInput.value = crypto.randomUUID();
  stateInput.dispatchEvent(new Event("change"));
}

function fillNonceRandomUUID() {
  nonceInput.value = crypto.randomUUID();
  stateInput.dispatchEvent(new Event("change"));
}

function fillCodeVerifier() {
  const len = Math.floor(Math.random() * (128 - 43)) + 43;
  const bytes = new Uint8Array(len);
  crypto.getRandomValues(bytes);
  const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
  const digit = "0123456789";
  const alphabet = alpha + digit + "-._~";
  let value = "";
  for (let i = 0; i < len; i++) {
    value += alphabet[bytes[i] % alphabet.length];
  }
  codeVerifierInput.value = value;
  codeVerifierInput.dispatchEvent(new Event("change"));
}

function genURL() {
  const required = ["client_id", "redirect_uri", "response_type"];
  let data = {
    client_id: clientIdInput.value,
    redirect_uri: redirectUriInput.value,
    response_type: responseTypeInput.value,
    scope: scopeInput.value,
    state: stateInput.value,
    code_challenge: codeChallengeInput.value,
    code_challenge_method: codeChallengeMethodInput.value,
    nonce: nonceInput.value,
    max_age: maxAgeInput.value,
    ui_locales: uiLocalesInput.value,
    login_hint: loginHintInput.value,
    response_mode: responseModeInput.value,
    display: displayInput.value,
    prompt: promptInput.value,
    acr_values: acrValuesInput.value,
    id_token_hint: idTokenHintInput.value,
  };
  data = Object.keys(data)
    .filter((k) => !!data[k] || required.includes(k))
    .reduce((acc, cur) => ({ ...acc, [cur]: data[cur] }), {});
  const queryString = new URLSearchParams(data);
  const redirectURL = new URL(hostInput.value);
  redirectURL.search = queryString.toString();
  urlDiv.innerHTML = `<a target="_blank" href=${redirectURL.toString()}>${redirectURL.toString()}</a>`;
}
