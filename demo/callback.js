const localHost = localStorage.getItem("host");
const responseType = localStorage.getItem("response_type");
const localClientId = localStorage.getItem("client_id");
const localRedirectUri = localStorage.getItem("redirect_uri");
const localState = localStorage.getItem("state");
const localCodeVerifier = localStorage.getItem("code_verifier");
const localCodeChallengeMethod = localStorage.getItem("code_challenge_method");

const searchParams = new URLSearchParams(location.search);

async function handleCodeCallback(code) {
  const data = {
    code,
    grant_type: "authorization_code",
    client_id: localClientId,
    redirect_uri: localRedirectUri,
  };

  if (localCodeVerifier) {
    data["code_verifier"] = localCodeVerifier;
  }

  const queryString = new URLSearchParams(data);

  response = await fetch(localHost.replace("auth", "token"), {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
    },
    body: queryString.toString(),
  });

  if (!response.ok) {
    document.body.innerHTML = `
  <h1>Error - ${response.status}</h1>

  <pre>
    ${await response.text()}
  </pre>
  `;
    return;
  }

  document.body.innerHTML = `
  <h1>Result</h1>
  <pre style="
    white-space: pre-wrap;
    word-wrap:break-word;
  ">
${JSON.stringify(await response.json(), null, 4)}
  </pre>
  `;
}

async function main() {
  const error = searchParams.get("error");
  const errorDescription = searchParams.get("error_description");

  if (error) {
    document.body.innerHTML = `<h1>${error} - ${errorDescription}</h1>`;
    return;
  }

  const state = searchParams.get("state");
  if (state) {
    if (state != localState) {
      document.body.innerHTML = `<h1>states are different</h1><p>${localState} - ${state}</p>`;
      return;
    }
  }

  const code = searchParams.get("code");

  if (code) {
    await handleCodeCallback(code);
  }
}

main();
