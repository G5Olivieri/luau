function genform() {
  const names = [
    "state",
    "nonce",
    "response_mode",
    "display",
    "prompt",
    "max_age",
    "ui_locales",
    "id_token_hint",
    "login_hint",
    "acr_values",
    "code_challenge",
    "code_challenge_method",
  ];

  console.log(
    names
      .map(
        (s) => `
    <div>
        <label for="${s}">
            ${s}
        </label>
        <input type="text" id="${s}" name="${s}">
    </div>
`
      )
      .join("\n")
  );
}

function genoptions(names) {
    console.log(
        names
        .map((s) => `<option value="${s}">${s}</option>`)
        .join("\n")
    );
}

// genoptions(['page', 'popup', 'touch', 'wap'])
genoptions(['none', 'login', 'consent', 'select_account'])
