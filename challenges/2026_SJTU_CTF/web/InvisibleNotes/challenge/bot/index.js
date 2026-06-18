import express from "express";
import rateLimit from "express-rate-limit";
import crypto from "node:crypto";

import { visit, challenge, flag } from "./conf.js";

if (!flag.validate(flag.value)) {
  console.log(`Invalid flag: ${flag.value}`);
  process.exit(1);
}

const app = express();

app.use(express.json());
app.set("view engine", "ejs");

app.get("/", (req, res) => {
  res.render("index", {
    name: challenge.name,
    appUrl: challenge.appUrl.origin,
  });
});

app.use(
  "/api",
  rateLimit({
    windowMs: 60_000,
    max: challenge.rateLimit,
    ipv6Subnet: false,
  }),
);

let activeToken = null;

function clearActiveToken() {
  if (activeToken?.timeout) {
    clearTimeout(activeToken.timeout);
  }
  activeToken = null;
}

app.post("/api/report", async (req, res) => {
  const { url } = req.body;
  if (
    typeof url !== "string" ||
    (!url.startsWith("http://") && !url.startsWith("https://"))
  ) {
    return res.status(400).send("Invalid url");
  }

  const token = "TOKEN_" + crypto.randomBytes(6).toString("hex");
  // console.log(`token: ${token}`);

  clearActiveToken();
  activeToken = {
    value: token,
    verifyCount: 0,
    timeout: setTimeout(() => {
      clearActiveToken();
    }, 240_000),
  };

  try {
    await visit(url, token);
    res.sendStatus(200);
  } catch (e) {
    console.error(e);
    res.status(500).send("Something went wrong");
  }
});

app.post("/api/verify", (req, res) => {
  const { token } = req.body;

  if (!activeToken) {
    res.status(404).send("Not found");
    return;
  }

  activeToken.verifyCount += 1;
  const matched = token === activeToken.value;

  if (matched) {
    res.send(flag.value);
  } else {
    res.status(404).send("Not found");
  }

  if (activeToken && activeToken.verifyCount >= 3) {
    clearActiveToken();
  }
});

app.listen(1337);
