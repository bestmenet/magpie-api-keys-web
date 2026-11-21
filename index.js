import { createHash, timingSafeEqual } from "node:crypto";
import { lstatSync, readFileSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { isIP } from "node:net";
import { networkInterfaces } from "node:os";
import { join } from "node:path";
import manifest from "./package.json" with { type: "json" };

const actions = new Set([
  "add-key", "rename-key", "copy-key", "on-key", "off-key", "rotate-key", "remove-key",
  "models-key", "access-key", "concurrency-key", "limit-key", "reset-limit-key",
]);
const digest = (value) => createHash("sha256").update(value).digest();
const hashSource = (value) => "'sha256-" + digest(value).toString("base64") + "'";
const readPage = (file) => readFileSync(new URL("./page/" + file, import.meta.url), "utf8");
const desktop = manifest.magpie.edition === "desktop";
const periods = new Set(["day", "week", "month", "total", "days", "hours"]);
const script = readPage("app.js");
const style = readPage("app.css");
const html = readPage("app.html").replace("<!--STYLE-->", () => "<style>" + style + "</style>")
  .replace("<!--SCRIPT-->", () => "<script>" + script + "</script>");

function webAddress() {
  const gateway = new URL("http://" + (process.env.MAGPIE_ADDR || "127.0.0.1:3425"));
  const address = new URL("http://" +
    (process.env.MAGPIE_KEY_MANAGER_WEB_ADDR || gateway.hostname + ":3430"));
  const hostname = address.hostname.replace(/^\[|\]$/g, "");
  const local = Object.values(networkInterfaces()).flat().some((entry) => entry?.address === hostname);
  if (address.username || address.password || address.pathname !== "/" || address.search ||
      address.hash || !address.port || !isIP(hostname) ||
      (!local && hostname !== "127.0.0.1" && hostname !== "::1")) {
    throw new Error("MAGPIE_KEY_MANAGER_WEB_ADDR must be a local IP address and port");
  }
  return { hostname, port: Number(address.port) };
}

function desktopAccess(directory) {
  const gateway = new URL("http://" + (process.env.MAGPIE_ADDR || "127.0.0.1:3425"));
  if (!["127.0.0.1", "localhost", "[::1]"].includes(gateway.hostname) || !gateway.port) {
    throw new Error("Desktop requires a loopback Magpie gateway");
  }
  const path = join(directory, "api-key-manager-desktop.json");
  try {
    const stat = lstatSync(path);
    if (!stat.isFile() || (process.platform !== "win32" && (stat.mode & 0o077))) return null;
    const { key, id } = JSON.parse(readFileSync(path, "utf8"));
    if (!/^mkd_[a-f0-9]{64}$/.test(key) || !/^[a-f0-9]{24}$/.test(id)) return null;
    return { address: { hostname: gateway.hostname.replace(/^\[|\]$/g, ""), port: Number(gateway.port) },
      key, id };
  } catch {
    return null;
  }
}

function callMagpie(address, upstreamKey, action, body) {
  return new Promise((resolve, reject) => {
    const headers = { Accept: "application/json" };
    if (desktop) headers.Authorization = "Bearer " + upstreamKey;
    else headers.Cookie = "magpie_web_" + address.port + "=" + upstreamKey;
    if (body) {
      headers["Content-Type"] = "application/json";
      headers["Content-Length"] = Buffer.byteLength(body);
    }
    const request = httpRequest({
      ...address,
      path: (desktop ? "/v1/magpie/admin/gateway-keys" : "/api/caller-keys") + (action ? "/" + action : ""),
      method: action ? "POST" : "GET",
      headers,
      agent: false,
      signal: AbortSignal.timeout(8000),
    }, (response) => {
      response.on("error", reject);
      if (!response.headers["content-type"]?.includes("application/json")) {
        response.resume();
        reject(new Error("Magpie returned HTTP " + response.statusCode));
        return;
      }
      const chunks = [];
      let size = 0;
      response.on("data", (chunk) => {
        size += chunk.length;
        if (size > 4 * 1024 * 1024) {
          response.destroy(new Error("Magpie response was too large"));
          return;
        }
        chunks.push(chunk);
      });
      response.on("end", () => {
        try {
          const data = JSON.parse(Buffer.concat(chunks).toString("utf8"));
          if (response.statusCode >= 400 && typeof data.error !== "string" && !data.error?.message) {
            reject(new Error("Magpie returned HTTP " + response.statusCode));
          } else {
            resolve(typeof data.error?.message === "string" ? { error: data.error.message } : data);
          }
        } catch (error) {
          reject(error);
        }
      });
    });
    request.on("error", reject);
    request.end(body);
  });
}

const cors = {
  "Access-Control-Allow-Origin": "null",
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
};

function json(data, status = 200) {
  return Response.json(data, { status, headers: cors });
}

function limitsOf(key) {
  return [key.limit, ...(key.moreLimits || [])].filter(Boolean);
}

function limitRevision(key) {
  return digest(JSON.stringify(limitsOf(key))).toString("hex");
}

function keyRows(keys, hiddenId) {
  return keys.filter((key) => key.id !== hiddenId).map((key) => ({
    id: key.id, name: key.name, masked: key.masked, off: !!key.off, lan: !!key.lan,
    expires: key.expires, readOnly: !!key.readOnly, browser: !!key.browser,
    models: key.models || [], accounts: key.accounts?.length || 0,
    maxConcurrency: key.maxConcurrency || 0, limits: limitsOf(key),
    usage: key.usedAll || [], limitRevision: limitRevision(key),
  }));
}

function modelPatterns(value) {
  return Array.isArray(value) && value.length <= 200 &&
    value.every((model) => typeof model === "string" && model.length <= 300);
}

function keyChange(action, input, key, name) {
  switch (action) {
    case "add-key":
    case "access-key":
      if (input.readOnly === undefined && action === "add-key") return { key, name };
      if (typeof input.readOnly !== "boolean") return null;
      return { key, name, readOnly: input.readOnly };
    case "models-key":
      return modelPatterns(input.models) ? { key, models: input.models } : null;
    case "concurrency-key":
      return Number.isInteger(input.maxConcurrency) && input.maxConcurrency >= 0 && input.maxConcurrency <= 1000
        ? { key, maxConcurrency: input.maxConcurrency } : null;
    case "limit-key":
    case "reset-limit-key": {
      const index = input.index;
      if (!Number.isInteger(index) || index < 0 || index >= 5) return null;
      const limit = input.limit;
      if (action === "reset-limit-key" || limit === null) return { key, index };
      if (!limit || !periods.has(limit.period) || !Number.isSafeInteger(limit.tokens) ||
          limit.tokens < 0 || !Number.isFinite(limit.cost) || limit.cost < 0 ||
          !(limit.tokens || limit.cost >= 0.0001) || !modelPatterns(limit.models) ||
          typeof limit.cacheReads !== "boolean") return null;
      const { period, tokens, cost, models, cacheReads } = limit;
      const result = { key, index, limit: { period, tokens, cost, models, cacheReads } };
      if (period === "days" || period === "hours") {
        const length = limit[period];
        if (!Number.isInteger(length) || length < 1 || length > (period === "days" ? 3650 : 8760)) return null;
        result.limit[period] = length;
      }
      return result;
    }
    default:
      return { key, name };
  }
}

export default async function apiKeys({ directory }, options = {}) {
  const port = manifest.magpie.page.service.port;
  const proof = options.sessionProof;
  const expected = typeof proof === "string" && /^[a-f0-9]{64}$/.test(proof) ? digest(proof) : null;
  const local = desktop ? desktopAccess(directory) : null;
  const upstreamKey = desktop ? local?.key : process.env.MAGPIE_WEB_KEY;
  const address = desktop ? local?.address : webAddress();

  Bun.serve({
    hostname: "127.0.0.1",
    port,
    maxRequestBodySize: 48 * 1024,
    async fetch(req) {
      if (req.headers.get("host") !== "127.0.0.1:" + port) return new Response(null, { status: 403 });
      const origin = req.headers.get("origin");
      if (origin !== null && origin !== "null") return new Response(null, { status: 403 });
      const path = new URL(req.url).pathname;
      if (path === "/" && req.method === "GET") {
        return new Response(html, {
          headers: {
            "Content-Type": "text/html; charset=utf-8",
            "Cache-Control": "no-store",
            "Content-Security-Policy": "default-src 'none'; script-src " + hashSource(script) +
              "; style-src " + hashSource(style) + "; connect-src " +
              (desktop ? "http://127.0.0.1:" + port : "'self'") + "; base-uri 'none'; form-action 'none'",
          },
        });
      }
      if (path !== "/api/keys") return json({ error: "找不到该接口。" }, 404);
      if (req.method === "OPTIONS") {
        return new Response(null, { status: 204, headers: {
          ...cors, "Access-Control-Allow-Methods": "POST",
          "Access-Control-Allow-Headers": "authorization, content-type",
        } });
      }
      if (req.method !== "POST" || !req.headers.get("content-type")?.startsWith("application/json")) {
        return json({ error: "请求格式不正确。" }, 405);
      }
      if (!expected) return json({ error: "请按 README 完成一次性初始化。" }, 503);
      const auth = req.headers.get("authorization") || "";
      if (auth.length > 4096 || !auth.startsWith("Bearer ") ||
          !timingSafeEqual(expected, digest(auth.slice(7)))) {
        return json({ error: "管理会话不可用，请重新打开插件。" }, 401);
      }

      if (!upstreamKey || !address) return json({ error: "Magpie 管理接口尚未配置，请检查 README 的安装步骤。" }, 503);

      const input = await req.json().catch(() => null);
      const action = input?.action;
      if (action !== "list" && !actions.has(action)) return json({ error: "不支持该操作。" }, 400);
      const id = typeof input.id === "string" ? input.id : "";
      const name = typeof input.name === "string" ? input.name.trim() : "";
      if (action !== "list" && action !== "add-key" && !/^[a-zA-Z0-9_-]{1,120}$/.test(id)) {
        return json({ error: "找不到要操作的密钥。" }, 400);
      }
      if ((action === "add-key" || action === "rename-key") && (!name || [...name].length > 120)) {
        return json({ error: "名称需为 1–120 个字符。" }, 400);
      }

      if (desktop && (id === local.id || action === "copy-key")) {
        return json({ error: "Desktop 的本机管理接口只在创建和轮换时返回完整密钥。" }, 403);
      }
      const body = action === "list" ? null : keyChange(action, input, id, name);
      if (action !== "list" && !body) return json({ error: "设置格式不正确，请检查后重试。" }, 400);

      try {
        if (action === "limit-key" || action === "reset-limit-key") {
          const current = (await callMagpie(address, upstreamKey)).keys?.find((key) => key.id === id);
          if (!current || limitRevision(current) !== input.limitRevision) {
            return json({ error: "额度已在其他页面修改，请刷新后重新打开详情。" }, 409);
          }
        }
        const result = action === "list"
          ? await callMagpie(address, upstreamKey)
          : await callMagpie(address, upstreamKey, action, JSON.stringify(body));
        if (typeof result.error === "string") return json({ error: result.error }, 400);
        if (!Array.isArray(result.keys)) {
          return json({ error: "Magpie 无法完成该操作，请刷新列表后确认状态。" }, 409);
        }
        const output = { keys: keyRows(result.keys, local?.id), revealExisting: !desktop };
        if (action === "add-key" || action === "rotate-key" || action === "copy-key") {
          if (!result.secret) return json({ error: "Magpie 未返回密钥，请刷新后检查。" }, 409);
          output.secret = result.secret;
        }
        return json(output);
      } catch {
        return json({ error: "无法确认 Magpie 操作结果，请刷新列表后检查。" }, 502);
      }
    },
  });
  return {};
}
