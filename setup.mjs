import { randomBytes } from "node:crypto";
import { execFileSync } from "node:child_process";
import { lstatSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, isAbsolute, join } from "node:path";
import manifest from "./package.json" with { type: "json" };

const cli = process.env.MAGPIE_BIN || "magpie";
const plugin = process.argv[2] || manifest.name;
const desktop = manifest.magpie.edition === "desktop";

function magpie(args, input) {
  try {
    return execFileSync(cli, args, { encoding: "utf8", input, timeout: 30000, stdio: ["pipe", "pipe", "pipe"] });
  } catch {
    throw new Error("Magpie command failed: " + args.slice(0, 2).join(" ") +
      ". Check the CLI path, version, and configuration directory.");
  }
}

function installDesktopCredential() {
  const config = process.env.MAGPIE_API_KEYS_CONFIG_DIR ||
    join(process.env.XDG_CONFIG_HOME || join(homedir(), ".config"), "magpie");
  if (!isAbsolute(config)) throw new Error("Set MAGPIE_API_KEYS_CONFIG_DIR to Magpie's absolute configuration path.");
  const path = join(config, "api-key-manager-desktop.json");
  try {
    const stat = lstatSync(path);
    if (!stat.isFile() || (process.platform !== "win32" && (stat.mode & 0o077))) {
      throw new Error("Existing Desktop credential must be an owner-only regular file.");
    }
    const existing = JSON.parse(readFileSync(path, "utf8"));
    if (!/^mkd_[a-f0-9]{64}$/.test(existing.key) || !/^[a-f0-9]{24}$/.test(existing.id)) {
      throw new Error("Existing Desktop credential is invalid.");
    }
    magpie(["gateway-key", "admin", existing.id, "local"]);
    return;
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }

  const name = "APIKeyManagerDesktop-" + randomBytes(8).toString("hex");
  const key = "mkd_" + randomBytes(32).toString("hex");
  magpie(["gateway-key", "add", name, "--key", "-"], key + "\n");
  const line = magpie(["gateway-key", "list"]).split("\n").find((row) => row.split(/\s+/)[1] === name);
  const id = line?.split(/\s+/)[0];
  if (!/^[a-f0-9]{24}$/.test(id || "")) throw new Error("Could not resolve the newly created Desktop integration key.");
  try {
    magpie(["gateway-key", "admin", id, "local"]);
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    writeFileSync(path, JSON.stringify({ id, key }) + "\n", { flag: "wx", mode: 0o600 });
  } catch (error) {
    magpie(["gateway-key", "remove", id]);
    throw error;
  }
}

try {
  if (desktop) installDesktopCredential();
  const optionText = magpie(["plugin", "options", plugin]).trim();
  const options = optionText.startsWith("{") ? JSON.parse(optionText) : {};
  options.sessionProof = randomBytes(32).toString("hex");
  magpie(["plugin", "options", plugin, JSON.stringify(options)]);
  console.log("Setup complete. Reopen Magpie and select the API Keys sidebar page.");
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
