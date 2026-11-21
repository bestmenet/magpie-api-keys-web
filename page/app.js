const get = (id) => document.getElementById(id);
const theme = location.hash.slice(1);
if (theme === "light" || theme === "dark") document.documentElement.dataset.theme = theme;

const endpoint = new URL("api/keys", location.href);
const edit = get("edit");
const detail = get("detail");
const policy = get("policy");
const secretDialog = get("secret-dialog");
const secretField = get("secret");
const nameField = get("new-name");
const rename = get("rename-value");
const rows = get("keys");
const search = get("search");
const filter = get("filter");

const modelExample = "例如 openai/* 或 group/default";
const periods = { day: "每日", week: "每周", month: "每月", total: "累计", days: "每 N 天", hours: "每 N 小时" };
const states = { on: "已启用", off: "已停用", expired: "已过期" };
const decimal = new Intl.NumberFormat("zh-CN");
const dollars = new Intl.NumberFormat("zh-CN", { style: "currency", currency: "USD", maximumFractionDigits: 4 });
const date = new Intl.DateTimeFormat("zh-CN", { dateStyle: "medium", timeStyle: "short" });
const splitPatterns = (value) => [...new Set(value.split(/[\n,，]/).map((part) => part.trim()).filter(Boolean))];

let credential = "";
let revealExisting = false;
let keys = null;
let busy = false;
let pendingEdit;
let detailId;
let savePolicy;
let copyNotice = "";

function node(tag, text, className) {
  const el = document.createElement(tag);
  if (text) el.textContent = text;
  if (className) el.className = className;
  return el;
}

function button(text, handler, label = "", className = "") {
  const el = node("button", text, className);
  el.type = "button";
  if (label) el.setAttribute("aria-label", text + "：" + label);
  el.addEventListener("click", handler);
  return el;
}

function close(dialog) {
  if (dialog.open) dialog.close();
}

function message(text, target = get("status"), error = false) {
  target.textContent = text;
  target.toggleAttribute("data-error", error);
}

function lock() {
  credential = "";
  keys = null;
  detailId = undefined;
  pendingEdit = undefined;
  savePolicy = undefined;
  secretField.value = "";
  search.value = "";
  filter.value = "";
  for (const dialog of [detail, policy, edit, secretDialog]) close(dialog);
  get("policies").replaceChildren();
  get("budgets").replaceChildren();
  get("policy-fields").replaceChildren();
  render();
}

async function request(action, fields = {}, feedback = get("status"), success = "") {
  if (busy) return null;
  busy = true;
  let listChanged = false;
  const enabled = [...document.querySelectorAll("button:enabled")];
  enabled.forEach((el) => { el.disabled = true; });
  message("", feedback);
  try {
    const response = await fetch(endpoint, {
      method: "POST", credentials: "omit", redirect: "error", cache: "no-store",
      headers: { "Content-Type": "application/json", Authorization: "Bearer " + credential },
      body: JSON.stringify({ action, ...fields }),
    });
    const result = await response.json();
    if (response.status === 401) lock();
    if (!response.ok) throw new Error(result.error);
    if (action !== "copy-key") {
      keys = result.keys;
      revealExisting = result.revealExisting === true;
      listChanged = true;
    }
    if (success) message(success, feedback);
    return result;
  } catch (error) {
    const problem = error instanceof TypeError || error instanceof SyntaxError
      ? "暂时无法连接密钥管理服务，请刷新后重试。" : error.message;
    message(problem, feedback.closest("dialog")?.open === false ? get("status") : feedback, true);
    return null;
  } finally {
    busy = false;
    for (const el of enabled) el.disabled = false;
    if (listChanged) render();
  }
}

// The website/desktop shell supplies the private option for this exact plugin
// frame. The URL contains no credential, and top-level service pages fail closed.
function optionFromParent() {
  if (parent === window) return Promise.reject(new Error("请从 Magpie 侧栏打开此插件。"));
  const desktop = false;
  const id = crypto.getRandomValues(new Uint32Array(1))[0];
  return new Promise((resolve, reject) => {
    const done = (error, value) => {
      clearTimeout(timer);
      removeEventListener("message", onMessage);
      if (error) reject(new Error(error));
      else resolve(value);
    };
    const onMessage = (event) => {
      if (event.source !== parent || (!desktop && event.origin !== location.origin)) return;
      const data = event.data;
      if (data?.magpie !== 1 || data.id !== id) return;
      done(data.error, data.result?.sessionProof);
    };
    const timer = setTimeout(() => done("无法从 Magpie 管理窗口取得插件会话。"), 5000);
    addEventListener("message", onMessage);
    parent.postMessage({ magpie: 1, id, method: "options.get" }, desktop ? "*" : location.origin);
  });
}

async function connect() {
  if (busy) return;
  get("show-keys").disabled = true;
  try {
    const proof = await optionFromParent();
    if (typeof proof !== "string" || !/^[a-f0-9]{64}$/.test(proof)) {
      throw new Error("请在运行 Magpie 的设备上按 README 完成一次性初始化。");
    }
    credential = proof;
    await request("list");
  } catch (error) {
    message(error.message, get("status"), true);
  } finally {
    get("show-keys").disabled = false;
  }
}

function stateOf(key) {
  if (key.expires && Date.parse(key.expires) <= Date.now()) return "expired";
  return key.off ? "off" : "on";
}

function typeOf(key) {
  return key.browser ? "浏览器扩展" : key.readOnly ? "仅查看统计" : "模型调用";
}

function render() {
  const unlocked = keys !== null;
  for (const id of ["refresh", "key-table"]) get(id).hidden = !unlocked;
  get("locked").hidden = unlocked;
  search.disabled = filter.disabled = get("create-button").disabled = !unlocked;
  get("directory-note").textContent = unlocked ? "按名称或密钥尾号查找，点击「管理」查看单把密钥的设置。" : "等待 Magpie 管理接口。请从对应版本的侧栏打开。";
  get("total").textContent = unlocked ? keys.length : "—";
  const active = keys?.filter((key) => stateOf(key) === "on").length ?? 0;
  get("active").textContent = unlocked ? active : "—";
  get("inactive").textContent = unlocked ? keys.length - active : "—";
  const query = search.value.trim().toLowerCase();
  const visible = (keys ?? []).filter((key) =>
    (!filter.value || filter.value === stateOf(key)) &&
    (!query || key.name.toLowerCase().includes(query) || key.masked?.toLowerCase().includes(query)));
  rows.replaceChildren(...visible.map(renderRow));
  const empty = get("empty");
  empty.hidden = visible.length > 0;
  empty.textContent = keys?.length ? "没有匹配的密钥。" : "还没有网关密钥。可在上方创建第一把。";
  if (!detail.open) return;
  const current = keys?.find((key) => key.id === detailId);
  if (current) renderDetail(current);
  else close(detail);
}

function renderRow(key) {
  const row = node("tr");
  const identity = node("th", key.name);
  identity.scope = "row";
  identity.append(node("code", key.masked || "…", "meta"));
  const state = stateOf(key);
  const statusCell = node("td");
  const badge = node("span", states[state], "pill");
  badge.dataset.state = state;
  statusCell.append(badge);
  const scope = key.models.length ? `指定 ${key.models.length} 个模型或规则` :
    key.accounts ? "受账号范围限制" : "全部模型";
  const limits = key.limits.length ? `${key.limits.length} 项额度` : "无额度限制";
  const access = node("td", typeOf(key));
  access.append(node("span", (key.readOnly || key.browser ? "" : scope + " · ") + limits, "meta"));
  const actions = node("td");
  const group = node("div", "", "actions");
  if (revealExisting) group.append(button("查看密钥", () => reveal(key), key.name));
  group.append(button("管理", () => openDetail(key.id), key.name));
  actions.append(group);
  row.append(identity, statusCell, access, actions);
  return row;
}

async function create() {
  const name = nameField.value.trim();
  nameField.setCustomValidity(name && [...name].length <= 120 ? "" : "请输入 1–120 个字符作为密钥名称。");
  if (!nameField.reportValidity()) return;
  const readOnly = get("new-access").value === "readonly";
  if (keys === null) return;
  const result = await request("add-key", { name, readOnly }, get("status"), "已创建密钥。");
  if (!result) return;
  nameField.value = "";
  search.value = "";
  filter.value = "";
  render();
  showSecret(result.secret, name, "新 API Key");
}

function showSecret(secret, name, title) {
  get("secret-title").textContent = title + " · " + name;
  secretField.value = secret;
  get("copy-status").textContent = "";
  secretDialog.showModal();
  get("copy-value").focus();
}

async function reveal(key) {
  const result = await request("copy-key", { id: key.id });
  if (result) showSecret(result.secret, key.name, "API Key");
}

async function copy() {
  const value = secretField.value;
  let text = "已复制。";
  try {
    await navigator.clipboard.writeText(value);
  } catch {
    if (!secretDialog.open || secretField.value !== value) return;
    secretField.focus();
    secretField.select();
    let copied = false;
    try { copied = document.execCommand("copy"); } catch {}
    if (!copied) text = "已选中密钥，请按 Ctrl+C 或 ⌘C 复制。";
  }
  if (!secretDialog.open) return;
  copyNotice = text === copyNotice ? text + "\u00a0" : text;
  get("copy-status").textContent = copyNotice;
}

function openDetail(id) {
  const key = keys?.find((row) => row.id === id);
  if (!key) return;
  detailId = id;
  renderDetail(key);
  if (!detail.open) detail.showModal();
  get("detail-close").focus();
}

function summary(title, description, ...buttons) {
  const row = node("div", "", "policy-row");
  const info = node("div");
  info.append(node("strong", title), node("p", description, "meta"));
  const actions = node("div", "", "actions");
  actions.append(...buttons);
  row.append(info, actions);
  return row;
}

function periodLabel(limit) {
  if (limit.period === "days") return `每 ${limit.days} 天`;
  if (limit.period === "hours") return `每 ${limit.hours} 小时`;
  return periods[limit.period];
}

function budgetSummary(limit, usage) {
  const parts = [];
  if (limit.tokens) parts.push(`${usage ? decimal.format(usage.tokens) : "—"} / ${decimal.format(limit.tokens)} Token`);
  if (limit.cost) parts.push(`${usage ? dollars.format(usage.cost) : "—"} / ${dollars.format(limit.cost)}`);
  if (limit.models?.length) parts.push(limit.models.join("、"));
  if (usage?.spent) parts.push("已达上限");
  if (usage?.reset && Date.parse(usage.reset) > 0) parts.push("重置 " + date.format(new Date(usage.reset)));
  return parts.join(" · ");
}

function renderDetail(key) {
  get("detail-title").textContent = key.name;
  const bits = [key.masked || "…", states[stateOf(key)]];
  if (key.lan) bits.push("共享密钥");
  if (key.expires) bits.push("到期 " + date.format(new Date(key.expires)));
  get("detail-meta").textContent = bits.join(" · ");
  const accessControls = key.browser || key.lan ? [] : [button("设置", () => editPolicy(key, "access-key"))];
  const policyRows = [
    summary("访问类型", typeOf(key), ...accessControls),
    summary("可用模型", key.models.join("、") || (key.accounts ? "受账号范围限制" : "全部模型"),
      button("设置", () => editPolicy(key, "models-key"))),
    summary("并发上限", key.maxConcurrency ? `${key.maxConcurrency} 个请求` : "不限制",
      button("设置", () => editPolicy(key, "concurrency-key"))),
  ];
  get("policies").replaceChildren(...policyRows);
  get("budgets").replaceChildren(...key.limits.map((limit, index) =>
    summary(periodLabel(limit), budgetSummary(limit, key.usage[index]),
      button("编辑", () => editLimit(key, index), periodLabel(limit)),
      button("重置用量", () => ask(key, "reset-limit-key", "重置用量", "此额度的用量将从零重新计算。", index), periodLabel(limit)),
      button("移除额度", () => ask(key, "limit-key", "移除额度", "移除后，此周期的额度将停止生效。", index), periodLabel(limit)))));
  if (!key.limits.length) get("budgets").append(node("p", "当前没有额度限制。", "hint"));
  get("add-limit").disabled = key.limits.length >= 5;
  const lifecycle = stateOf(key) === "expired" ? [] : [
    key.off ? button("启用", () => changeDetail(key, "on-key"), key.name)
      : button("停用", () => ask(key, "off-key", "停用密钥", "使用此密钥的平台将暂时无法调用网关。"), key.name),
    button("轮换", () => ask(key, "rotate-key", "轮换密钥", "旧密钥会立即失效。轮换后请更新对应平台的配置。"), key.name),
  ];
  get("detail-actions").replaceChildren(
    ...(revealExisting ? [button("查看密钥", () => reveal(key), key.name)] : []),
    button("重命名", () => ask(key, "rename-key", "重命名"), key.name),
    ...lifecycle,
    button("删除", () => ask(key, "remove-key", "删除密钥", "删除后，此密钥会永久失效。"), key.name, "danger"),
  );
}

async function changeDetail(key, action) {
  const id = key.id;
  const result = await request(action, { id }, get("status"), "已更新密钥。");
  if (result) openDetail(id);
}

function ask(key, action, title, details = "", index) {
  pendingEdit = { key, action, index };
  get("edit-title").textContent = title + " · " + key.name;
  get("edit-details").hidden = !details;
  get("edit-details").textContent = details;
  const naming = action === "rename-key";
  get("rename-group").hidden = !naming;
  rename.required = naming;
  rename.setCustomValidity("");
  rename.value = naming ? key.name : "";
  get("confirm").textContent = naming ? "保存名称" : "确认";
  get("confirm").classList.toggle("danger", action === "remove-key");
  message("", get("edit-status"));
  edit.showModal();
  if (naming) { rename.focus(); rename.select(); }
  else get("cancel").focus();
}

async function confirmEdit() {
  if (!pendingEdit || busy) return;
  const { key, action, index } = pendingEdit;
  const name = rename.value.trim();
  if (action === "rename-key") {
    rename.setCustomValidity(name && [...name].length <= 120 ? "" : "请输入 1–120 个字符。");
    if (!rename.reportValidity()) return;
  }
  const fields = { id: key.id, name };
  if (index !== undefined) Object.assign(fields, { index, limit: null, limitRevision: key.limitRevision });
  const result = await request(action, fields, get("edit-status"));
  if (!result) return;
  close(edit);
  message("已更新密钥。");
  if (result.secret) showSecret(result.secret, key.name, "新 API Key");
}

function field(title, input, hint = "") {
  const label = node("label", title, "field");
  label.append(input);
  if (hint) {
    const note = node("span", hint, "meta");
    note.id = input.id + "-help";
    input.setAttribute("aria-describedby", note.id);
    label.append(note);
  }
  return label;
}

function numberControl(id, value, min, max, step = "1") {
  const input = node("input");
  Object.assign(input, { id, type: "number", value: value ?? "", min, max, step });
  return input;
}

function options(values, selected) {
  const control = node("select");
  for (const [value, text] of Object.entries(values)) {
    const option = node("option", text);
    option.value = value;
    control.append(option);
  }
  control.value = selected;
  return control;
}

function patterns(id, existing) {
  const control = node("textarea");
  Object.assign(control, { id, value: existing.join("\n"), spellcheck: false });
  return control;
}

function startPolicy(key, title, fields, collect, action) {
  get("policy-title").textContent = title + " · " + key.name;
  get("policy-fields").replaceChildren(...fields);
  message("", get("policy-status"));
  savePolicy = async () => {
    const changes = collect();
    if (!changes) return;
    const result = await request(action, { id: key.id, ...changes }, get("policy-status"));
    if (result) {
      close(policy);
      message("设置已保存。");
    }
  };
  policy.showModal();
  policy.querySelector("input, select, textarea")?.focus();
}

function editPolicy(key, action) {
  if (action === "access-key") {
    const control = options({ full: "模型调用", readonly: "仅查看统计" }, key.readOnly ? "readonly" : "full");
    startPolicy(key, "访问类型", [field("允许的访问", control)], () => ({ readOnly: control.value === "readonly" }), action);
  } else if (action === "models-key") {
    const control = patterns("model-scope", key.models);
    control.placeholder = modelExample;
    startPolicy(key, "可用模型", [field("模型 ID 或规则", control, "每行一项。留空表示沿用网关可用范围，已有账号限制仍生效。")],
      () => ({ models: splitPatterns(control.value) }), action);
  } else {
    const control = numberControl("max-concurrency", key.maxConcurrency, "0", "1000");
    startPolicy(key, "并发上限", [field("同时处理的请求数", control, "填 0 表示不限制，超过上限的请求会排队。")],
      () => control.reportValidity() ? { maxConcurrency: Number(control.value) } : null, action);
    onEnter(control, () => savePolicy?.());
  }
}

function editLimit(key, index) {
  const existing = key.limits[index] ?? {};
  const period = options(periods, existing.period || "day");
  const length = numberControl("period-length", existing.days || existing.hours || 5, "1", "8760");
  length.required = true;
  const tokens = numberControl("limit-tokens", existing.tokens, "0", String(Number.MAX_SAFE_INTEGER));
  const cost = numberControl("limit-cost", existing.cost, "0", "", "0.0001");
  const models = patterns("limit-models", existing.models || []);
  const cache = node("input");
  Object.assign(cache, { id: "cache-reads", type: "checkbox", checked: !!existing.cacheReads });
  const cacheLabel = node("label", "", "field check");
  cacheLabel.append(cache, "将缓存读取计入 Token 用量");
  const duration = field("周期长度", length);
  const limits = node("div", "", "field-grid");
  limits.append(field("Token 上限", tokens), field("费用上限（USD）", cost));
  const updatePeriod = () => {
    duration.hidden = period.value !== "days" && period.value !== "hours";
    length.max = period.value === "days" ? "3650" : "8760";
  };
  period.addEventListener("change", updatePeriod);
  updatePeriod();
  startPolicy(key, index < key.limits.length ? "编辑额度" : "添加额度",
    [field("统计周期", period), duration, limits, field("统计的模型", models, "可填模型 ID 或供应商通配规则，每行一项。留空统计整把密钥。"), cacheLabel],
    () => {
      if (![tokens, cost].every((input) => input.reportValidity()) || (!duration.hidden && !length.reportValidity())) return null;
      if (!Number(tokens.value) && !Number(cost.value)) {
        message("请至少填写一个大于零的上限。", get("policy-status"), true);
        return null;
      }
      const limit = { period: period.value, tokens: Number(tokens.value), cost: Number(cost.value),
        cacheReads: cache.checked, models: splitPatterns(models.value) };
      if (!duration.hidden) limit[period.value] = Number(length.value);
      return { index, limit, limitRevision: key.limitRevision };
    }, "limit-key");
}

function onEnter(field, submit) {
  field.addEventListener("keydown", (event) => {
    if (event.key !== "Enter" || event.isComposing || event.keyCode === 229 || event.repeat) return;
    event.preventDefault();
    submit();
  });
}

get("show-keys").addEventListener("click", connect);
get("create-button").addEventListener("click", create);
nameField.addEventListener("input", () => nameField.setCustomValidity(""));
search.addEventListener("input", render);
filter.addEventListener("change", render);
get("refresh").addEventListener("click", () => request("list", {}, get("status"), "列表已刷新。"));
get("detail-close").addEventListener("click", () => close(detail));
get("add-limit").addEventListener("click", () => {
  const key = keys?.find((row) => row.id === detailId);
  if (key && key.limits.length < 5) editLimit(key, key.limits.length);
});
get("cancel").addEventListener("click", () => close(edit));
get("confirm").addEventListener("click", confirmEdit);
rename.addEventListener("input", () => rename.setCustomValidity(""));
get("policy-cancel").addEventListener("click", () => close(policy));
get("policy-save").addEventListener("click", () => savePolicy?.());
policy.addEventListener("close", () => { savePolicy = undefined; });
get("close-secret").addEventListener("click", () => close(secretDialog));
secretDialog.addEventListener("close", () => { secretField.value = ""; });
for (const dialog of [edit, policy, detail]) {
  dialog.addEventListener("cancel", (event) => { if (busy) event.preventDefault(); });
}
document.addEventListener("command", (event) => {
  if (event.command === "--copy" && event.target === secretField) copy();
}, true);
if (!("CommandEvent" in window)) get("copy-value").addEventListener("click", copy);
onEnter(nameField, create);
onEnter(rename, confirmEdit);

connect();
