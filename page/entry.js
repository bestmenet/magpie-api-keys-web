window.magpie.ready.then(() => {
  if (!window.magpie.service) {
    document.querySelector("#message").textContent = "请在 Magpie Web 管理页打开此版本。";
    return;
  }
  const service = new URL(window.magpie.service);
  const theme = document.documentElement.dataset.theme;
  if (theme === "light" || theme === "dark") service.hash = theme;
  location.replace(service.href);
}).catch(() => {
  document.querySelector("#message").textContent = "无法打开 API Key 管理，请重新打开该栏目。";
});
