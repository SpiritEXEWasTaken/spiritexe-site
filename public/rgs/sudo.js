// Sudo mode, like GitHub's: big actions (bans, maintenance, linking servers, password changes…)
// ask for a 2FA code once. The sudo token it gives is kept only in this tab (sessionStorage), so
// it ends when you leave the site, and the website only accepts it from the same sign-in and
// network address it was made for.
window.rgsSudo = (() => {
  const KEY = "rgsSudo";
  let dialog = null;

  function build() {
    dialog = document.createElement("dialog");
    dialog.className = "card sudo";
    dialog.setAttribute("aria-labelledby", "sudoTitle");
    dialog.innerHTML = `<form method="dialog">
        <h2 id="sudoTitle">Confirm It’s You</h2>
        <p class="dim" id="sudoWhy"></p>
        <label for="sudoCode">6-digit code from your authenticator app</label>
        <input id="sudoCode" inputmode="numeric" autocomplete="one-time-code" required>
        <div class="msg" id="sudoMsg" role="status" aria-live="polite"></div>
        <div class="row" style="margin-top:12px"><button class="primary" value="ok">Confirm</button><button value="cancel" formnovalidate>Cancel</button></div>
      </form>`;
    const style = document.createElement("style");
    style.textContent = `dialog.sudo { max-width: 400px; width: calc(100% - 32px); color: inherit; }
      dialog.sudo::backdrop { background: rgba(0, 0, 0, 0.6); }
      dialog.sudo h2 { font-size: 1.25rem; line-height: 1.3; margin: 0 0 6px; }
      dialog.sudo label { display: block; font-size: var(--fs-small); font-weight: 500; color: var(--ink-2); margin: 14px 0 6px; }
      dialog.sudo input { width: 100%; }`;
    document.head.appendChild(style);
    document.body.appendChild(dialog);
  }

  /** Shows the dialog; resolves with the typed code, or null if cancelled. */
  function ask(why, error = "") {
    if (!dialog) build();
    dialog.querySelector("#sudoWhy").textContent = why;
    const msg = dialog.querySelector("#sudoMsg");
    msg.className = "msg" + (error ? " err" : ""); msg.textContent = error;
    const input = dialog.querySelector("#sudoCode");
    input.value = "";
    dialog.returnValue = "";
    dialog.showModal();
    input.focus();
    return new Promise((resolve) => dialog.addEventListener("close", () => {
      resolve(dialog.returnValue === "ok" && input.value.trim() ? input.value.trim() : null);
    }, { once: true }));
  }

  /** Asks for a code until it works (or is cancelled), using `check(code)`, which throws on a bad code. */
  async function askUntil(why, check) {
    let error = "";
    for (;;) {
      const code = await ask(why, error);
      if (code === null) return false;
      try { await check(code); return true; } catch (err) { error = err.message; }
    }
  }

  /** Website sudo mode for this tab. True once it's on. */
  function confirm(why = "Enter your 2FA code to continue. You won’t be asked again until you leave the site.") {
    return askUntil(why, async (code) => {
      const res = await fetch("/rgs/api/sudo", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ code }), credentials: "same-origin" });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.message || "That code didn’t work.");
      sessionStorage.setItem(KEY, data.sudo);
    });
  }

  const token = () => sessionStorage.getItem(KEY) || "";
  return {
    token,
    headers: () => (token() ? { "X-RGS-Sudo": token() } : {}),
    active: () => !!token(),
    clear: () => sessionStorage.removeItem(KEY),
    confirm,
    askUntil,
  };
})();
