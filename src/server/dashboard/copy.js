// Copy commands, preserve disclosure state, and manage inline popovers.
function bindControls() {
  "use strict";
  const status = document.getElementById("copy-status");
  for (const button of document.querySelectorAll("[data-copy]")) {
    const label = button.textContent.trim();
    button.addEventListener("click", async () => {
      const source = document.getElementById(button.dataset.copy);
      if (!source) return;
      const text = [...source.childNodes]
        .filter((n) => !(n.classList && n.classList.contains("prompt")))
        .map((n) => n.textContent)
        .join("");
      try {
        await navigator.clipboard.writeText(text);
        if (status) {
          delete status.dataset.error;
          status.textContent = "Copied. Paste it into your terminal.";
        }
        delete button.dataset.copyError;
        button.textContent = "Copied";
        button.dataset.copied = "";
        setTimeout(() => {
          button.textContent = label;
          delete button.dataset.copied;
        }, 2000);
      } catch {
        if (status) {
          status.dataset.error = "";
          status.textContent =
            "Copy is not available here. Select the command and copy it.";
        }
        delete button.dataset.copied;
        button.textContent = "Copy failed";
        button.dataset.copyError = "";
        setTimeout(() => {
          button.textContent = label;
          delete button.dataset.copyError;
        }, 2500);
      }
    });
  }

  // Keep open disclosures in the URL (?revoked=show).
  for (const details of document.querySelectorAll("details[data-param]")) {
    const { param, value } = details.dataset;
    if (new URL(location.href).searchParams.get(param) === value)
      details.open = true;
    details.addEventListener("toggle", () => {
      const next = new URL(location.href);
      if (details.open) next.searchParams.set(param, value);
      else next.searchParams.delete(param);
      history.replaceState(null, "", next);
    });
  }

  // Inline popovers (reset breakdown and reset confirmation):
  // one open at a time, viewport-safe upward flip, click-outside & Escape close.
  const menus = [...document.querySelectorAll("details.popover-menu")];
  for (const menu of menus) {
    menu.addEventListener("toggle", () => {
      if (!menu.open) {
        delete menu.dataset.flip;
        return;
      }
      for (const other of menus) {
        if (other !== menu && other.open) other.open = false;
      }
      const panel = menu.querySelector(".popover");
      if (!panel) return;
      delete menu.dataset.flip;
      const rect = panel.getBoundingClientRect();
      if (rect.bottom > window.innerHeight - 16) {
        menu.dataset.flip = "up";
      }
    });
  }

  for (const closeBtn of document.querySelectorAll("[data-close-details]")) {
    closeBtn.addEventListener("click", () => {
      const menu = closeBtn.closest("details");
      if (!menu) return;
      menu.open = false;
      const summary = menu.querySelector("summary");
      if (summary) summary.focus();
    });
  }

  document.addEventListener("click", (event) => {
    for (const menu of menus) {
      if (menu.open && !menu.contains(event.target)) {
        menu.open = false;
      }
    }
  });

  document.addEventListener("keydown", (event) => {
    if (event.key !== "Escape") return;
    for (const menu of menus) {
      if (!menu.open) continue;
      menu.open = false;
      const summary = menu.querySelector("summary");
      if (summary) summary.focus();
    }
  });
}
bindControls();
