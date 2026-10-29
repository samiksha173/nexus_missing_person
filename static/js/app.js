"use strict";

document.addEventListener("DOMContentLoaded", () => {
    // Mobile sidebar
    const toggle = document.getElementById("menuToggle");
    const sidebar = document.getElementById("sidebar");
    if (toggle && sidebar) {
        toggle.addEventListener("click", () => sidebar.classList.toggle("open"));
        document.addEventListener("click", (e) => {
            if (window.innerWidth <= 850 && sidebar.classList.contains("open") &&
                !sidebar.contains(e.target) && !toggle.contains(e.target)) {
                sidebar.classList.remove("open");
            }
        });
    }

    // Dismissible flash messages
    document.querySelectorAll(".flash-close").forEach((btn) => {
        btn.addEventListener("click", () => btn.closest(".flash-message")?.remove());
    });

    // Login password show/hide
    const pwToggle = document.getElementById("passwordToggle");
    const pwInput = document.getElementById("password");
    if (pwToggle && pwInput) {
        pwToggle.addEventListener("click", () => {
            const showing = pwInput.type === "text";
            pwInput.type = showing ? "password" : "text";
            pwToggle.innerHTML = showing
                ? '<i class="fa-regular fa-eye"></i>'
                : '<i class="fa-regular fa-eye-slash"></i>';
            pwToggle.setAttribute("aria-label", showing ? "Show password" : "Hide password");
        });
    }

    // Prevent double submits
    document.querySelectorAll("form").forEach((form) => {
        form.addEventListener("submit", () => {
            const btn = form.querySelector('button[type="submit"]');
            if (btn) setTimeout(() => { btn.disabled = true; }, 0);
        });
    });
});
