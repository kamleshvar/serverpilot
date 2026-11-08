(function () {
  "use strict";

  const provisioningForm = document.getElementById("server-add-form");
  const overlay = document.getElementById("server-provision-overlay");
  if (provisioningForm && overlay) {
    provisioningForm.addEventListener("submit", function (event) {
      if (!provisioningForm.checkValidity()) return;
      if (provisioningForm.dataset.submitted === "1") {
        event.preventDefault();
        return;
      }
      provisioningForm.dataset.submitted = "1";
      overlay.hidden = false;
    });
  }

  document.addEventListener("submit", function (event) {
    const form = event.target.closest("form[data-confirm]");
    if (!form) return;
    const message = form.getAttribute("data-confirm");
    if (message && !window.confirm(message)) {
      event.preventDefault();
    }
  });
})();
