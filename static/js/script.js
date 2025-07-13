document.addEventListener("DOMContentLoaded", function () {
  const textarea = document.querySelector("#message_content");
  if (textarea) {
    textarea.addEventListener("input", function () {
      this.style.height = "auto";
      this.style.height = this.scrollHeight + "px";
    });
  }

  // Form validation
  const form = document.querySelector("#phishingForm");
  if (form) {
    form.addEventListener("submit", function (e) {
      const url = document.querySelector("#url").value.trim();
      const content = document.querySelector("#message_content").value.trim();

      if (!url && !content) {
        e.preventDefault();
        alert("Mohon masukkan URL atau konten pesan untuk dianalisis!");
        return false;
      }

      showLoading();
    });
  }

  // Loading animation
  function showLoading() {
    document.querySelector(".loading").style.display = "block";
    document.querySelector("#detectBtn").disabled = true;
  }

  function hideLoading() {
    document.querySelector(".loading").style.display = "none";
    document.querySelector("#detectBtn").disabled = false;
  }

  // Form submission
  document.addEventListener("DOMContentLoaded", function () {
    const form = document.querySelector("#phishingForm");
    if (form) {
      form.addEventListener("submit", function (e) {
        showLoading();
        // Form akan disubmit secara normal
      });
    }
  });

  // Auto-hide alerts
  setTimeout(function () {
    const alerts = document.querySelectorAll(".alert");
    alerts.forEach(function (alert) {
      alert.style.transition = "opacity 0.5s";
      alert.style.opacity = "0";
      setTimeout(function () {
        alert.remove();
      }, 500);
    });
  }, 5000);
});
