(function () {
  "use strict";
  var scope = document.getElementById("scope");
  var wrap = document.getElementById("custom-wrap");
  if (!scope || !wrap) return;
  function sync() {
    wrap.classList.toggle("hidden", scope.value !== "custom");
  }
  scope.addEventListener("change", sync);
  sync();
})();
