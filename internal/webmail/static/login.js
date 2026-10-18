// Browsers require a user action to ask for notification permission. Use the
// sign-in submission so the choice is made once without a separate setup step.
(function () {
  "use strict";

  var form = document.querySelector("[data-login]");
  if (!form) return;
  var waiting = false;

  form.addEventListener("submit", function (event) {
    if (!window.isSecureContext || !window.Notification || Notification.permission !== "default") return;
    event.preventDefault();
    if (waiting) return;
    waiting = true;

    function finish() {
      // Permission is optional: a refusal or browser error must not lock the
      // user out of their mailbox. The browser persists Allow and Block.
      waiting = false;
      HTMLFormElement.prototype.submit.call(form);
    }
    try {
      Notification.requestPermission().then(finish, finish);
    } catch (err) {
      finish();
    }
  });
}());
