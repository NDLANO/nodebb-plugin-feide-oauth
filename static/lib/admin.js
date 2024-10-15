define("admin/plugins/sso-feide", ["settings", "alerts"], function (
  Settings,
  alerts,
) {
  "use strict";
  /* globals $, app, socket, require */

  var ACP = {};

  ACP.init = function () {
    Settings.load("sso-feide", $(".sso-feide-settings"));

    $("#save").on("click", function () {
      Settings.save("sso-feide", $(".sso-feide-settings"), function () {
        alerts.alert({
          type: "success",
          alert_id: "sso-feide-saved",
          title: "Settings Saved",
          message: "Please reload your NodeBB to apply these settings",
          clickfn: function () {
            socket.emit("admin.reload");
          },
        });
      });
    });
  };

  return ACP;
});
