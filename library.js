(function (module) {
  const User = require.main.require("./src/user");
  const db = require.main.require("./src/database");
  const meta = require.main.require("./src/meta");
  const nconf = require.main.require("nconf");
  const async = require.main.require("async");
  const passport = require.main.require("passport");
  const OpenIDConnectStrategy = require("passport-openidconnect");
  const utils = require("passport-openidconnect/lib/utils");
  const winston = require.main.require("winston");
  const authenticationController = require.main.require(
    "./src/controllers/authentication",
  );

  const gatewayHost = process.env.API_GATEWAY_HOST
    ? `http://${process.env.API_GATEWAY_HOST}`
    : `https://api.test.ndla.no`;

  const constants = Object.freeze({
    name: "Feide",
    admin: {
      icon: "fa-users",
      route: "/plugins/sso-feide",
    },
    gatewayHost,
    myndlaApiUrl: `${gatewayHost}/myndla-api/v1/users/`,
    validRoles: ["employee"],
  });

  const sanitizeUsername = (username) => {
    return username
      .trim()
      .replace(/[^'"\s\-.*0-9\u00BF-\u1FFF\u2C00-\uD7FF\w]+/, "-");
  };

  const Feide = {};

  const fetchUserInfo = async (token) => {
    try {
      const response = await fetch(constants.myndlaApiUrl, {
        headers: {
          FeideAuthorization: `Bearer ${token}`,
        },
      });
      if (response.ok) {
        return await response.json();
      }
      const responseBody = await response.json();
      winston.error(
        `[feide-sso] Got error when fetching user info. Got code ${response.code} with body: ${JSON.stringify(responseBody)}`,
      );
      return null;
    } catch (error) {
      throw Error(
        "[feide-sso] An error occurred while fetching userInfo",
        error,
      );
    }
  };

  Feide.getStrategy = (strategies, callback) => {
    winston.info("[feide-sso] Getting strategy...");
    meta.settings.get("sso-feide", (err, settings) => {
      Feide.settings = settings;

      if (err) {
        winston.error(
          "[feide-sso] Got error when fetching login strategy",
          err,
        );
      }

      if (!settings.id || !settings.secret) {
        winston.error(
          "[feide-sso] Missing client id or client secret for feide settings:",
          settings,
        );
      }

      if (!err && settings.id && settings.secret) {
        passport.use(
          "feide",
          new OpenIDConnectStrategy(
            {
              issuer: "https://auth.dataporten.no",
              authorizationURL:
                "https://auth.dataporten.no/oauth/authorization",
              tokenURL: "https://auth.dataporten.no/oauth/token",
              callbackURL: nconf.get("url") + "/auth/feide/callback",
              userInfoURL: "https://auth.dataporten.no/openid/userinfo",
              clientID: settings.id,
              clientSecret: settings.secret,
              scope:
                "email openid userinfo-photo groups-edu userinfo-language userid userinfo-name groups-org userid-feide",
              passReqToCallback: true,
              store: {
                verify(req, handle, cb) {
                  winston.info("[feide-sso] Passport store verify called...");
                  if (!req.session) {
                    return cb(
                      new Error(
                        "OpenID Connect requires session support. Did you forget to use `express-session` middleware?",
                      ),
                    );
                  }

                  const state = req.session.ssoState;
                  if (!state) {
                    winston.error(
                      "[feide-sso] No csrf state found in request...",
                    );
                    return cb(null, false, {
                      message: "Unable to verify authorization request state.",
                    });
                  }

                  if (state !== handle) {
                    winston.error(
                      "[feide-sso] Invalid csrf state found in request...",
                    );
                    return cb(null, false, {
                      message: "Invalid authorization request state.",
                    });
                  }

                  const ctx = {
                    maxAge: state.maxAge,
                    nonce: state.nonce,
                    issued: state.issued,
                  };
                  if (typeof ctx.issued === "string") {
                    ctx.issued = new Date(ctx.issued);
                  }

                  return cb(null, ctx, state.state);
                },
                store(req, ctx, appState, meta, cb) {
                  if (!req.session)
                    return cb(
                      new Error(
                        "OpenID Connect requires session support. Did you forget to use `express-session` middleware?",
                      ),
                    );
                  const key = this._key;
                  const handle = utils.uid(24);
                  const state = { handle: handle };
                  if (ctx.maxAge) {
                    state.maxAge = ctx.maxAge;
                  }
                  if (ctx.nonce) {
                    state.nonce = ctx.nonce;
                  }
                  if (ctx.issued) {
                    state.issued = ctx.issued;
                  }
                  if (appState) {
                    state.state = appState;
                  }
                  if (!req.session[key]) {
                    req.session[key] = {};
                  }
                  req.session[key].state = state;
                  cb(null, appState);
                },
              },
            },
            async (
              req,
              issuer,
              profile,
              context,
              idToken,
              accessToken,
              refreshToken,
              done,
            ) => {
              winston.info("[feide-sso] Passport strategy callback called...");
              const feideId = profile.id;
              const alreadyLoggedIn =
                Object.prototype.hasOwnProperty.call(req, "user") &&
                Object.prototype.hasOwnProperty.call(req.user, "uid") &&
                req.user.uid > 0;
              if (alreadyLoggedIn) {
                await User.setUserField(req.user.uid, "feideid", feideId);
                await db.setObjectField("feideid:uid", feideId, req.user.uid);
                return done(null, req.user);
              }

              const userInfo = await fetchUserInfo(accessToken);
              const user = await Feide.login(feideId, userInfo);
              authenticationController.onSuccessfulLogin(req, user.uid);
              done(null, user);
            },
          ),
        );

        strategies.push({
          name: "feide",
          url: "/auth/feide",
          callbackURL: "/auth/feide/callback",
          icon: constants.admin.icon,
          icons: {
            normal: "fa fa-fw fa-user",
            square: "fa fa-fw fa-user",
          },
          labels: {
            login: "Logg inn med Feide",
            register: "Registrer deg med Feide",
          },
          color: "#25292f",
          scope: "user:email",
        });
      }

      callback(null, strategies);
    });
  };

  Feide.appendUserHashWhitelist = (data, callback) => {
    data.whitelist.push("feideid");
    setImmediate(callback, null, data);
  };

  Feide.getAssociation = (data, callback) => {
    User.getUserField(data.uid, "feideid", (err, feideid) => {
      if (err) {
        winston.error("[feide-sso] Error in `Feide.getAssociation`.", err);
        return callback(err, data);
      }

      if (feideid) {
        data.associations.push({
          associated: true,
          name: constants.name,
          icon: constants.admin.icon,
          deauthUrl: nconf.get("url") + "/deauth/feide",
        });
      } else {
        data.associations.push({
          associated: false,
          url: nconf.get("url") + "/auth/feide",
          name: constants.name,
          icon: constants.admin.icon,
        });
      }

      callback(null, data);
    });
  };

  const updateEmailForUser = async (uid, email) => {
    winston.info(`[feide-sso] Setting and validating email for uid ${uid}...`);
    await User.setUserField(uid, "email", email);
    await User.setUserField(uid, "email:confirmed", 1);
  };

  const updateFeideIdForUser = async (uid, feideID, location) => {
    await User.setUserField(uid, "feideid", feideID);
    await db.setObjectField("feideid:uid", feideID, uid);
    await User.setUserField(uid, "location", location);
  };

  const mergeUserData = async (uid, displayName) => {
    const info = await User.getUserFields(uid, [
      "picture",
      "firstName",
      "lastName",
      "fullname",
    ]);
    if (!info.fullname && displayName) {
      User.setUserField(uid, "fullname", displayName);
    }
  };

  const updateUserData = async (uid, displayName, feideID, email, location) => {
    await updateFeideIdForUser(uid, feideID, location);
    await mergeUserData(uid, displayName);
    await updateEmailForUser(uid, email);
    return uid;
  };

  const getLocation = (userInfo) => {
    const primarySchoolGroup = userInfo.groups.find(
      (group) => group.isPrimarySchool,
    );
    if (primarySchoolGroup) return primarySchoolGroup.displayName;
    return userInfo.organization;
  };

  Feide.login = async (feideID, userInfo) => {
    const { email, displayName, username } = userInfo;
    const location = getLocation(userInfo);

    if (!email) {
      throw new Error("[feide-sso] Email not sent to `Feide.login`.");
    }

    const existingUid = await Feide.getUidByFeideID(feideID);
    if (existingUid) {
      winston.info(
        `[feide-sso] User '${existingUid}' already exists in the system for feideID '${feideID}'.`,
      );
      return { uid: existingUid };
    }

    winston.info(`[feide-sso] Creating new user for feideID '${feideID}'...`);
    const uidFromEmail = await User.getUidByEmail(email);
    if (uidFromEmail) {
      const resultUid = await updateUserData(
        uidFromEmail,
        displayName,
        feideID,
        email,
        location,
      );
      return { uid: resultUid };
    }

    if (Feide.settings.disableRegistration === "on") {
      winston.warn(
        "[feide-sso] Registration is disabled, but user tried to login.",
      );
      throw new Error("[[error:sso-registration-disabled, Feide]]");
    }

    const sanitizedUsername = sanitizeUsername(username);
    winston.info(
      `[feide-sso] No user with email username '${sanitizedUsername}' found. Creating new user...`,
    );
    const newUid = await User.create({ username: sanitizedUsername });
    winston.info(`[feide-sso] New user created with uid: ${newUid}`);
    const resultUid = await updateUserData(
      newUid,
      displayName,
      feideID,
      email,
      location,
    );
    return { uid: resultUid };
  };

  Feide.getUidByFeideID = async (feideID) => {
    winston.info(`[feide-sso] Getting UID by for feideID: '${feideID}'...`);
    return db.getObjectField("feideid:uid", feideID);
  };

  Feide.addMenuItem = (custom_header, callback) => {
    winston.info("[feide-sso] Adding menu item...");
    custom_header.authentication.push({
      route: constants.admin.route,
      icon: constants.admin.icon,
      name: constants.name,
    });

    callback(null, custom_header);
  };

  Feide.init = (data, callback) => {
    winston.info("[feide-sso] Initializing...");
    const hostHelpers = require.main.require("./src/routes/helpers");

    hostHelpers.setupAdminPageRoute(
      data.router,
      "/admin/plugins/sso-feide",
      (req, res) => {
        res.render("admin/plugins/sso-feide", {
          title: constants.name,
          callbackURL: nconf.get("url") + "/auth/feide/callback",
        });
      },
    );

    hostHelpers.setupPageRoute(
      data.router,
      "/deauth/feide",
      [data.middleware.requireUser],
      (req, res) => {
        res.render("plugins/sso-feide/deauth", {
          service: "Feide",
        });
      },
    );
    data.router.post(
      "/deauth/feide",
      [data.middleware.requireUser, data.middleware.applyCSRF],
      (req, res, next) => {
        Feide.deleteUserData(
          {
            uid: req.user.uid,
          },
          (err) => {
            if (err) {
              return next(err);
            }

            res.redirect(nconf.get("relative_path") + "/me/edit");
          },
        );
      },
    );

    callback();
  };

  Feide.deleteUserData = (data, callback) => {
    const uid = data.uid;
    winston.info(`[feide-sso] Deleting user data for uid: '${uid}'...`);

    async.waterfall(
      [
        async.apply(User.getUserField, uid, "feideid"),
        (oAuthIdToDelete, next) => {
          db.deleteObjectField("feideid:uid", oAuthIdToDelete, next);
        },
        async.apply(db.deleteObjectField, "user:" + uid, "feideid"),
      ],
      (err) => {
        if (err) {
          winston.error(
            "[feide-sso] Could not remove OAuthId data for uid " +
              uid +
              ". Error: " +
              err,
          );
          return callback(err);
        }
        callback(null, uid);
      },
    );
  };

  module.exports = Feide;
})(module);
