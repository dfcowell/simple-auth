// Bootstrap an express app to host our application
const express = require("express");
const passport = require("passport");
const session = require("express-session");
const { createClient } = require("redis");
const morgan = require("morgan");

// Connect to redis
const redisClient = createClient({
  url: `redis://${process.env.REDIS_HOST}:${process.env.REDIS_PORT}`,
});
redisClient.connect().catch(console.error);

// set up session store
const RedisStore = require("connect-redis").default;
const sessionStore = new RedisStore({ client: redisClient });

// set up passport
const GoogleStrategy = require("passport-google-oauth20").Strategy;
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
    },
    function (accessToken, refreshToken, profile, cb) {
      if (profile.emails[0].value !== process.env.GOOGLE_AUTHORIZED_EMAIL) {
        return cb(null, false);
      }

      // here we would normally store the user in a database
      // and then return the user object
      return cb(null, profile);
    }
  )
);

// serialize the user into the session
passport.serializeUser(function (user, cb) {
  cb(null, JSON.stringify(user));
});

// deserialize the user from the session
passport.deserializeUser(function (obj, cb) {
  cb(null, JSON.parse(obj));
});

const sessionMiddleware = session({
  store: sessionStore,
  secret: process.env.SESSION_SECRET,
  resave: true,
  saveUninitialized: true,
  cookie: {
    secure: true,
    maxAge: 60000,
    domain: process.env.COOKIE_DOMAIN,
    sameSite: "none",
  },
});
const passportMiddleware = passport.session();

const createApp = (name) => {
  const app = express();

  if (process.env.NUMBER_OF_REVERSE_PROXIES) {
    // trust one layer of reverse proxies
    app.set("trust proxy", parseInt(process.env.NUMBER_OF_REVERSE_PROXIES, 10));
  }

  // set up middleware required by passport
  app.use(sessionMiddleware);
  app.use(passportMiddleware);
  app.use(
    morgan(
      `[${name}] :remote-addr - :remote-user [:date[clf]] ":method :url HTTP/:http-version" :status :res[content-length] ":referrer" ":user-agent"`
    )
  );

  return app;
};

// This app will be exposed to the public to handle authentication
const publicApp = createApp("public");

publicApp.get(
  "/login",
  (req, res, next) => {
    if (!req.query.returnTo) {
      return res.status(400).send("Missing returnTo query parameter");
    }

    const redirectUrl = new URL(req.query.returnTo);

    if (
      !redirectUrl.host.endsWith(process.env.COOKIE_DOMAIN) ||
      redirectUrl.protocol !== "https:"
    ) {
      console.log(
        `Invalid returnTo query parameter: ${req.query.returnTo}; ${redirectUrl.host}, ${redirectUrl.protocol}`
      );
      return res.status(400).send("Invalid returnTo query parameter");
    }

    req.session.returnTo = req.query.returnTo;

    next();
  },
  passport.authenticate("google", { scope: ["email", "profile"] })
);

publicApp.get("/oauth2/redirect/google", (req, res) => {
  if (!req.session.returnTo) {
    return res.status(500).end("Internal error");
  }

  const redirectUrl = new URL(req.session.returnTo);

  passport.authenticate("google", (err, user) => {
    if (err) {
      return res.status(401).end("Unauthorized");
    }

    res.redirect(redirectUrl);
  })(req, res);
});

publicApp.listen(3000, () => {
  console.log("Public app listening on port 3000");
});

// This app will be exposed internally to validate authentication on requests forwarded by nginx
const privateApp = createApp("private");

privateApp.get("/", (req, res) => {
  if (req.user) {
    return res.status(200).end("OK");
  }

  res.status(401).end("Unauthorized");
});

privateApp.listen(3001, () => {
  console.log("Private app listening on port 3001");
});
