// Bootstrap an express app to host our application
const express = require("express");
const passport = require("passport");
const session = require("express-session");
const { createClient } = require("redis");

// Connect to redis
const redisClient = createClient({
  host: process.env.REDIS_HOST,
  port: process.env.REDIS_PORT,
  password: process.env.REDIS_PASSWORD,
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
  cookie: { secure: true, maxAge: 60000, domain: process.env.COOKIE_DOMAIN },
});
const passportMiddleware = passport.session();

const createApp = () => {
  const app = express();

  // set up middleware required by passport
  app.use(express.bodyParser());
  app.use(sessionMiddleware);
  app.use(passportMiddleware);

  return app;
};

// This app will be exposed to the public to handle authentication
const publicApp = createApp();

publicApp.get(
  "/login",
  (req, res, next) => {
    if (!req.query.returnTo) {
      return res.status(400).send("Missing returnTo query parameter");
    }

    const redirectUrl = new URL(req.query.returnTo);

    if (
      !redirectUrl.host.endsWith(process.env.COOKIE_DOMAIN) ||
      redirectUrl.protocol !== "https"
    ) {
      return res.status(400).send("Invalid returnTo query parameter");
    }

    req.session.returnTo = req.query.returnTo;

    next();
  },
  passport.authenticate("google")
);

publicApp.get(
  "/oauth2/redirect/google",
  passport.authenticate("google"),
  (req, res) => {
    if (req.session.returnTo) {
      return res.redirect(req.session.returnTo);
    }

    res.status(500).end("Internal error");
  }
);

publicApp.listen(3000, () => {
  console.log("Public app listening on port 3000");
});

// This app will be exposed internally to validate authentication on requests forwarded by nginx
const privateApp = createApp();

privateApp.get("/", passport.authenticate("google"), (req, res) => {
  res.status(200).end("OK");
});

privateApp.listen(3001, () => {
  console.log("Private app listening on port 3001");
});
