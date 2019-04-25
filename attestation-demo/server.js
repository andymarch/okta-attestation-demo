require('dotenv').config()

const express = require("express");
const session = require("express-session");
const ExpressOIDC = require("@okta/oidc-middleware").ExpressOIDC;

let app = express();

// Globals
const OKTA_ISSUER_URI = process.env.OKTA_AUTHZ_SERVER;
const OKTA_CLIENT_ID = process.env.OKTA_CLIENT_ID;
const OKTA_CLIENT_SECRET = process.env.OKTA_CLIENT_SECRET;
const REDIRECT_URI = process.env.REDIRECT_URI;
const PORT = process.env.PORT || "3000";
const SECRET = process.env.SECRET;

// App settings
app.set("view engine", "pug");

// App middleware
app.use("/static", express.static("static"));

app.use(session({
  cookie: { httpOnly: true },
  secret: process.env.SESSION_SECRET
}));

let oidc = new ExpressOIDC({
  issuer: process.env.OKTA_AUTHZ_SERVER,
  client_id: process.env.OKTA_CLIENT_ID,
  client_secret: process.env.OKTA_CLIENT_SECRET,
  appBaseUrl: process.env.OKTA_REDIRECT_URI,
  redirect_uri: process.env.OKTA_REDIRECT_URI,
  routes: { loginCallback: { afterCallback: "/dashboard" } },
  scope: 'openid profile'
});

// App routes
app.use(oidc.router);

app.get("/", (req, res) => {
  res.render("index");
});

app.get("/dashboard", oidc.ensureAuthenticated(), (req, res) => {
  res.render("dashboard", {
     user: req.userContext.userinfo,
     token: req.userContext.tokens.id_token
    });
});

app.get("/attestation", oidc.ensureAuthenticated(), (req,res) => {
  var login_hint = req.userContext.userinfo.preferred_username;
  var oauth_nonce = "";

  //generate a reasonable nonce
  var possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  for(var i = 0; i < 13; i++) {
    oauth_nonce += possible.charAt(Math.floor(Math.random() * possible.length));
  }

  var nJwt = require('njwt');

  var request = {
      iss: process.env.OKTA_CLIENT_ID,
      aud: process.env.OKTA_BASE_URL,
      response_type: 'id_token',
      client_id: process.env.OKTA_CLIENT_ID,
      response_mode: 'fragment',
      acr_values: 'urn:okta:app:mfa:attestation',
      nonce: oauth_nonce,
      scope: 'openid',
      state: 'demo',
      login_hint: login_hint,
      redirect_uri: "http://localhost:"+PORT+"/attestation/callback"
  }

  var signedRequest = nJwt.create(request,process.env.OKTA_CLIENT_SECRET);

  res.redirect(
  process.env.OKTA_AUTHZ_SERVER.split('/oauth2')[0]+'/oauth2/v1/authorize'+
  '?request='+signedRequest.compact());
});
  
app.get("/attestation/callback", oidc.ensureAuthenticated(), (req,res) => {
  res.render("attestation",{ user: req.userContext.userinfo })
});

app.get("/logout", (req, res) => {
  req.logout();
  res.redirect("/");
});

oidc.on("ready", () => {
  console.log("Server running on port: " + PORT);
  app.listen(parseInt(PORT));
});

oidc.on("error", err => {
  console.error(err);
});