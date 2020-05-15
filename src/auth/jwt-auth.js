const AuthService = require("../../auth-service");

function jwtAuth(req, res, next) {
  const authToken = req.get("Authorization") || "";
  let bearerToken;
  let payload;
  if (!authToken.toLowerCase().startsWith("bearer ")) {
    return res.status(401).json({ error: "Missing bearer token" });
  }
  else {
    bearerToken = authToken.split(" ")[1];
  }

  try {
    payload = AuthService.verifyJwt(bearerToken);
  }
  catch (err) {
    return res.status(401);
  }

  AuthService.getUserWithUserName(
    req.app.get("db"),
    payload.sub
  )
    .then(user => {
      if (!user) {
        return res.status(401).json({ error: "Unauthorized request" });
      }
      req.user = user;
      next();
    })
    .catch(err => {
      console.error(err);
      next(err);
    });
}

module.exports = { jwtAuth };