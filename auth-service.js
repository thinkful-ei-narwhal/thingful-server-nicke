const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const config = require("./src/config");

const AuthService = {
  getUserWithUserName(db, user_name) {
    return db("thingful_users").where({ user_name }).first();
  },
  comparePasswords(password, hash) {
    return bcrypt.compare(password, hash);
  },
  createJwt(subject, payload) {
    return jwt.sign(payload, config.JWT_TOKEN, {
      subject,
      algorithm: "HS256"
    });
  },
  verifyJwt(token) {
    return jwt.verify(token, config.JWT_TOKEN, { algorithms: ["HS256"] });
  }
};

module.exports = AuthService;