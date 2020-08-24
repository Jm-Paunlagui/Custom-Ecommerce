const mongoose = require('mongoose');
const crypto = require("crypto");

const UserSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
    unique: true, // Unique email for each user
  },
  hashed_password: {
    type: String,
    required: true,
  },
  avatar: {
    // User Image
    type: String,
  },
  role: {
    // Role of user it will be (normal or admin )
    type: Number,
    default: 0,
  },
  history: {
    // order history
    type: Array,
    default: [],
  },
  resetPasswordLink: {
    data: String,
    default: "",
  },
  salt: String,
});

// virtual
UserSchema
  .virtual("password")
  .set(function (password) {
    this._password = password;
    this.salt = this.makeSalt();
    this.hashed_password = this.encryptPassword(password);
  })
  .get(function () {
    return this._password;
  });

// methods
UserSchema.methods = {
  authenticate: function (plainText) {
    return this.encryptPassword(plainText) === this.hashed_password;
  },

  encryptPassword: function (password) {
    if (!password) return "";
    try {
      return crypto
        .createHmac("sha1", this.salt)
        .update(password)
        .digest("hex");
    } catch (err) {
      return "";
    }
  },

  makeSalt: function () {
    return Math.round(new Date().valueOf() * Math.random()) + "";
  },
};

module.exports = User = mongoose.model('User', UserSchema )