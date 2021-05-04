const mongoose = require("mongoose");

const User = mongoose.model(
  "User",
  new mongoose.Schema({
    nom: String,
    prenom: String,
    email: String,
    numtel: String,
    password: String,
    roles: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Role",
    },
  })
);

module.exports = User;
