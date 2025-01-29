const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const userSchema = new Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  roles: [{ type: Schema.Types.ObjectId, ref: "Role" }],
});

module.exports = mongoose.model("User", userSchema);
