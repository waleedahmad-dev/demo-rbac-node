const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const User = require("./models/User");
const Role = require("./models/Role");
const Permission = require("./models/Permission");
const checkPermissions = require("./middleware/checkPermissions");

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(bodyParser.json());

mongoose.connect("mongodb://localhost:27017/dynamicRolesApp", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// Middleware to verify JWT
const verifyToken = (req, res, next) => {
  const token = req.headers["authorization"];
  if (!token)
    return res.status(403).send("A token is required for authentication");
  try {
    req.user = jwt.verify(token, "SECRET_KEY");
    next();
  } catch (err) {
    res.status(401).send("Invalid Token");
  }
};

// Register a new user
app.post("/register", async (req, res) => {
  try {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, password: hashedPassword });
    await user.save();
    res.status(201).send("User registered successfully");
  } catch (err) {
    res.status(400).send(err.message);
  }
});

// Login a user
app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (user && (await bcrypt.compare(password, user.password))) {
      const token = jwt.sign(
        { userId: user._id, username: user.username },
        "SECRET_KEY",
        { expiresIn: "2h" }
      );
      res.json({ token });
    } else {
      res.status(400).send("Invalid Credentials");
    }
  } catch (err) {
    res.status(400).send(err.message);
  }
});

// Create a new role
app.post(
  "/roles",
  verifyToken,
  checkPermissions(["create_role"]),
  async (req, res) => {
    try {
      const { name } = req.body;
      const role = new Role({ name });
      await role.save();
      res.status(201).send("Role created successfully");
    } catch (err) {
      res.status(400).send(err.message);
    }
  }
);

// Assign permissions to a role
app.post(
  "/roles/:roleId/permissions",
  verifyToken,
  checkPermissions(["assign_permissions"]),
  async (req, res) => {
    try {
      const { roleId } = req.params;
      const { permissionIds } = req.body;
      const role = await Role.findById(roleId);
      role.permissions = permissionIds;
      await role.save();
      res.status(200).send("Permissions assigned to role successfully");
    } catch (err) {
      res.status(400).send(err.message);
    }
  }
);

// Assign roles to a user
app.post(
  "/users/:userId/roles",
  verifyToken,
  checkPermissions(["assign_roles"]),
  async (req, res) => {
    try {
      const { userId } = req.params;
      const { roleIds } = req.body;
      const user = await User.findById(userId);
      user.roles = roleIds;
      await user.save();
      res.status(200).send("Roles assigned to user successfully");
    } catch (err) {
      res.status(400).send(err.message);
    }
  }
);

// Protected route example
app.get(
  "/admin",
  verifyToken,
  checkPermissions(["access_admin"]),
  (req, res) => {
    res.send("Welcome to the admin panel");
  }
);

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
