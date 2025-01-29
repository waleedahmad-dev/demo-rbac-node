const User = require("../models/User");
const Role = require("../models/Role");
const Permission = require("../models/Permission");

const checkPermissions = (requiredPermissions) => {
  return async (req, res, next) => {
    try {
      // Get the user ID from the request (set by verifyToken middleware)
      const userId = req.user.userId;

      // Find the user and populate their roles and permissions
      const user = await User.findById(userId).populate({
        path: "roles",
        populate: {
          path: "permissions",
          model: "Permission",
        },
      });

      if (!user) {
        return res.status(404).send("User not found");
      }

      // Extract all permissions from the user's roles
      const userPermissions = user.roles.reduce((acc, role) => {
        return acc.concat(
          role.permissions.map((permission) => permission.name)
        );
      }, []);

      // Check if the user has all the required permissions
      const hasPermission = requiredPermissions.every((permission) =>
        userPermissions.includes(permission)
      );

      if (!hasPermission) {
        return res
          .status(403)
          .send("Access denied. You do not have the required permissions.");
      }

      // If the user has the required permissions, proceed to the next middleware/route
      next();
    } catch (err) {
      res.status(500).send("Internal Server Error");
    }
  };
};

module.exports = checkPermissions;
