require('dotenv').config(); // Add this at the top
const jwt = require("jsonwebtoken");
const User = require("../mics_models/user");

const authMiddleware = async (req, res, next) => {
  try {
    // 1. Get token from header
    const token = req.header("Authorization")?.replace("Bearer ", "");

    if (!token) {
      return res.status(401).json({
        status: false,
        message: "No token provided",
      });
    }

    // 2. Verify JWT_SECRET exists
    if (!process.env.JWT_SECRET) {
      throw new Error("JWT_SECRET is missing in environment variables");
    }

    // 3. Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    console.log("Decoded token:s", decoded);

    // 4. Find user (adjust based on your ORM)
    const user = await User.findOne({ 
      where: { id: decoded.id } // For Sequelize
     
    });

    if (!user) {
      return res.status(404).json({
        status: false,
        message: "User not found",
      });
    }

    // 5. Attach user to request
    req.user = user;
    next();
  } catch (error) {
    console.error("Authentication error:", error.message);

    let message = "Authentication failed";
    if (error.name === "JsonWebTokenError") {
      message = "Invalid token";
    } else if (error.message.includes("JWT_SECRET")) {
      message = "Server configuration error";
    }

    res.status(401).json({
      status: false,
      message,
      error: process.env.NODE_ENV === "development" ? error.message : undefined,
    });
  }
};

module.exports = authMiddleware;