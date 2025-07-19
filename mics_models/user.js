const db = require("../config/db");
const bcrypt = require("bcryptjs");

const User = {
  create: async (userData) => {
    try {
      const {
        firstName,
        lastName,
        username,
        ssn,
        email,
        password,
        phone,
        countryCode,
        role,
      } = userData;

      // Validate required fields
      if (!password) {
        throw new Error("Password is required");
      }

      // Hash the password
      const hashedPassword = await bcrypt.hash(password, 10);

      const result = await db.query(
        "INSERT INTO users (first_name, last_name, username, ssn, email, password, phone, country_code, role) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *",
        [
          firstName,
          lastName,
          username,
          ssn,
          email,
          hashedPassword,
          phone,
          countryCode,
          role,
        ]
      );
      
      // Remove password from returned user object
      const user = result.rows[0];
      delete user.password;
      
      return user;
    } catch (error) {
      console.error("Error creating user:", error);
      throw error;
    }
  },

  findByUsername: async (username) => {
    try {
      const result = await db.query(
        "SELECT * FROM users WHERE username = $1 AND deleted_at IS NULL",
        [username]
      );
      return result.rows[0];
    } catch (error) {
      console.error("Error finding user by username:", error);
      throw error;
    }
  },

  findByEmail: async (email) => {
    try {
      const result = await db.query(
        "SELECT * FROM users WHERE email = $1 AND deleted_at IS NULL",
        [email]
      );
      return result.rows[0];
    } catch (error) {
      console.error("Error finding user by email:", error);
      throw error;
    }
  },

  findById: async (id) => {
    try {
      const result = await db.query(
        "SELECT * FROM users WHERE id = $1 AND deleted_at IS NULL",
        [id]
      );
      
      // Remove password from returned user object
      const user = result.rows[0];
      if (user) {
        delete user.password;
      }
      
      return user;
    } catch (error) {
      console.error("Error finding user by ID:", error);
      throw error;
    }
  },

  findBySSN: async (ssn) => {
    try {
      const result = await db.query(
        "SELECT * FROM users WHERE ssn = $1 AND deleted_at IS NULL",
        [ssn]
      );
      
      // Remove password from returned user object
      const user = result.rows[0];
      if (user) {
        delete user.password;
      }
      
      return user;
    } catch (error) {
      console.error("Error finding user by SSN:", error);
      throw error;
    }
  },

  getAllDoctors: async () => {
    try {
      const result = await db.query(
        "SELECT id, first_name, last_name, username, email, phone, status, ssn FROM users WHERE role = 'Doctor' AND deleted_at IS NULL"
      );
      return result.rows;
    } catch (error) {
      console.error("Error getting all doctors:", error);
      throw error;
    }
  },

  softDelete: async (id) => {
    try {
      const result = await db.query(
        "UPDATE users SET deleted_at = CURRENT_TIMESTAMP, status = $1 WHERE id = $2 RETURNING *",
        ["deleted", id]
      );
      
      // Remove password from returned user object
      const user = result.rows[0];
      if (user) {
        delete user.password;
      }
      
      return user;
    } catch (error) {
      console.error("Error soft deleting user:", error);
      throw error;
    }
  },

  update: async (id, userData) => {
    try {
      const { firstName, lastName, username, phone } = userData;
      const result = await db.query(
        "UPDATE users SET first_name = $1, last_name = $2, username = $3, phone = $4, updated_at = CURRENT_TIMESTAMP WHERE id = $5 RETURNING *",
        [firstName, lastName, username, phone, id]
      );
      
      // Remove password from returned user object
      const user = result.rows[0];
      if (user) {
        delete user.password;
      }
      
      return user;
    } catch (error) {
      console.error("Error updating user:", error);
      throw error;
    }
  },

  updatePassword: async (id, newPassword) => {
    try {
      if (!newPassword) {
        throw new Error("New password is required");
      }

      const hashedPassword = await bcrypt.hash(newPassword, 10);
      await db.query(
        "UPDATE users SET password = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2",
        [hashedPassword, id]
      );
      return true;
    } catch (error) {
      console.error("Error updating password:", error);
      throw error;
    }
  },

authenticate: async (email, password) => {
  try {
    if (!email || !password) {
      throw new Error("Email and password are required");
    }

    const user = await User.findByEmail(email);
    if (!user) {
      throw new Error("Invalid credentials");
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    
    if (!isPasswordValid) {
      throw new Error("Invalid credentialss");
    }

    // Remove password from returned user object
    const userWithoutPassword = { ...user };
    delete userWithoutPassword.password;

    return userWithoutPassword;
  } catch (error) {
    console.error("Authentication error:", error);
    throw error;
  }
},

  // Helper method to verify password (for sensitive operations)
  verifyPassword: async (userId, password) => {
    try {
      const user = await db.query(
        "SELECT password FROM users WHERE id = $1",
        [userId]
      );
      
      if (!user.rows[0]) {
        throw new Error("User not found");
      }

      return await bcrypt.compare(password, user.rows[0].password);
    } catch (error) {
      console.error("Error verifying password:", error);
      throw error;
    }
  }
};

module.exports = User;