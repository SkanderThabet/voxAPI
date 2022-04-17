const express = require("express");
const router = express.Router();
const User = require("../models/User");
const bcryptjs = require("bcryptjs");
const user_jwt = require("../middleware/user_jwt");
const jwt = require("jsonwebtoken");
var slugify = require("slugify");
const { token } = require("morgan");
const sendEmail = require("../utils/email");
const crypto = require("crypto");

router.get("/", user_jwt, async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id).select("-password");
    res.status(200).json({
      success: true,
      user: user,
    });
  } catch (error) {
    console.log(error.message);
    res.status(500).json({
      success: false,
      msg: "Server error",
    });
    next();
  }
});
/**
 * API : Post
 * Registration
 */

router.post("/register", async (req, res, next) => {
  const { email, password, firstname, lastname, dob, avatar } = req.body;

  try {
    let user_exist = await User.findOne({ email: email });
    if (user_exist) {
      return res.status(400).json({
        success: false,
        msg: "User already exists",
      });
    }
    let user = new User();

    user.email = email;
    user.firstname = firstname;
    user.lastname = lastname;
    user.dob = dob;
    user.avatar = avatar;

    const salt = await bcryptjs.genSalt(10);
    user.password = await bcryptjs.hash(password, salt);

    let size = 200;

    user.username = slugify(`${firstname} ${lastname}`, {
      replacement: "_",
      lower: true,
    });

    await user.save();

    const payload = {
      user: {
        id: user.id,
      },
    };

    /**
     * Generating token for newly registered users
     */

    jwt.sign(
      payload,
      process.env.jwtUserSecret,
      {
        expiresIn: 360000,
      },
      (err, token) => {
        if (err) throw err;

        res.status(200).json({
          success: true,
          msg: "User registered",
          token: token,
        });
      }
    );
  } catch (error) {
    console.log(error);
    res.status(402).json({
      success: false,
      msg: "Something error occured",
    });
  }
});

/**
 * API : POST
 *  Login
 */

router.post("/login", async (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;

  try {
    let user = await User.findOne({
      email: email,
    });

    if (!user) {
      return res.status(400).json({
        success: false,
        msg: "User does not exists",
      });
    }

    const isMatch = await bcryptjs.compare(password, user.password);

    if (!isMatch) {
      return res.status(400).json({
        success: false,
        msg: "Wrong password ! Try again.",
      });
    }

    const payload = {
      user: {
        id: user.id,
      },
    };

    jwt.sign(
      payload,
      process.env.jwtUserSecret,
      {
        expiresIn: 36000,
      },
      (error, token) => {
        if (error) throw error;

        res.status(200).json({
          success: true,
          msg: "User logged in",
          token: token,
          user: user,
        });
      }
    );
  } catch (error) {
    console.log(error.message);
    res.status(500).json({
      success: false,
      msg: "Server error",
    });
  }
});

/**
 * API : GET ALL Users
 */

router.get("/allUsers", async (req, res, next) => {
  const users = await User.find().select("-password");

  res.status(200).json({
    status: "success",
    result: users.length,
    data: {
      users,
    },
  });
});

/**
 * API : Forgot Password
 */

router.post("/forgotPassword", async (req, res, next) => {
  const user = await User.findOne({ email: req.body.email });

  if (!user) {
    return res.status(404).json({
      success: false,
      msg: "There's no user with this email address",
    });
  }

  const resetToken = user.createPasswordResetToken();
  await user.save({ validateBeforeSave: false });

  const resetURL = `${req.protocol}://${req.get(
    "host"
  )}/api/vox/auth/resetPassword/${resetToken}`;

  const message = `Forgot your password ? Submit a PATCH request with your new password to : ${resetURL}.\nIf you didn't forget your password, please ignore this email`;

  try {
    await sendEmail({
      email: user.email,
      subject: "Your password reset token valid for 10 minutes",
      message,
    });

    res.status(200).json({
      status: "success",
      message: "Token sent to email",
    });
  } catch (error) {
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save({ validateBeforeSave: false });
    console.log(error);

    return res.status(500).json({
      success: false,
      msg: "There was an error sending the email, Try again later!",
    });
  }
});

/**
 * API : Reset Password
 */

router.patch("/resetPassword/:token", async (req, res, next) => {
  const password = req.body.password;
  const hashedToken = crypto
    .createHash("sha256")
    .update(req.params.token)
    .digest("hex");

  const user = await User.findOne({
    passwordResetToken: hashedToken,
    passwordResetExpires: { $gt: Date.now() },
  });

  if (!user) {
    return res.status(400).json({
      success: false,
      msg: "Token is not valid or has expired",
    });
  }
  const salt = await bcryptjs.genSalt(10);
  user.password = await bcryptjs.hash(password, salt);
  //   user.password = req.body.password;
  user.passwordResetToken = undefined;
  user.passwordResetExpires = undefined;
  await user.save();
  const payload = {
    user: {
      id: user.id,
    },
  };

  /**
   * Generating token for newly registered users
   */

  jwt.sign(
    payload,
    process.env.jwtUserSecret,
    {
      expiresIn: 360000,
    },
    (err, token) => {
      if (err) throw err;

      res.status(200).json({
        success: true,
        msg: "success",
        token: token,
      });
    }
  );
});

module.exports = router;
