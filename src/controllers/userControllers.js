import mongoose from "mongoose";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { UserSchema } from "../models/userModel";

const User = mongoose.model("User", UserSchema);

export const loginRequired = (req, res, next) => {
  if (req.user) {
    next();
  } else {
    return res.status(401).json({ message: "Unauthorized user!" });
  }
};

export const register = (req, res) => {
  const newUser = new User(req.body); //parameter is the data inside the entered "body" -- like passing a json data or body from Postman
  newUser.hashPassword = bcrypt.hashSync(req.body.password, 10); //encrypting and passing the user entered pw, 10 is required for hashSync...
  newUser.save((err, user) => {
    if (err) {
      return res.status(400).send({
        message: err,
      });
    } else {
      user.hashPassword = undefined;
      return res.json(user);
    }
  });
};

export const login = (req, res) => {
  User.findOne(
    {
      email: req.body.email,
    },
    (err, user) => {
      if (err) throw err;
      if (!user) {
        res
          .status(401)
          .json({ message: "Authentication failed. No user found." });
      } else if (user) {
        if (!user.comparePassword(req.body.password, user.hashPassword)) {
          res
            .status(401)
            .json({ message: "Authentication failed. Wrong Password." });
        } else {
          return res.json({
            token: jwt.sign(
              { email: user.email, username: user.username, _id: user.id },
              "RESTFULAPIs"
            ),
          });
        }
      }
    }
  );
};
