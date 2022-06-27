// TODO - Additional Error handling for cases like duplicate user, DB constraints, the like

const express = require("express");
const bcrypt = require("bcryptjs");
const connection = require("../config/db");
const logMessage = require("../config/logger");
const utilityFunctions = require("../config/utility");
const fs = require("fs");
const AWS = require("aws-sdk");
AWS.config.update({ region: "us-east-1" });
const ses = new AWS.SES();
const s3 = new AWS.S3();

const Router = express();

// @API - REGISTER
Router.post("/register", (req, res) => {
  const { email, password, firstName, lastName, company } = req.body;
  const passwordAsString = password.toString();

  const salt = bcrypt.genSaltSync(10);
  const passwordHash = bcrypt.hashSync(passwordAsString, salt);

  let sql = `INSERT INTO user (email, password, first_name, last_name, company) VALUES (?, ?, ?, ?, ?)`;
  connection.query(
    sql,
    [
      email.toString(),
      passwordHash,
      firstName.toString(),
      lastName.toString(),
      company.toString(),
    ],
    (err, results, fields) => {
      if (err) {
        if (err.code === "ER_DUP_ENTRY") {
          return res.status(409).json({ msg: "Error: Email already in use." });
        } else {
          logMessage("Error", err.message);
          return res.status(400).json({
            msg: "An unexpected error occured. Please try again later or contact support.",
            err: err.message,
          });
        }
      }
      const user = {
        id: results.insertId,
        email,
        firstName,
        lastName,
        company,
      };

      const token = utilityFunctions.signToken(user);

      res.status(200).json({ msg: "Registration successful.", token, user });
      ses.sendEmail(
        utilityFunctions.generateParamsForRegisterSES(req),
        function (err, data) {
          if (err) console.log(err, err.stack); // an error occurred
          else console.log(data); // successful response
        }
      );
      logMessage("User Create", `User with email: ${email} created.`);
    }
  );
});

// @API - LOGIN
Router.post("/login", (req, res) => {
  const { email, password } = req.body;
  let sql = `SELECT * FROM user WHERE email = ?`;
  connection.query(sql, [email], (error, results, fields) => {
    if (error) throw error;
    if (results.length === 0)
      return res.status(404).json({ msg: "No user found." });
    bcrypt.compare(password, results[0].password, (err, success) => {
      if (success) {
        const user = {
          id: results[0].id,
          email: results[0].email,
          firstName: results[0].first_name,
          lastName: results[0].last_name,
          company: results[0].company,
        };
        const token = utilityFunctions.signToken(user);
        res.status(200).json({
          msg: "Success!",
          token,
          user,
        });
      } else {
        res.status(401).json({ msg: "Incorrect password" });
        logMessage("Error", `Invalid login attempt for ${email}`);
      }
    });
  });
});

Router.post("/upload", (req, res) => {
  const { email, data } = req.body;

  if (email) {
  } else {
    logMessage(
      "UNAUTHORIZED UPLOAD ATTEMPT",
      `Unauthorized attempt to upload pdf from email: ${email}`
    );
    res
      .status(401)
      .json({ msg: "Unauthorized request. Please sign out and sign back in." });
  }
});

// ---------- ALL Subsequent requests will use the token validation middleware ---------- \\
Router.use(utilityFunctions.verifyToken);

// @API - EDIT USER
Router.post("/edit/:id", (req, res) => {
  const { originalEmail, email, firstName, lastName, company, verifyEmail } =
    req.body;

  if (originalEmail === verifyEmail) {
    let sqlSelect = `SELECT id FROM user WHERE email = ?`;

    connection.query(sqlSelect, [originalEmail], (error, results, fields) => {
      if (error) {
        return res.status(500).json({
          msg: "An unexpected server error occured. Please try again later.",
        });
      }
      let id = results[0].id;

      let sqlUpdate = `UPDATE user SET email = ?, first_name = ?, last_name = ?, company = ? WHERE id = ?`;

      connection.query(
        sqlUpdate,
        [email, firstName, lastName, company, id],
        (error, results, fields) => {
          if (error) {
            logMessage("Error", error.message);
            return res.status(500).json({
              msg: "Error updating user. Please try again later.",
            });
          }

          const user = {
            id,
            email,
            firstName,
            lastName,
            company,
          };

          const token = utilityFunctions.signToken(user);

          if (results) {
            return res.status(200).json({
              msg: "Successfully updated user information.",
              token,
              user,
            });
          }
        }
      );
    });
  } else {
    logMessage(
      "UNAUTHORIZED ACCESS ATTEMPT",
      `Unauthorized attempt to edit user with email: ${email}`
    );

    res
      .status(401)
      .json({ msg: "Unauthorized request. Please sign out and sign back in." });
  }
});

// @API - DELETE USER
Router.delete("/delete/:id", (req, res) => {
  const { originalEmail, email, id } = req.body;
  if (originalEmail === email) {
    let sqlDelete = `DELETE FROM user WHERE id = ?`;

    connection.query(sqlDelete, [id], (error, results, fields) => {
      if (error) {
        logMessage("Error", error.message);
        res
          .status(500)
          .json({ msg: `Error removing user with email ${email}` });
      }
      res.send(results);
    });
  } else {
    logMessage(
      "UNAUTHORIZED ACCESS ATTEMPT",
      `Unauthorized attempt to delete user with email: ${email}`
    );
    res
      .status(401)
      .json({ msg: "Unauthorized request. Please sign out and sign back in." });
  }
});

// @API - RESET PASSWORD
Router.post("/reset/:id", (req, res) => {});

// @API - UPLOAD PDFS TO S3

module.exports = Router;
