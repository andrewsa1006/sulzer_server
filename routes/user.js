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
const axios = require("axios");
const { verifyTokenWithExp } = require("../config/utility");

const Router = express();

Router.get("/test", (req, res) => {
  console.log("Test Sucessful");
  res.json({ msg: "Test successful" });
});

// @API - REGISTER
Router.post("/register", (req, res) => {
  const { email, password, firstName, lastName, company } = req.body;
  const passwordAsString = password.toString();

  const salt = bcrypt.genSaltSync(10);
  const passwordHash = bcrypt.hashSync(passwordAsString, salt);

  let sql = `INSERT INTO user (email, password, first_name, last_name, company) VALUES (?, ?, ?, ?)`;
  connection.query(
    sql,
    [email.toString(), passwordHash, firstName.toString(), company.toString()],

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
      ses.sendEmail(utilityFunctions.generateParamsForRegisterSES(email, firstName, lastName, company), function (err, data) {
        if (err) console.log(err, err.stack); // an error occurred
        else console.log(data); // successful response
      });
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

    if (results.length === 0) return res.status(401).json({ msg: "Invalid email or password" });

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
        res.status(401).json({ msg: "Invalid email or password" });
        logMessage("Error", `Invalid login attempt for ${email}`);
      }
    });
  });
});

// @API - REQUEST PASSWORD RESET EMAIL
Router.post("/request", (req, res) => {
  const { email, firstName, lastName, company } = req.body;
  let sql = `SELECT email, first_name FROM user WHERE email = ? AND first_name = ? AND last_name = ? AND company = ?`;
  connection.query(sql, [email, firstName, lastName, company], (err, results) => {
    if (err) {
      console.log(err);
    } else {
      if (results.length > 0) {
        const user = results[0];

        const token = utilityFunctions.signTokenWithExp(user);

        const base64Token = Buffer.from(token, "utf-8").toString();
        console.log(base64Token);

        let URI = "https://localhost:5000/api/user/reset?token=" + base64Token;

        ses.sendEmail(utilityFunctions.generateParamsForPWReset(user, URI), function (err, data) {
          if (err) console.log(err, err.stack); // an error occurred
          else console.log(data); // successful response
        });
      }
    }
  });

  res.status(200).json({ msg: "Password reset email sent." });
});

// ---------- ALL Subsequent requests will use the token validation middleware ---------- \\
Router.use(utilityFunctions.verifyToken);

// @API - RESET PASSWORD
Router.get("/reset", (req, res) => {
  res.status(200);
});

Router.post("/reset", (req, res) => {
  const { verifyEmail, newPassword } = req.body;
  let passwordAsString = newPassword.toString();
  const salt = bcrypt.genSaltSync(10);
  const passwordHash = bcrypt.hashSync(passwordAsString, salt);

  let sql = `UPDATE user SET password = ? WHERE email = ?`;

  connection.query(sql, [verifyEmail, passwordHash], (err, results) => {
    if (err) console.log(err);
    console.log(results);
    res.sendStatus(200);
  });
});

// @API - EDIT USER
Router.post("/edit/:id", (req, res) => {
  const { originalEmail, email, firstName, lastName, company, verifyEmail } = req.body;

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

      connection.query(sqlUpdate, [email, firstName, lastName, company, id], (error, results, fields) => {
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
      });
    });
  } else {
    logMessage("UNAUTHORIZED ACCESS ATTEMPT", `Unauthorized attempt to edit user with email: ${email}`);

    res.status(401).json({ msg: "Unauthorized request. Please sign out and sign back in." });
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
        res.status(500).json({ msg: `Error removing user with email ${email}` });
      }
      res.send(results);
    });
  } else {
    logMessage("UNAUTHORIZED ACCESS ATTEMPT", `Unauthorized attempt to delete user with email: ${email}`);
    res.status(401).json({ msg: "Unauthorized request. Please sign out and sign back in." });
  }
});

// @API - UPLOAD PDFS AND SEND EMAIL
Router.post("/upload", (req, res) => {
  const user = {
    id: req.body.id,
    email: req.body.email,
    firstName: req.body.firstName,
    company: req.body.company,
  };

  const formData = {
    value1: req.body.value1,
    value2: req.body.value2,
    value3: req.body.value3,
    dropdown1: req.body.dropdown1,
    dropdown2: req.body.dropdown2,
    files: req.files?.pdfs,
  };

  if (user?.email) {
    ses.sendRawEmail(
      {
        RawMessage: {
          Data: utilityFunctions.generateEmailWithPDFAttachment(user, formData).toString(),
        },
      },
      (err, sesdata, response) => {
        if (err) console.log(err);
        if (sesdata) {
          res.status(200).json({ msg: "Request submitted" });
        }
        if (response) console.log("response ", response);
      }
    );
  } else {
    logMessage("UNAUTHORIZED UPLOAD ATTEMPT", `Unauthorized attempt to upload pdf from email: ${email}`);
    res.status(401).json({ msg: "Unauthorized request. Please sign out and sign back in." });
  }
});

module.exports = Router;
