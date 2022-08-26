// TODO - Prepare for production by changing the TO addresses in the email generation

const jwt = require("jsonwebtoken");
const mimemessage = require("mimemessage");
const fs = require("fs");
const logMessage = require("./logger");

const secret = process.env.JWT_SECRET;

const utilityFunctions = {
  // GENERATE PARAMS FOR REGISTRATION EMAIL FOR SES
  generateParamsForRegisterSES: (email, firstName, lastName, company) => {
    let params = {
      Destination: {
        ToAddresses: ["jp.distributions.signup@gmail.com"],
      },
      Message: {
        Body: {
          Html: {
            Charset: "UTF-8",
            Data: `
            <html>
              <head></head>
              <body>
                <h2>User sign up notification</h2> 
                <h4>${email}</h4>
                <h5>${firstName} ${lastName} with ${company} has just registered for a new account.</h5>
                <br>
                <br>
                <p>This is an automated message sent from an unmonitored mailbox. Please do not respond.</p>
               </body>
            </html>`,
          },
        },
        Subject: {
          Charset: "UTF-8",
          Data: `${email} Sign Up`,
        },
      },
      Source: "no-reply@no-reply.jpdistributions.link",
      SourceArn: "arn:aws:ses:us-east-1:938027577283:identity/jpdistributions.link",
    };

    return params;
  },

  // GENERATE PARAMS FOR PASSWORD RESET EMAIL FOR SES
  generateParamsForPWReset: (user, uri) => {
    let { email, first_name } = user;
    let params = {
      Destination: {
        ToAddresses: ["Steve.Keen@Sulzer.com"],
      },
      Message: {
        Body: {
          Html: {
            Charset: "UTF-8",
            Data: `
            <html>
              <head></head>
              <body>
                <h2>Password Reset Email</h2> 
                <h2>Hello ${first_name}</h2>
                <h3>Please use the below link to reset your password. This link will expire in 15 minutes. If you did not make this request, please ignore this email and reach out to support@support.com</h3>
                <br>
                <p>${uri}</p>
                <br>
                <p>This is an automated message sent from an unmonitored mailbox. Please do not respond.</p>
               </body>
            </html>`,
          },
        },
        Subject: {
          Charset: "UTF-8",
          Data: `Password reset for ${email}`,
        },
      },
      Source: "no-reply@jpdistributions.net",
      SourceArn: "arn:aws:ses:us-east-1:938027577283:identity/jpdistributions.net",
    };

    return params;
  },

  // CREATE EMAIL WITH PDF ATTACHMENT
  generateEmailWithPDFAttachment: (user, formData) => {
    let filesAsArr = [];
    if (formData.files) {
      filesAsArr = Array.from(formData.files);
    }
    const { email, firstName, company } = user;
    const mailContent = mimemessage.factory({
      contentType: "multipart/mixed",
      body: [],
    });

    mailContent.header("From", "Sulzer Notification <no-reply@jpdistributions.link>");
    mailContent.header("To", "andrewsa1006@gmail.com");
    mailContent.header("Subject", "New File Upload");

    const alternateEntity = mimemessage.factory({
      contentType: "multipart/alternate",
      body: [],
    });

    const htmlEntity = mimemessage.factory({
      contentType: "text/html;charset=utf-8",
      body: `
      <html>
        <head></head>
        <body>
          <h2>New upload from ${firstName} with ${company}</h2> 
          <h4>Email: ${email}</h4>
          <h5>Please find documents attached.</h5>
          <h1>${formData.value1}</h1>
          <br>
          <p>This is an automated message sent from an unmonitored mailbox. Please do not respond.</p>
         </body>
      </html>`,
    });

    alternateEntity.body.push(htmlEntity);
    mailContent.body.push(alternateEntity);

    // const info = formData.files;

    filesAsArr.forEach((file) => {
      let info = file.data;
      const attachmentEntity = mimemessage.factory({
        contentType: "text/plain",
        contentTransferEncoding: "base64",
        body: info.toString("base64").replace(/([^\0]{76})/g, "$1\n"),
      });

      attachmentEntity.header("Content-Disposition", `attachment; filename="${file.name}"`);
      mailContent.body.push(attachmentEntity);
    });

    return mailContent;
  },

  // CREATE JWT AND RETURN TO USER
  signToken: (user) => {
    return jwt.sign({ user }, secret);
  },

  signTokenWithExp: (user) => {
    return jwt.sign({ user }, secret, { expiresIn: 60 * 15 });
  },

  // VERIFY JWT IS VALID
  verifyToken: (req, res, next) => {
    const token = req.query.token || req.headers.token || req.body.token;
    jwt.verify(token, secret, (err, decoded) => {
      if (decoded) {
        req.body.verifyEmail = decoded.user.email;
        req.body.claim = decoded.claim;
        next();
      } else {
        res.json({ status: 401, msg: "Unauthorized" });
        logMessage(
          "Unauthorized Access Attempt",
          `Invalid access attempt on ${req.body.email}. ${err ? err.message.toUpperCase() : "Somethng went wrong."}.`
        );
      }
    });
  },
};

module.exports = utilityFunctions;
