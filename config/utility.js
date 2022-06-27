const jwt = require("jsonwebtoken");
const secret = process.env.JWT_SECRET;

const utilityFunctions = {
  generateParamsForRegisterSES: (req) => {
    const { email, firstName, lastName, company } = req.body;

    let params = {
      Destination: {
        ToAddresses: ["andrewsa1006@gmail.com"],
      },
      Message: {
        Body: {
          Html: {
            Charset: "UTF-8",
            Data: `
            <h2>User sign up notification</h2> 
            <h4>${email}</h4>
            <h5>${firstName} ${lastName} with ${company} has just registered for a new account.</h5>
            <br>
            <br>
            <p>This is an automated message sent from an unmonitored mailbox. Please do not respond.</p>
            `,
          },
        },
        Subject: {
          Charset: "UTF-8",
          Data: `${email} Sign Up`,
        },
      },
      Source: "andrewsiftco@gmail.com",
      SourceArn:
        "arn:aws:ses:us-east-1:736572217294:identity/andrewsiftco@gmail.com",
    };

    return params;
  },

  signToken: (user) => {
    return jwt.sign({ user: user }, secret);
  },

  verifyToken: (req, res, next) => {
    const token = req.body.token;
    jwt.verify(token, secret, (err, decoded) => {
      if (decoded) {
        req.body.verifyEmail = decoded.user.email;
        next();
      } else {
        res.json({ status: 401, msg: "Unauthorized" });
        logMessage(
          "Unauthorized Access Attempt",
          `Invalid access attempt on ${req.body.email}. Invalid JWT.`
        );
      }
    });
  },
};

module.exports = utilityFunctions;
