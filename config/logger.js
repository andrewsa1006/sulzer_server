const fs = require("fs");
const path = require("path");
const moment = require("moment");
const os = require("os");

const logMessage = (type, message) => {
  let messageToWrite = `Date: ${moment().format(
    "MMMM Do YYYY, h:mm:ss a"
  )} || Action: ${type.toUpperCase()} || Message: ${message}`;

  fs.appendFileSync(path.join(__dirname, "log.txt"), messageToWrite + os.EOL);
};

module.exports = logMessage;
