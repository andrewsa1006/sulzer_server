const mysql = require("mysql");

let connection = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE,
});

connection.query(`
CREATE TABLE IF NOT EXISTS user (
  id int NOT NULL AUTO_INCREMENT,
  email varchar(45) NOT NULL,
  password varchar(500) NOT NULL,
  first_name varchar(45) NOT NULL,
  company varchar(45) NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY email_UNIQUE (email)
)`);

module.exports = connection;
