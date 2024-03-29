require("dotenv").config();
const express = require("express");
const cors = require("cors");
const user = require("./routes/user");
const fileUpload = require("express-fileupload");

const app = express();
const port = process.env.SERVER_PORT || 5000;

app.use(cors());
app.use(fileUpload());
app.use(express.json());

app.use("/api/user", user);

app.get("/", (req, res) => {
  res.sendStatus(200);
});

app.listen(port, () => {
  console.log(`Should be listening on ${port}`);
});
