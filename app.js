require("dotenv").config();
const express = require("express");
const cors = require("cors");
const user = require("./routes/user");

const app = express();
const port = process.env.SERVER_PORT || 5000;

app.use(cors());
app.use(express.json());

app.use("/api/user", user);

app.listen(port, () => {
  console.log(`Should be listening on ${port}`);
});
