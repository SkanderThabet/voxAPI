const express = require("express");
// const colors = require("colors");
const morgan = require("morgan");
const dotenv = require("dotenv");
const connectDB = require("./config/db");
const swaggerUi = require("swagger-ui-express");
const YAML = require("yamljs");
const swaggerDocument = YAML.load("./swagger.yaml");

const app = express();

app.use(morgan("dev"));
app.use(express.json({}));
app.use(
  express.json({
    extended: true,
  })
);

dotenv.config({
  path: "./config/config.env",
});

connectDB();

// https://localhost:3000/api/vox/auth/register

app.use("/api/vox/auth", require("./routes/user"));

const PORT = process.env.PORT || 3000;

app.listen(PORT, console.log(`Server running on port ${PORT}`));

/**
 * API Documentation : Swagger
 */
app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerDocument));
