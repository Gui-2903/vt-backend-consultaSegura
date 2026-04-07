const express = require("express");
const axios = require("axios");
const cors = require("cors");
const multer = require("multer");

const app = express();
const upload = multer();

app.use(cors());
app.use(express.urlencoded({ extended: true }));

const API_KEY = process.env.API_KEY;

// URL
app.post("/scan-url", async (req, res) => {
  try {
    const response = await axios.post(
      "https://www.virustotal.com/api/v3/urls",
      new URLSearchParams({ url: req.body.url }),
      {
        headers: {
          "x-apikey": API_KEY,
          "Content-Type": "application/x-www-form-urlencoded"
        }
      }
    );

    res.json(response.data);
  } catch (err) {
    res.status(500).json(err.response?.data || err.message);
  }
});

// FILE
app.post("/scan-file", upload.single("file"), async (req, res) => {
  try {
    const response = await axios.post(
      "https://www.virustotal.com/api/v3/files",
      req.file.buffer,
      {
        headers: {
          "x-apikey": API_KEY,
          "Content-Type": "application/octet-stream"
        }
      }
    );

    res.json(response.data);
  } catch (err) {
    res.status(500).json(err.response?.data || err.message);
  }
});

// ANALYSIS (polling de resultado)
app.get("/analysis/:id", async (req, res) => {
  try {
    const response = await axios.get(
      `https://www.virustotal.com/api/v3/analyses/${req.params.id}`,
      {
        headers: { "x-apikey": API_KEY }
      }
    );
    res.json(response.data);
  } catch (err) {
    res.status(500).json(err.response?.data || err.message);
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("rodando..."));
