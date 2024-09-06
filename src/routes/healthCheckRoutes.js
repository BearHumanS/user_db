// src/routes/userRoutes.js
import express from "express";

const router = express.Router();

router.get("/", (req, res) => {
  res.status(200).send("OKKKK");
});

export default router;
