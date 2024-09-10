import express from "express";
import { authenticate } from "./middlewares/authenticate";

const router = express.Router();

// 프로필 라우트
router.get("/profile", authenticate, (req, res) => {
  res.json({ message: "Profile data", user: req.user });
});

// 대시보드 라우트
router.get("/dashboard", authenticate, (req, res) => {
  res.json({ message: "Dashboard data", user: req.user });
});

// 프로필 라우트
router.get("/", authenticate, (req, res) => {
  res.json({ message: "Main data", user: req.user });
});

export default router;
