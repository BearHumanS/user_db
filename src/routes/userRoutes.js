// src/routes/userRoutes.js
import express from "express";
import { register, login, logout } from "../controllers/userController.js";
import { authenticate } from "../middleware/authMiddleware.js";

const router = express.Router();

// 회원가입 API
router.post("/register", register);

// 로그인 API
router.post("/login", login);

// 로그아웃 API
router.post("/logout", authenticate, logout);

export default router;
