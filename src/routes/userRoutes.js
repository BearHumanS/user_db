// src/routes/userRoutes.js
import express from "express";
import {
  sendVerificationCode,
  register,
  login,
  logout,
  requestPasswordReset,
  resetPassword,
  verifyCode,
} from "../controllers/userController.js";
import { authenticate } from "../middleware/authMiddleware.js";

const router = express.Router();

// 이메일 인증 코드 발송 API
router.post("/verification", sendVerificationCode);

// 이메일 인증 확인 API
router.post("/verify", verifyCode);

// 회원가입 API
router.post("/register", register);

// 로그인 API
router.post("/login", login);

// 로그아웃 API
router.post("/logout", authenticate, logout);

// 비밀번호 재설정 인증 코드 발송 API
router.post("/request", requestPasswordReset);

// 비밀번호 재설정 API
router.post("/reset", resetPassword);

export default router;
