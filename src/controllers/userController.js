import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import pool from "../config/db.js";

const SECRET_KEY = process.env.JWT_SECRET_KEY;

// 사용자 등록 API
export const register = async (req, res) => {
  const { email, password } = req.body;

  try {
    // 먼저 이메일이 이미 존재하는지 확인
    const [existingUser] = await pool.query(
      "SELECT * FROM users WHERE email = ?",
      [email]
    );

    if (existingUser.length > 0) {
      return res.status(400).json({ message: "Email already registered" });
    }

    // 비밀번호 해시화
    const hashedPassword = await bcrypt.hash(password, 10);

    // 새 사용자 등록
    const [result] = await pool.query(
      "INSERT INTO users (email, password_hash, email_verified) VALUES (?, ?, ?)",
      [email, hashedPassword, false]
    );

    res
      .status(201)
      .json({ message: "User registered", userId: result.insertId });
  } catch (error) {
    console.error("Error during registration:", error);
    res.status(500).json({ message: "Server error" });
  }
};

// 로그인 API (JWT 발급)
export const login = async (req, res) => {
  const { email, password } = req.body;

  try {
    // 사용자 조회
    const [rows] = await pool.query("SELECT * FROM users WHERE email = ?", [
      email,
    ]);
    const user = rows[0];

    // 사용자가 없거나 비밀번호가 잘못된 경우
    if (!user) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    // 비밀번호 해시를 문자열로 변환
    const passwordHash = user.password_hash.toString();

    // 비밀번호 비교
    if (!(await bcrypt.compare(password, passwordHash))) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    // JWT 발급
    const token = jwt.sign({ id: user.id, email: user.email }, SECRET_KEY, {
      expiresIn: "1h",
    });

    // 세션 저장
    await pool.query(
      "INSERT INTO sessions (user_id, session_token, expires_at) VALUES (?, ?, ?)",
      [user.id, token, new Date(Date.now() + 3600000)] // 1시간 유효기간
    );

    // 로그인 성공 기록
    await pool.query(
      "INSERT INTO login_attempts (user_id, attempted_at, success) VALUES (?, NOW(), ?)",
      [user.id, 1] // 성공 기록
    );

    // JWT를 HttpOnly 쿠키로 설정
    res.cookie("token", token, {
      httpOnly: true, // 클라이언트에서 자바스크립트로 접근 불가
      secure: process.env.NODE_ENV === "production", // HTTPS에서만 전송 (프로덕션 환경에서만)
      sameSite: "strict", // CSRF 방지
      maxAge: 3600000, // 쿠키 만료 시간 (1시간)
    });

    res.status(200).json({ message: "Login successful" });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ message: "Server error" });
  }
};

// 로그아웃 API (세션 삭제)
export const logout = async (req, res) => {
  const token = req.cookies.token; // 쿠키에서 JWT 토큰 가져오기

  try {
    const [result] = await pool.query(
      "DELETE FROM sessions WHERE session_token = ?",
      [token]
    );

    if (result.affectedRows === 0) {
      return res.status(400).json({ message: "Session not found" });
    }

    // 로그아웃 시 쿠키에서 토큰 삭제
    res.clearCookie("token", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
    });

    res.status(200).json({ message: "Logout successful" });
  } catch (error) {
    console.error("Logout error:", error);
    res.status(500).json({ message: "Server error" });
  }
};
