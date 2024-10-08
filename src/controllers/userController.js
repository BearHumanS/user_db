import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import pool from "../config/db.js";
import crypto from "crypto";
import nodemailer from "nodemailer";
import { v4 as uuidv4 } from "uuid";

const SECRET_KEY = process.env.JWT_SECRET_KEY;

// 이메일 발송 (OAuth2 설정)
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    type: "OAuth2",
    user: process.env.EMAIL_USER,
    clientId: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    refreshToken: process.env.REFRESH_TOKEN,
  },
});

// 이메일 인증 코드 발송 API
export const sendVerificationCode = async (req, res) => {
  const { email } = req.body;

  try {
    // 이미 존재하는 이메일인지 확인
    const [existingUser] = await pool.query(
      "SELECT 1 FROM users WHERE email = ? LIMIT 1",
      [email]
    );

    if (existingUser.length > 0) {
      return res.status(400).json({ message: "이미 등록된 이메일입니다." });
    }

    // 이전에 생성된 인증 코드가 있다면 삭제
    await pool.query("DELETE FROM email_verifications WHERE email = ?", [
      email,
    ]);

    // 인증 코드 생성
    const verificationCode = crypto
      .randomBytes(3)
      .toString("hex")
      .toUpperCase();

    // UTC 시간으로 현재 시간과 만료 시간 설정 (5분 뒤 만료)
    const nowUTC = new Date().toISOString().slice(0, 19).replace("T", " ");
    const expiresAtUTC = new Date(Date.now() + 5 * 60000)
      .toISOString()
      .slice(0, 19)
      .replace("T", " ");

    // 데이터베이스 또는 세션에 저장 (임시로 저장)
    await pool.query(
      "INSERT INTO email_verifications (email, verification_code,created_at, expires_at) VALUES (?, ?, ?, ?)",
      [email, verificationCode, nowUTC, expiresAtUTC]
    );

    const mailOption = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: "이메일 인증 코드입니다.",
      text: `이메일 인증 코드: ${verificationCode}`,
    };

    await transporter.sendMail(mailOption);

    res.status(200).json({ message: "인증코드가 발송되었습니다." });
  } catch (error) {
    console.error("인증코드 발송 에러:", error);
    res.status(500).json({ message: "Server error" });
  }
};

// 인증코드 확인 API
export const verifyCode = async (req, res) => {
  const { email, verificationCode } = req.body;

  try {
    const [codeEntry] = await pool.query(
      "SELECT verification_code, expires_at FROM email_verifications WHERE email = ? AND verification_code = ? AND expires_at > NOW()",
      [email, verificationCode]
    );

    if (codeEntry.length === 0) {
      return res
        .status(400)
        .json({ message: "유효하지 않거나 만료된 인증 코드입니다." });
    }

    // verified 필드 업데이트
    await pool.query(
      "UPDATE email_verifications SET verified = 1 WHERE email = ? AND verification_code = ?",
      [email, verificationCode]
    );

    res.status(200).json({ message: "인증코드가 확인되었습니다." });
  } catch (error) {
    console.error("인증 도중 에러 발생:", error);
    res.status(500).json({ message: error.message || "Server error" });
  }
};

// 회원가입 API
export const register = async (req, res) => {
  const { email, password, confirmPassword } = req.body;
  const connection = await pool.getConnection(); // 트랜잭션 사용을 위해 커넥션 가져오기

  try {
    await connection.beginTransaction(); // 트랜잭션 시작

    // 비밀번호와 비밀번호 확인 일치 여부 확인
    if (password !== confirmPassword) {
      await connection.rollback(); // 에러 발생 시 롤백
      return res.status(400).json({ message: "비밀번호가 일치하지 않습니다." });
    }

    // 이미 존재하는 이메일 확인
    const [existingUser] = await connection.query(
      "SELECT 1 FROM users WHERE email = ? LIMIT 1",
      [email]
    );
    if (existingUser.length > 0) {
      await connection.rollback(); // 에러 발생 시 롤백
      return res.status(400).json({ message: "이미 등록된 이메일입니다." });
    }

    // 인증이 완료되었는지 확인
    const [verifiedEntry] = await connection.query(
      "SELECT verified FROM email_verifications WHERE email = ? AND verified = 1",
      [email]
    );
    if (verifiedEntry.length === 0) {
      await connection.rollback(); // 에러 발생 시 롤백
      return res.status(400).json({ message: "이메일 인증이 필요합니다." });
    }

    // 비밀번호 해시화
    const hashedPassword = await bcrypt.hash(password, 10);

    // UUID 생성
    const userId = uuidv4(); // 사용자 ID로 UUID 사용

    // 사용자 등록
    await connection.query(
      "INSERT INTO users (id, email, password_hash, email_verified) VALUES (?, ?, ?, ?)",
      [userId, email, hashedPassword, true]
    );

    // 인증 기록 삭제 (사용 후 삭제)
    await connection.query("DELETE FROM email_verifications WHERE email = ?", [
      email,
    ]);

    // 인증된 이메일 기록
    await connection.query("INSERT INTO verified_emails (email) VALUES (?)", [
      email,
    ]);

    await connection.commit(); // 모든 쿼리가 성공했을 때 커밋

    // 회원가입 후 JWT 발급 (자동 로그인)
    const token = jwt.sign({ id: userId, email }, SECRET_KEY, {
      expiresIn: "1h", // 토큰 유효기간 설정
    });

    // 세션 저장
    await connection.query(
      "INSERT INTO sessions (user_id, session_token, expires_at) VALUES (?, ?, ?)",
      [userId, token, new Date(Date.now() + 3600000)] // 1시간 유효기간
    );

    // JWT를 HttpOnly 쿠키로 설정하여 클라이언트에게 전달
    res.cookie("token", token, {
      httpOnly: true, // 자바스크립트에서 접근 불가
      secure: true, // 프로덕션에서는 HTTPS를 사용
      sameSite: "strict", // CSRF 방지
      maxAge: 3600000, // 쿠키 만료 시간 (1시간)
    });

    res.status(201).json({ message: "회원가입 및 로그인 성공" });
  } catch (error) {
    await connection.rollback(); // 에러 발생 시 롤백
    console.error("회원가입 중 오류:", error);
    res.status(500).json({ message: "Server error" });
  } finally {
    connection.release(); // 커넥션 반환
  }
};

// 로그인 API (JWT 발급)
export const login = async (req, res) => {
  const { email, password } = req.body;

  try {
    // 사용자 조회
    const [rows] = await pool.query(
      "SELECT id, email, password_hash FROM users WHERE email = ? LIMIT 1",
      [email]
    );
    const user = rows[0];

    // 사용자가 없거나 비밀번호가 잘못된 경우
    if (!user) {
      return res
        .status(401)
        .json({ message: "유효하지않은 이메일 또는 비밀번호입니다." });
    }

    // 비밀번호 해시를 문자열로 변환
    const passwordHash = user.password_hash.toString();

    // 비밀번호 비교
    if (!(await bcrypt.compare(password, passwordHash))) {
      return res
        .status(401)
        .json({ message: "유효하지않은 이메일 또는 비밀번호입니다." });
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
      secure: true, // HTTPS에서만 전송 (프로덕션 환경에서만)
      sameSite: "strict", // CSRF 방지
      maxAge: 3600000, // 쿠키 만료 시간 (1시간)
    });

    res.status(200).json({ message: "로그인 성공" });
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
      secure: true,
      sameSite: "strict",
    });

    res.status(200).json({ message: "Logout successful" });
  } catch (error) {
    console.error("Logout error:", error);
    res.status(500).json({ message: "Server error" });
  }
};

// 비밀번호 재설정 요청 API
export const requestPasswordReset = async (req, res) => {
  const { email } = req.body;

  try {
    // 이메일 존재 유무 체크
    const [user] = await pool.query("SELECT * FROM users WHERE email = ?", [
      email,
    ]);

    if (user.length === 0) {
      return res.status(404).json({ message: "이메일이 존재하지 않습니다." });
    }

    // 비밀번호 재설정 코드 생성
    const resetCode = crypto.randomBytes(3).toString("hex").toUpperCase();

    // UTC 시간으로 현재 시간과 만료 시간 설정 (5분 뒤 만료)
    const nowUTC = new Date().toISOString().slice(0, 19).replace("T", " ");
    const expiresAtUTC = new Date(Date.now() + 5 * 60000)
      .toISOString()
      .slice(0, 19)
      .replace("T", " ");

    // 비밀번호 재설정 요청 저장
    await pool.query(
      "INSERT INTO password_reset_requests (email, reset_code, created_at, expires_at) VALUES (?, ?, ?, ?)",
      [email, resetCode, nowUTC, expiresAtUTC] // nowUTC와 expiresAtUTC를 사용
    );

    // 이메일 인증 코드 전송
    const mailOptions = {
      from: process.env.EMAIL_FROM,
      to: email,
      subject: "비밀번호 재설정 인증 코드입니다",
      text: `비밀번호 재설정 인증 코드: ${resetCode}`,
    };

    await transporter.sendMail(mailOptions);
    res.status(200).json({ message: "인증코드가 발송되었습니다." });
  } catch (error) {
    console.error("요청 중에 발생한 에러:", error);
    res.status(500).json({ message: "Server error" });
  }
};
// 비밀번호 재설정 API
export const resetPassword = async () => {
  const { email, resetCode, newPassword } = req.body;
  try {
    // 유효한 비밀번호 재설정 요청 확인
    const [request] = await pool.query(
      "SELECT * FROM password_reset_requests WHERE email = ? AND reset_code = ? AND expires_at > NOW()",
      [email, resetCode]
    );

    if (request.length === 0) {
      return res
        .status(404)
        .json({ message: "유효하지 않거나 만료된 코드입니다." });
    }

    // 비밀번호 해시화
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // 비밀번호 업데이트
    await pool.query("UPDATE uesrs SET password_hash = ? WHERE email = ?", [
      hashedPassword,
      email,
    ]);

    // 재설정 요청 사용 후 삭제
    await pool.query(
      "DELETE FROM password_reset_requests WHERE email = ?, AND reset_code = ?",
      [email, resetCode]
    );

    res.status(200).json({ message: "패스워드 재설정이 완료되었습니다." });
  } catch (error) {
    console.error("재설정 요청 중에 발생한 에러", error);
    res.status(500).json({ message: "Server error" });
  }
};

// 회원탈퇴 API

export const deleteUser = async (req, res) => {
  const { userId } = req.params;

  try {
    const [result] = await pool.query("DELETE FROM users WHERE id = ?", [
      userId,
    ]);

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "사용자를 찾을 수 없습니다." });
    }

    res.status(200).json({ message: "탈퇴가 성공적으로 처리되었습니다." });
  } catch (error) {
    console.error("탈퇴 요청 중 에러 발생:", error);
    res.status(500).json({ message: "Server error" });
  }
};
