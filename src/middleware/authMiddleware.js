import jwt from "jsonwebtoken";

const SECRET_KEY = process.env.JWT_SECRET_KEY;

// 인증 미들웨어
export const authenticate = (req, res, next) => {
  // 쿠키에서 JWT 토큰을 가져옴
  const token = req.cookies.token;

  if (!token) {
    return res.status(401).json({ message: "Authentication required" });
  }

  try {
    // JWT 토큰 검증
    const decoded = jwt.verify(token, SECRET_KEY);
    req.user = decoded; // 사용자 정보 저장
    next(); // 다음 미들웨어로 넘어감
  } catch (error) {
    return res.status(401).json({ message: "Invalid token" });
  }
};
