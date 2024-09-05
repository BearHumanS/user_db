import jwt from "jsonwebtoken";

const SECRET_KEY = process.env.JWT_SECRET_KEY;

export const verifyToken = (req, res, next) => {
  const token = req.headers["authorization"]?.split(" ")[1];

  if (!token) {
    return res.status(403).json({ message: "Token required" });
  }

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: "Invalid token" });
    }

    req.user = decoded; // JWT의 payload에서 사용자 정보 저장
    next();
  });
};
