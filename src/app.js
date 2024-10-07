import express from "express";
import userRoutes from "./routes/userRoutes.js";
import healthCheckRoutes from "./routes/healthCheckRoutes.js";
import protectedRoutes from "./routes/protectedRoutes.js";
import cookieParser from "cookie-parser";
import cors from "cors";
import dotenv from "dotenv";
import helmet from "helmet";
import morgan from "morgan";

// 환경 변수 로드
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// 미들웨어 설정
app.use(express.json()); // JSON 요청 본문 파싱
app.use(cookieParser()); // 쿠키 파서 미들웨어 추가
app.use(helmet()); // 보안 관련 HTTP 헤더 설정
app.use(morgan("combined")); // 요청/응답 로깅

// CORS 설정
app.use(
  cors({
    origin: [
      "https://www.emotional.today",
      "https://api.emotional.today",
      "https://test.d2nn3b1ti2yjfk.amplifyapp.com",
    ],
    credentials: true, // 쿠키와 함께 요청을 보낼 수 있도록 허용
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"], // 허용할 메서드 설정
    allowedHeaders: ["Content-Type", "Authorization", "Set-Cookie"], // 요청에 허용할 헤더 설정
  })
);

// 사용자 관련 경로
app.use("/users", userRoutes);
// AWS Elastic BeansTalk 로드 벨런서 상태 체크
app.use("/", healthCheckRoutes);
// 사용자 관련 Route관리
app.use("/protected", protectedRoutes);

// 404 핸들링
app.use((_, res) => {
  res.status(404).json({ message: "Not Found" });
});

// 에러 핸들링 미들웨어
app.use((err, _, res) => {
  console.error(err.stack);
  res.status(500).json({ message: "Internal Server Error" });
});

// 서버 실행
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
