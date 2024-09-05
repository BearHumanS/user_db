import express from "express";
import userRoutes from "./routes/userRoutes.js";
import cookieParser from "cookie-parser";
import cors from "cors";

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json()); // JSON 요청 본문 파싱
app.use(cookieParser()); // 쿠키 파서 미들웨어 추가

app.use(
  cors({
    origin: process.env.URL, // 허용할 도메인 (필요에 따라 변경)
    credentials: true, // 쿠키와 함께 요청을 보낼 수 있도록 허용
  })
);

// 사용자 관련 경로
app.use("/users", userRoutes);

// 서버 실행
app.listen(PORT, () => {
  console.log(`Server is running on ${PORT}PORT`);
});
