const jwt = require("jsonwebtoken"); // Mengimpor modul jsonwebtoken untuk bekerja dengan JWT
require("dotenv").config(); // Mengimpor dan mengkonfigurasi dotenv untuk memuat variabel lingkungan dari file .env

// Middleware untuk mengautentikasi token JWT
const authenticateToken = (req, res, next) => {
  // Mendapatkan token dari header Authorization dan memisahkannya dari skema Bearer
  const token = req.header("Authorization")?.split(" ")[1];

  // Jika token tidak ada, mengembalikan respon status 401 (Unauthorized)
  if (!token)
    return res
      .status(401)
      .json({ message: "Access denied, no token provided" });

  try {
    // Memverifikasi token dengan kunci rahasia yang disimpan dalam variabel lingkungan
    const verified = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
    // Menyimpan informasi pengguna yang terverifikasi dalam request object
    req.user = verified;
    // Melanjutkan ke middleware berikutnya
    next();
  } catch (error) {
    // Jika token tidak valid, mengembalikan respon status 400 (Bad Request)
    res.status(400).json({ message: "Invalid token" });
  }
};

// Middleware untuk mengotorisasi pengguna berdasarkan peran (role)
const authorizeRole = (role) => (req, res, next) => {
  // Memeriksa apakah peran pengguna sesuai dengan peran yang dibutuhkan
  if (req.user.role !== role)
    return res
      .status(403)
      .json({ message: "Access denied, insufficient privileges" });
  // Melanjutkan ke middleware berikutnya
  next();
};

module.exports = { authenticateToken, authorizeRole }; // Mengekspor middleware untuk digunakan di bagian lain dari aplikasi
