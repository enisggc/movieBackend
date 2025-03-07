import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import pkg from "pg";






const { Pool } = pkg;


dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());


const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASS,
    port: process.env.DB_PORT
  });


  app.post("/auth/register", async(req,res)=>{
    console.log("Gelen body:", req.body);
    const {email , password} = req.body;
    
    if (!email || !password) {
        return res.status(400).json({ error: "Email ve şifre gereklidir." });
    }

    try {

        const userExists = await pool.query("SELECT * FROM users WHERE email = $1", [email]);

        if (userExists.rows.length > 0) {
            return res.status(400).json({ error: "Bu e-posta ile kayıtlı bir kullanıcı zaten var." });
        }
        const hashedPassword = await bcrypt.hash(password,10);
        console.log("Şifre hashlenmiş:", hashedPassword);
        const result  = await pool.query(
            "INSERT INTO users (email,password) VALUES ($1,$2) RETURNING id ",
            [email,hashedPassword]
        );
        console.log("Veritabanı sonucu:", result.rows);

        res.json({ message: "Kayıt başarılı", userId: result.rows[0].id });
    } catch (error) {
        console.error("Kayıt hatası:", error);
        res.status(500).json({ error: "Sunucu hatası" });
    }
  });


  app.post("/auth/login" , async(req,res)=>{
    const {email ,password} = req.body;

    try {
        console.log("Gelen login isteği:", { email, password });
        const result = await pool.query(
            "SELECT * FROM users WHERE email = $1" , [email]
        );
        if(result.rows.length===0) return res.status(401).json({ error: "Kullanıcı bulunamadı" });

        const user = result.rows[0];
        console.log("Veritabanından gelen kullanıcı:", user);
        const match = await bcrypt.compare(password,user.password);
        console.log("Şifre eşleşmesi sonucu:", match);
        if (!match) return res.status(401).json({ error: "Şifre yanlış" });

        const token = jwt.sign({userId : user.id}, process.env.JWT_SECRET , {expiresIn:"2h"});
        console.log("Token oluşturuldu:", token);
        res.json({token});

    } catch (error) {
        res.status(500).json({ error: "Sunucu hatası" });
    }
  });


  app.post("/movies/add-favorite" , async(req,res)=>{
    const {movie_id} = req.body;
    const token = req.headers.authorization;

    try {
        const decoded = jwt.verify(token , process.env.JWT_SECRET);
        await pool.query(
            "INSERT INTO favorites (user_id, movie_id) VALUES ON CONFLICT DO NOTHING",
            [decoded.userId , movie_id]
        );
        res.json({message : "Film favorilere eklendi"});
    } catch (error) {
        res.status(401).json({ error: "Yetkilendirme başarısız" });
    }
  });


  app.get("/movies/favorites" , async (req,res)=>{
    const token = req.headers.authorization;

    try {
        const decoded = jwt.verify(token,process.env.JWT_SECRET);
        const result = await pool.query("SELECT * FROM favorites WHERE user_id = $1" , [decoded.userId]);
        res.json(result.rows);
    } catch (error) {
        res.status(401).json({ error: "Yetkilendirme başarısız" });
    }
  });


  const PORT = 5002;
  app.listen(PORT, () => console.log(` Server ${PORT} portunda çalışıyor...`));