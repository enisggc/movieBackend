import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import pkg from "pg";
import crypto from "crypto";
import nodemailer from "nodemailer";


const resetTokens = {};








const { Pool } = pkg;

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ limit: "50mb", extended: true }));


const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASS,
    port: process.env.DB_PORT
  });



  app.post("/auth/forgot-password", async (req, res) => {
    const { email } = req.body;
    try {
       const userResult = await pool.query("SELECT id FROM users WHERE email = $1", [email]); 

       if(userResult.rows.length === 0){
           return res.status(404).json({error: "Kullanıcı bulunamadı."});
       }

       const otpCode = crypto.randomInt(100000, 999999).toString();
         resetTokens[email] = { otpCode,userId: userResult.rows[0].id, expires: Date.now() + 10 * 60 * 1000 };

         console.log("🔑 Otp Kodu:", otpCode);


         const transporter = nodemailer.createTransport({
            service: "gmail",
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS
            },
        });

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: "Şifre Sıfırlama",
            text: `Şifrenizi sıfırlamak için bu kodu kullanın: ${otpCode}(10 dakika geçerlidir)`
        };


        await transporter.sendMail(mailOptions);
        res.json({ message: "Şifre sıfırlama kodu e-posta adresinize gönderildi." });
    } catch (error) {
        console.error("Şifre sıfırlama hatası:", error);
        res.status(500).json({ error: "Sunucu hatası" });
    }
});


app.post("/auth/reset-password", async (req, res) => {
    const { email, otp, newPassword } = req.body;
    try {
        if(!resetTokens[email]|| resetTokens[email].otpCode !== otp){
            return res.status(400).json({error: "Geçersiz veya süresi dolmuş şifre sıfırlama isteği."});
        }

        const hashedPassword = await bcrypt.hash(newPassword,10);
        await pool.query("UPDATE users SET password = $1 WHERE id = $2", [hashedPassword, resetTokens[email].userId]);

        delete resetTokens[email];
        res.json({ message: "Şifre sıfırlandı!" });
    } catch (error) {
        console.error("Şifre sıfırlama hatası:", error);
        res.status(500).json({ error: "Sunucu hatası" });   
    }
});



  app.post("/auth/register", async(req,res)=>{
    console.log("Gelen body:", req.body);
    const {email , password ,username} = req.body;
    
    if (!email || !password  || !username    ) {
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
            "INSERT INTO users (email,password,username) VALUES ($1,$2,$3) RETURNING id ",
            [email,hashedPassword,username]
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
            "SELECT id, username, email, profile_picture, password FROM users WHERE email = $1" , [email]
        );
        if(result.rows.length===0) return res.status(401).json({ error: "Kullanıcı bulunamadı" });

        const user = result.rows[0];
        console.log("Veritabanından gelen kullanıcı:", user);
        const match = await bcrypt.compare(password,user.password);
        console.log("Şifre eşleşmesi sonucu:", match);
        if (!match) return res.status(401).json({ error: "Şifre yanlış" });

        const token = jwt.sign({userId : user.id}, process.env.JWT_SECRET , {expiresIn:"7d"});
        console.log("Token oluşturuldu:", token);
        res.json({token , 
            user : {
                id:user.id,
                username:user.username,
                email:user.email,
                password:user.password
            }
        });

    } catch (error) {
        res.status(500).json({ error: "Sunucu hatası" });
    }
  });

  app.get("/auth/user", async (req, res) => {
    try {
        const token = req.headers.authorization?.split(" ")[1];
        if (!token) {
            return res.status(401).json({ error: "Token eksik" });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const userResult = await pool.query("SELECT id, username, email, profile_picture FROM users WHERE id = $1", [decoded.userId]);

        if (userResult.rows.length === 0) {
            return res.status(404).json({ error: "Kullanıcı bulunamadı" });
        }

        res.json(userResult.rows[0]);
    } catch (error) {
        console.error("Kullanıcı bilgisi alınırken hata:", error);
        res.status(500).json({ error: "Sunucu hatası" });
    }
});


  app.post("/movies/add-favorite" , async(req,res)=>{
    const {movie_id} = req.body;
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(" ")[1];

    console.log("📢 API'ye gelen film ID:", movie_id);
    console.log("📢 API'ye gelen token:", authHeader);

    if (!token) {
        return res.status(401).json({ error: "Yetkilendirme başarısız: Token eksik" });
    }
    
    

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        console.log("API'ye gelen token doğrulandı:", decoded);
        const result = await pool.query(
            "INSERT INTO favorites (user_id, movie_id) VALUES ($1 , $2) ON CONFLICT ON CONSTRAINT unique_favorite DO NOTHING RETURNING *",
            [decoded.userId , movie_id]
        );
        console.log("Favorilere ekleme sonucu:", result.rows);

        if (result.rows.length === 0) {
            return res.status(400).json({ error: "Film zaten favorilerde!" });
        }
        res.json({message : "Film favorilere eklendi",
            favorite: result.rows[0]
        });
    } catch (error) {
        console.error("JWT doğrulama hatası:", error);
        res.status(401).json({ error: "Yetkilendirme başarısız" });
    }
  });


  app.get("/movies/favorites" , async (req,res)=>{
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) {
        return res.status(401).json({ error: "Yetkilendirme başarısız: Token eksik" });
    }

    try {
        const decoded = jwt.verify(token,process.env.JWT_SECRET);
        console.log("Token doğrulandı, User ID:", decoded.userId);
        const result = await pool.query("SELECT * FROM favorites WHERE user_id = $1" , [decoded.userId]);
        res.json(result.rows);
    } catch (error) {
        console.error("Token doğrulama hatası:", error);
        res.status(401).json({ error: "Yetkilendirme başarısız" });
    }
  });

  app.delete("/movies/remove-favorite", async (req, res) => {
    const { movie_id } = req.body;
    const token = req.headers.authorization?.split(" ")[1];

    if (!token) {
        return res.status(401).json({ error: "Yetkilendirme başarısız: Token eksik" });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        console.log("Token doğrulandı, User ID:", decoded.userId);
        
        const result = await pool.query(
            "DELETE FROM favorites WHERE user_id = $1 AND movie_id = $2 RETURNING *",
            [decoded.userId, movie_id]
        );

        if (result.rows.length === 0) {
            return res.status(400).json({ error: "Film zaten favorilerde değil!" });
        }

        res.json({ message: "Film favorilerden kaldırıldı" });
    } catch (error) {
        console.error("Favori silme hatası:", error);
        res.status(500).json({ error: "Sunucu hatası" });
    }
});


app.get("/users" , async(req,res)=>{
    try {
        const result = await pool.query("SELECT id, username, bio, favorite_genre, profile_picture FROM users");
        res.json(result.rows);
    } catch (error) {
        console.error("Kullanıcılar alınamadı:", error);
        res.status(500).json({ error: "Sunucu hatası." });
    }
})

app.put("/users/profile" , async(req,res)=>{
    const {username,bio,favorite_genre,profile_picture}=req.body;
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) return res.status(401).json({ error: "Yetkilendirme başarısız: Token eksik" });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        await pool.query("UPDATE users SET username=$1,bio=$2,favorite_genre=$3,profile_picture=$4 WHERE id=$5",
            [username, bio, favorite_genre, profile_picture, decoded.userId]
        )
        res.json({ message: "Profil güncellendi!" });
    } catch (error) {
        console.error("Profil güncelleme hatası:", error);
        res.status(500).json({ error: "Sunucu hatası" });
    }

})


app.get("/users/profile/:id" , async(req,res)=>{
    const {id} = req.params;

    try {
        const result = await pool.query("SELECT id ,username , bio ,favorite_genre, profile_picture FROM users WHERE id =$1",[id]);
        if(result.rows.length===0) return res.status(404).json({error: "Kullanıcı bulunamadı."});
        res.json(result.rows[0]);
    } catch (error) {
        console.error("Kullanıcı profili alınamadı:", error);
        res.status(500).json({ error: "Sunucu hatası." });
    }
});


app.post("/users/follow" , async(req,res)=>{
    const { following_id } = req.body;
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) return res.status(401).json({ error: "Yetkilendirme başarısız: Token eksik" });


    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        await pool.query("INSERT INTO followers (follower_id,following_id) VALUES ($1,$2) ON CONFLICT DO NOTHING " , [decoded.userId, following_id]);
        res.json({ message: "Takip işlemi başarılı!" });
    } catch (error) {
        console.error("Takip hatası:", error);
        res.status(500).json({ error: "Sunucu hatası." });
    }
});

app.post("/users/unfollow" , async(req,res)=>{
    const { following_id } = req.body;
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) return res.status(401).json({ error: "Yetkilendirme başarısız: Token eksik" });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        await pool.query("DELETE FROM followers WHERE follower_id =$1 AND following_id=$2" , [decoded.userId, following_id]);
        res.json({ message: "Takipten çıkıldı!" });
    } catch (error) {
        console.error("Takipten çıkma hatası:", error);
        res.status(500).json({ error: "Sunucu hatası." });
    }
});




app.post("/users/recommend-movie" , async(req,res)=>{
    const { receiver_username , movie_title , message} = req.body;
    const authHeader = req.headers.authorization;
    
    const token = authHeader && authHeader.split(" ")[1];
    console.log("📢 API'ye gelen token:", authHeader);

    if (!token) return res.status(401).json({ error: "Yetkilendirme başarısız: Token eksik" });


    try {

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        console.log("✅ Token doğrulandı:", decoded);
        const receiverResult = await pool.query("SELECT id FROM users WHERE username=$1",[receiver_username]);

        if (receiverResult.rows.length === 0) {
            return res.status(404).json({ error: "Alıcı kullanıcı bulunamadı." });
        }

        const receiver_id = receiverResult.rows[0].id;

        await pool.query("INSERT INTO movie_recommendations (sender_id, receiver_id, movie_title, message) VALUES ($1, $2, $3, $4)",
             [decoded.userId, receiver_id, movie_title, message]
            );
            res.json({ message: "Film önerisi gönderildi!" });
    } catch (error) {
        console.error("❌ JWT doğrulama hatası:", error);
        res.status(500).json({ error: "Sunucu hatası." });
    }
});


app.get("/movies/recommendations/:username", async(req,res)=>{
    const {username}=req.params;

    try {
       

        const userResult = await pool.query("SELECT id FROM users WHERE username = $1", [username]);
        if (userResult.rows.length === 0) {
            return res.status(404).json({ error: "Kullanıcı bulunamadı." });
        }

        const userId = userResult.rows[0].id; 
        console.log("🟢 Kullanıcı ID:", userId);
        const result = await pool.query(`
            SELECT r.movie_title, r.message, r.created_at, 
                   sender.username AS sender_username, sender.profile_picture 
            FROM movie_recommendations r
            JOIN users sender ON r.sender_id = sender.id
            WHERE r.receiver_id = $1
            ORDER BY r.created_at DESC
        `, [userId]);   

        console.log("🟢 API Sonuçları:", result.rows); 

        res.json(result.rows);
    } catch (error) {
        console.error("Film önerileri alınamadı:", error);
        res.status(500).json({ error: "Sunucu hatası." });
    }
})


  const PORT = 5002;
  app.listen(PORT, () => console.log(` Server ${PORT} portunda çalışıyor...`));