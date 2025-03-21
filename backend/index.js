import express from 'express';
const app = express();
import dotenv from 'dotenv';
import connectDB from './config/db.js';
import cors from 'cors';
import userRoutes from './routes/user.routes.js';
import adminRoutes from './routes/admin.routes.js';
import cookieParser from 'cookie-parser';

dotenv.config();
connectDB();

app.use(express.json());
app.use(cookieParser());
app.use(cors());

app.use('/api/auth', userRoutes)
app.use('/api/admin', adminRoutes)

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));