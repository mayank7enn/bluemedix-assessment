import express from 'express';
import { createUser, deleteUser, getAllUsers, getUserById, updateUser } from '../controllers/admin.controllers.js';
import { userAuth } from '../middlewares/userAuth.js';
import { adminAuth } from '../middlewares/adminAuth.js';

const router = express.Router();

router.get('/user/:id',userAuth, adminAuth, getUserById)
router.post('/user', userAuth, adminAuth, createUser)
router.patch('/user/:id', userAuth, adminAuth, updateUser)
router.delete('/user/:id', userAuth, adminAuth, deleteUser)

router.get('/users', userAuth, adminAuth, getAllUsers)

export default router;