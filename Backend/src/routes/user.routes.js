import { Router } from "express";
import { 
     changeCurrentPassword,
     changeUserDetails,
     getCurrentUser,
     loginUser, 
     logoutUser, 
     refreshAccessToken, 
     registerUser, 
     updateUserAvatar, 
     updateUsercoverImage 
    
    } from "../controllers/user.controller.js";
import { upload } from "../middlewares/multer.middlewares.js";
import { verifyJWT } from "../middlewares/auth.middlewares.js";

const router = Router()

router.route("/register").post(
    upload.fields([
        {
            name: "avatar",
            maxCount:1
        },
        {
            name: "coverImage",
            maxCount:1
        }
    ]),
    registerUser
)

router.route("/login").post(loginUser)

router.route("/logout").post(verifyJWT, logoutUser)

router.route("/refreshToken").post(refreshAccessToken)

router.route("/current-user").get(getCurrentUser)

router.route("/update-password").patch(verifyJWT, changeCurrentPassword)

router.route("/update-account").patch(verifyJWT, changeUserDetails)

router.route("/update-avatar").patch(verifyJWT, upload.single("avatar"), updateUserAvatar)

router.route("/update-coverImage").patch(verifyJWT, upload.single("coverImage"), updateUsercoverImage)

export default router


   