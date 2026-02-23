import {asyncHandler} from "../utils/asyncHandler.js"
import {ApiError} from "../utils/ApiError.js"
import {ApiResponse} from "../utils/ApiResponse.js"
import {User} from "../models/user.models.js"
import {uploadFileOnCloudinary} from "../utils/cloudinary.js"

const registerUser = asyncHandler( async (req, res) => {
    const {username, fullName, email, password  } = req.body

     if (!fullName || fullName.trim() === "") {
    throw new ApiError(400, "Full name is required");
  }

  if (!username || username.trim() === "") {
    throw new ApiError(400, "Username is required");
  }

  if (!email || email.trim() === "") {
    throw new ApiError(400, "Email is required");
  }

  if (!password || password.trim() === "") {
    throw new ApiError(400, "Password is required");
  }

  const existedUser = await User.findOne({email});
  if (existedUser) {
    throw new ApiError(409, "User with email already exist")
  }

  const avatarLocalPath = req.files?.avatar[0]?.path; 
  const coverImageLocalPath = req.files?.coverImage[0]?.path; 
  
  
  if (!avatarLocalPath) {
    throw new ApiError(400, "Avatar image is required")
  }

  const avatar = await uploadFileOnCloudinary(avatarLocalPath)
  const coverImage = await uploadFileOnCloudinary(coverImageLocalPath)

  if (!avatar?.url) {
  throw new ApiError(500, "Avatar upload failed");
  }

  const user = await User.create({
    fullName,
    username,
    email,
    password,
    avatar:avatar.url,
    coverImage: coverImage?.url || "",
  })

  const userCreated = await User.findById(user._id).select(
    "-password -refreshToken"
  )

  if (!userCreated) {
    throw new ApiError(500, "Something went wrong while creating the user account")
  }

  return res.status(201).json(
    new ApiResponse(200, userCreated, "Account create successfully")
  )

})

export {registerUser}