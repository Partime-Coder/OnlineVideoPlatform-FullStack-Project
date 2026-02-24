import { asyncHandler } from "../utils/asyncHandler.js"
import { ApiError } from "../utils/ApiError.js"
import { ApiResponse } from "../utils/ApiResponse.js"
import { User } from "../models/user.models.js"
import { uploadFileOnCloudinary } from "../utils/cloudinary.js"

const generateAccessAndRefreshTokens = async (userId) => {
  try {
    const user = await User.findById(userId);
    const accessToken = user.generateAccessToken();
    const refreshToken = user.generateRefreshToken();

    user.refreshToken = refreshToken
    await user.save({ validateBeforeSave: false })

    return { accessToken, refreshToken }
  } catch (error) {
    throw new ApiError(500, "Something went wrong while generating access and referesh tokens")
  }
}

const registerUser = asyncHandler(async (req, res) => {
  const { username, fullName, email, password } = req.body

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

  const existedUser = await User.findOne({ email });
  if (existedUser) {
    throw new ApiError(409, "User with email already exist")
  }

  const avatarLocalPath = req.files?.avatar[0]?.path;
  // const coverImageLocalPath = req.files?.coverImage[0]?.path; 
  let coverImageLocalPath;
  if (req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0) {
    coverImageLocalPath = req.files?.coverImage[0]?.path;
  }



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
    avatar: avatar.url,
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

});

const loginUser = asyncHandler(async (req, res) => {
  // get database 
  // get email and password   ---> data from req body
  // validate both are correct ----> same validate the data 
  // compare with database    -----> find the user
  // check password
  // if user found
  // create access token and refresh token ?
  // create session and cookie ?
  // give success messagec 
  // else 
  //    give error response message 

  const { username, email, password } = req.body;

  if (!username || !email) {
    throw new ApiError(400, "username or email is required")
  };
  const user = await User.find({
    $or: [{ username }, { email }]
  })

  if (!user) {
    throw new ApiError(404, "User does not exist")
  }

  const isPasswordValid = await user.isPasswordCorrect(password);

  if (!isPasswordValid) {
    throw new ApiError(401, "Invalid user credentials")
  };

  const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(user._id);
  const loggedInUser = await User.findById(user._id).select("-password -refreshToken")

  const options = {
    httpOnly: true,
    secure: true,
  };

  return res.status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
      new ApiResponse(
        200,
        {
          user: loggedInUser, accessToken, refreshToken
        },
        "user logged In successfully"
      )
    )
});

const logoutUser = asyncHandler(async (req, res) => {
  await User.findByIdAndUpdate(req.user._id), {
    $set: {
      refreshToken: undefined
    }
  },
  {
    new: true
  }

   const options = {
    httpOnly: true,
    secure: true,
  };

  return res.status(200)
  .clearCookie("accessToken", options)
  .clearCookie("refreshToken", options)
  .json(new ApiResponse(200, {}, "User logged out successfully"))

});
export { registerUser, loginUser, logoutUser }