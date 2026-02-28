import { asyncHandler } from "../utils/asyncHandler.js"
import { ApiError } from "../utils/ApiError.js"
import { ApiResponse } from "../utils/ApiResponse.js"
import { User } from "../models/user.models.js"
import { updateFileOnCloudinary, uploadFileOnCloudinary } from "../utils/cloudinary.js"
import jwt from "jsonwebtoken"

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

  if (!avatar?.public_id) {
    throw new ApiError(500, "Avatar upload failed");
  }

  const user = await User.create({
    fullName,
    username,
    email,
    password,
    avatar: avatar.url,
    avatarPublicId: avatar.public_id,
    coverImage: coverImage?.url || "",
    coverImagePublicId: coverImage?.public_id || "",
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

  const { username, email, password } = req.body;

  if (!username && !email) {
    throw new ApiError(400, "username or email is required")
  };
  const user = await User.findOne({
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

const refreshAccessToken = asyncHandler(async (req, res) => {
  const incomeingRefreshToken = req.cookies.refreshToken || req.body.refreshToken;
  if (!incomeingRefreshToken) {
    throw new ApiError(401, "Unauthorized request")
  };

  try {
    const decodedToken = jwt.verify(incomeingRefreshToken, process.env.REFRESH_TOKEN_SECRET);

    const user = await User.findById(decodedToken?._id);
    if (!user) {
      throw new ApiError(401, "Invalid refresh token");
    };

    if (incomeingRefreshToken !== user?.refreshToken) {
      throw new ApiError(401, "Refresh token is expired or used");

    };
    const options = {
      httpOnly: true,
      secure: true,
    };

    const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(user._id)

    return res.status(200)
      .cookie("accessToken", accessToken, options)
      .cookie("refreshToken", refreshToken, options)
      .json(
        new ApiResponse(
          200,
          {
            accessToken, refreshToken
          },
          "Access token refresh"
        )
      )
  } catch (error) {
    throw new ApiError(401, error?.message || "Invalid refresh token")
  }
});

const changeCurrentPassword = asyncHandler(async (req, res) => {

  const { oldPassword, newPassword } = req.body;
  const user = await User.findById(req.user?._id);
  const isPasswordCorrect = await user.isPasswordCorrect(oldPassword);

  if (!isPasswordCorrect) {
    throw new ApiError(400, "Invalid Password")
  }

  user.password = newPassword;
  await user.save({ validateBeforeSave: false });

  return res.status(200)
    .json(new ApiResponse(200, {}, "Password updated successfully"))


});

const getCurrentUser = asyncHandler(async (req, res) => {
  return res.status(200)
    .json(200, req.user, "Current user fetched");
});

const changeUserDetails = asyncHandler(async (req, res) => {
  const { username, email, fullName, password } = req.body;

  if (!password || password.trim() === "") {
    throw new ApiError(400, "Password is required to update details");
  }

  if (!fullName || fullName.trim() === "") {
    throw new ApiError(400, "Full name is required");
  }

  if (!username || username.trim() === "") {
    throw new ApiError(400, "Username is required");
  }

  if (!email || email.trim() === "") {
    throw new ApiError(400, "Email is required");
  }


  const user = await User.findById(req.user._id);

  if (!user) {
    throw new ApiError(404, "User not found");
  }

  const isPasswordCorrect = await user.isPasswordCorrect(password);
  if (!isPasswordCorrect) {
    throw new ApiError(401, "Invalid password");
  }

  user.username = username;
  user.email = email;
  user.fullName = fullName;

  await user.save();

  const userObj = user.toObject();
  delete userObj.password;
  delete userObj.refreshToken;

  return res
    .status(200)
    .json(new ApiResponse(200, userObj, "Account details updated successfully"));
});

const updateUserAvatar = asyncHandler(async (req, res) => {

  const avatarLocalPath = req.file?.path;
  if (!avatarLocalPath) {
    throw new ApiError(400, "Avatar file is missing")
  }
  const user = await User.findById(req.user?._id).select("-password -refreshToken")

  if (!user) {
    throw new ApiError(400, "user not found");
  }
  if (!user.avatarPublicId) {
    throw new ApiError(400, "AvatarId file is missing")
  }

  const avatar = await updateFileOnCloudinary(avatarLocalPath, user.avatarPublicId)

  user.avatar = avatar.url;
  user.avatarPublicId = avatar.public_id;

  await user.save()

  return res.status(200)
    .json(new ApiResponse(200, user, "avatar updated successfully"));

});

const updateUsercoverImage = asyncHandler(async (req, res) => {
  const coverImageLocalPath = req.file?.path;

  if (!coverImageLocalPath) {
    throw new ApiError(400, "cover image file is missing")
  }

  const user = await User.findById(req.user?._id).select("-password -refreshToken")

  if (!user) {
    throw new ApiError(400, "user not found");
  }

  let coverImage;

  if (user.coverImage === "" && user.coverImagePublicId === "") {
    coverImage = await uploadFileOnCloudinary(coverImageLocalPath);

  } else {
    coverImage = await updateFileOnCloudinary(coverImageLocalPath, user.coverImagePublicId);

  }

  user.coverImage = coverImage.url;
  user.coverImagePublicId = coverImage.public_id;

  await user.save();

  return res.status(200)
    .json(new ApiResponse(200, user, "cover image updated successfully"));

});

const getUserChannelProfile = asyncHandler(async (req, res) => {
  const { username } = req.params;

  if (!username?.trim()) {
    throw new ApiError(400, "username is missing")
  }

  const channel = await User.aggregate([
    {
      $match: {
        username: username
      }
    },
    {
      $lookup: {
        from: "subscriptions",
        localField: "_id",
        foreignField: "channel",
        as: "followers"
      }
    },
    {
      $lookup: {
        from: "subscriptions",
        localField: "_id",
        foreignField: "subscriber",
        as: "following"
      }
    },
    {
      $addFields: {
        followersCount: {
          $size: "$followers"
        },
        followingCount: {
          $size: "$following"
        },
        isFollowing: {
          $cond: {
            if: { $in: [req.user?._id, "$followers.subscriber"] },
            then: true,
            else: false
          }
        }
      }
    },
    {
      $project: {
        username: 1,
        fullName: 1,
        email: 1,
        avatar: 1,
        coverImage: 1,
        followersCount: 1,
        followingCount: 1,
        createdAt: 1,

      }
    }
  ]);

  if (!channel?.length) {
    throw new ApiError(404, "channel does not exist")
  }
  console.log(channel);

  return res.status(200)
    .json(
      new ApiResponse(200, channel[0], "User channel fetch successfully")
    )

});

const getUserWatchHistory = asyncHandler(async (req, res) => {

  const user = await User.aggregate([
    {
      $match: {
        _id: new mongoose.Types.ObjectId(req.user._id)
      }
    },
    {
      $lookup: {
        from: "videos",
        localField: "watchHistory",
        foreignField: "_id",
        as: "watchHistory",
        pipeline: [
          {
            $lookup: {
              from: "users",
              localField: "owner",
              foreignField: "_id",
              as: "owner",
              pipeline:[
                {
                  $project: {
                    username: 1,
                    avatar: 1
                  }
                }
              ]
            }
          },
          {
            $addFields:{
              owner:{
                $first:$owner
              }
            }
          }
        ]
      }
    }
  ]);
   return res.status(200)
    .json(
      new ApiResponse(200, user[0].watchHistory, "User watch history fetch successfully")
    )
});

export {
  registerUser,
  loginUser,
  logoutUser,
  refreshAccessToken,
  changeCurrentPassword,
  getCurrentUser,
  changeUserDetails,
  updateUserAvatar,
  updateUsercoverImage,
  getUserChannelProfile,
  getUserWatchHistory
}