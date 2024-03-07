import { asyncHandler } from "../utils/asyncHandler.js";
import { apiError } from "../utils/apiErrors.js";
import { User } from "../models/user.model.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";
import { apiResponse } from "../utils/apiResponse.js";
import jwt from "jsonwebtoken";

const generateAccessAndRefreshToken = async (userId) => {
    try {
        const user = await User.findById(userId);
        const accessToken = await user.generateAccessToken()
        const refreshToken = await user.generateRefreshToken()

        user.refreshToken = refreshToken
        await user.save({ validateBeforeSave: false })

        return { accessToken, refreshToken }

    } catch (error) {
        throw new apiError(500, "Something went wrong while generating refresh and access token.");
    }
}

const registerUser = asyncHandler(async (req, res) => {
  // Get user information from frontend
  // Validations - check the data is not empty
  // Check if the user is already registered : check by username, email
  // Check for images and avatar
  // Upload them to cloudinary and check for avatar
  // Create user object - create entry in database
  // Remove password and refresh token field from the response
  // Check if the user created successfully
  // reture response

  const { fullname, username, email, password } = req.body;

  // if (fullname === ""){
  //     throw new apiError(400, "Fullname is required")
  // } this code can also be used to check validation

  if (
    [fullname, username, email, password].some((field) => field?.trim() === "")
  ) {
    throw new apiError(400, "All fields are required");
  }

  const existedUser = await User.findOne({
    $or: [{ username }, { email }],
  });
  if (existedUser) {
    throw new apiError(409, "User with email or username already exists");
  }

  const avatarLocalPath = req.files?.avatar[0]?.path;
//   const coverImageLocalPath = req.files?.coverImage[0]?.path;

let coverImageLocalPath;
if(req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length>0){
    coverImageLocalPath = req.files.coverImage[0].path
}

  if (!avatarLocalPath) {
    throw new apiError(400, "Avatar file is required");
  }

  const avatar = await uploadOnCloudinary(avatarLocalPath);
  const coverImage = await uploadOnCloudinary(coverImageLocalPath);
  if (!avatar) {
    throw new apiError(400, "Avatar file is required");
  }

  const user = await User.create({
    fullname,
    avatar: avatar.url,
    coverImage: coverImage?.url || "",
    email,
    password,
    username: username.toLowerCase(),
  });

  const createdUser = await User.findById(user._id).select(
    "-password -refreshToken"
  )

  if(!createdUser){
    throw new apiError(500, "Something went wrong while registering a user")
  }

  return res.status(201).json(
    new apiResponse(200, createdUser, "User registered successfully")
  )
});

const loginUser = asyncHandler(async (req, res)=>{
    // Get data from request body
    // Check if there is username or email address
    // Find the user from database
    // If user present check password
    // If all set give access and generate refresh token
    // Send tokens in cookies
    // Finally send response

    const {email, username, password} = req.body;
    if(!email && !username){
        throw new apiError(400, "Username or email is required")
    }

    const user = await User.findOne({
        $or : [{username}, {email}]
    })
    if(!user){
        throw new apiError(404, "User not found")
    }

    const isPasswordValid = await user.isPasswordCorrect(password)
    if(!isPasswordValid){
        throw new apiError(401, "Password is not correct")
    }

    const {accessToken, refreshToken} = await generateAccessAndRefreshToken(user._id)

    const loggedInUser = await User.findById(user._id).select("-password -refresh-token")

    const options = {
        httpOnly: true,
        secure: true,
    }

    return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
        new apiResponse(
            200,
            {
                user: loggedInUser, accessToken, refreshToken
            },
            "User logged in successfully"
        )
    )

});

const logoutUser = asyncHandler(async (req, res)=>{
    await User.findByIdAndUpdate(
      req.user._id,
      {
        $set:{
          refreshToken: undefined
        }
      },
      { new: true }
    )

    const options = {
      httpOnly: true,
      secure: true,
  }

  return res
  .status(200)
  .clearCookie("accessToken", options)
  .clearCookie("refreshToken", options)
  .json(
    new apiResponse(200, {}, "User logged out successfully")
  )
})

const refreshAccessToken = asyncHandler(async (req, res) =>{
  const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken 
  if(!incomingRefreshToken) {
    throw new apiError(401, "Unauthorized request")
  }

  try {
    const decodedToken = jwt.verify(incomingRefreshToken, process.env.REFRESH_TOKEN_SECRET)
    const userId = await User.findById(decodedToken?._id)
  
    if (!userId) {
      throw new apiError(401, "Invalid Refresh token")
    }
  
    if (incomingRefreshToken !== userId?.refreshToken){
      throw new apiError(401, "Refresh token is expired or used")
    }
  
    const {accessToken, newRefreshToken} = await generateAccessAndRefreshToken(userId._id)
  
    const options = {
      httpOnly: true,
      secure: true,
    }
  
    return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", newRefreshToken, options)
    .json(
      new apiResponse(
        200,
        {accessToken, refreshToken: newRefreshToken},
        "Access token refreshed successfully"
      )
    )
  } catch (error) {
    throw new apiError(401, error?.message || "Invalid refresh token")
  }

})

const changeCurrentPassword = asyncHandler(async (req, res)=>{
  const {oldPassword, newPassword} = req.body

 const user = await User.findById(req.user?._id) //When can find req.user by auth.middleware.js
 const isPasswordCorrect = await user.isPasswordCorrect(oldPassword) //isPasswordCorrect comes from user.model.js
 if(!isPasswordCorrect){
  throw new apiError(400, "Invalid old password")
 }

 user.password = newPassword // Hashing the password is taken care in user.model.js
 await user.save({validateBeforeSave:false})

 return res
 .status(200)
 .json(new apiResponse(200, {}, "Password changed successfully"))
})

const getCurrentUser = asyncHandler (async(req, res)=>{
  return res
  .status(200)
  .json(new apiResponse(200, req.user, "Current user fetched successfully"))
})

const updateAccountDetails = asyncHandler (async(req, res)=>{
  const {fullname, email} = req.body

  if(!fullname || !email){
    throw new apiError(400, "All fields are required")
  }

  const user = await User.findByIdAndUpdate(
    req.user?._id,
    {
      $set: {
        fullname : fullname,
        email: email,
      }
    },
    {new:true} //this will return updated object
    ).select("-password -refreshToken")

    return res
    .status(200)
    .json( new apiResponse(200, user, "Account Details updated successfully"))
});

const updateUserAvatar = asyncHandler (async (req, res)=>{
  const avatarLocalPath = req.file?.path // req.file is response from multer middleware
  if(!avatarLocalPath){
    throw new apiError(400, "Avatar file is missing")
  }

  //If avatar is present upload on cloudinary server
  const newAvatar = await uploadOnCloudinary(avatarLocalPath)

  // If no url is provided by cloudinary
  if(!newAvatar.url) {
    throw new apiError(400, "Error while uploading on avatar")
  }

  // Update avatar in db
  const user = await User.findByIdAndUpdate(req.user?._id,
    {
      $set: {avatar: newAvatar.url},
    },
    {new: true}
    ).select("-password -refreshToken")
    return res
    .status(200)
    .json(new apiResponse(200,user, "Avatar uploaded successfully  "))
})

const updateUserCover = asyncHandler (async (req, res)=>{
  const coverLocalPath = req.file?.path // req.file is response from multer middleware
  if(!coverLocalPath){
    throw new apiError(400, "Cover Image file is missing")
  }

  //If avatar is present upload on cloudinary server
  const newCover = await uploadOnCloudinary(coverLocalPath)

  // If no url is provided by cloudinary
  if(!newCover.url) {
    throw new apiError(400, "Error while uploading on cover")
  }

  // Update avatar in db
  const user = await User.findByIdAndUpdate(req.user?._id,
    {
      $set: {coverImage: newCover.url},
    },
    {new: true}
    ).select("-password -refreshToken")
    return res
    .status(200)
    .json(new apiResponse(200,user, "Cover Image uploaded successfully  "))
}) 

const getUserChannelProfile = asyncHandler (async(req, res)=>{
  const {username} = req.params
  if(!username?.trim()){
    throw new apiError(400, "Username is missing in params")
  }

  const channel = await User.aggregate([
    {
      $match:{
        username: username?.toLowerCase() //First pipeline staged
      }
    },
    {
      $lookup:{
        from: "subscriptions",
        localField: "_id",
        foreignField: "channel",
        as: "subscribers"
      }
    },
    {
      $lookup:{
        from: "subscriptions",
        localField: "_id",
        foreignField: "subscriber",
        as: "subscribedTo"
      }
    },
    {
      $addFields:{
        subscribersCount:{
          $size: "$subscribers"
        },
        channelsSubscribedToCount:{
          $size: "$subscribedTo"
        },
        isSubscribed: {
          $cond: {
            if:{$in: [req.user?._id, "$subscribers.subscriber"]},
            then: true,
            else: false
          }
        }
      }
    },
    {
      $project:{
        fullname: 1,
        username: 1,
        avatar: 1,
        coverImage: 1,
        subscribersCount: 1,
        channelsSubscribedToCount: 1,
        isSubscribed: 1
      }
    }
  ])

  if(!channel?.length) {
    throw new apiError(404, "Channel does not exist")
  }

  return res
  .status(200)
  .json(new apiResponse(200, channel[0], "User data fetched successfully"))
})

export { registerUser, loginUser, logoutUser, refreshAccessToken, changeCurrentPassword, getCurrentUser, updateAccountDetails, updateUserAvatar, updateUserCover, getUserChannelProfile };
