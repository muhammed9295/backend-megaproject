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

export { registerUser, loginUser, logoutUser, refreshAccessToken };
