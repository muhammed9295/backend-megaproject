import {v2 as cloudinary} from 'cloudinary';
import fs from 'fs';
          
cloudinary.config({ 
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME, 
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET 
});

const uploadOnCloudinary = async (localFilePath) =>{
    try {
        if(!localFilePath) return null;
        // Upload the file in cloudinary
       const response = await cloudinary.uploader.upload(localFilePath, {
            resource_type:'auto'
        })
        // File has been successfully uploaded
        console.log("File has been successfully uploaded on cloudinary", response.url);
        return response;
    } catch (error) {
        fs.unlink(localFilePath) //Remove temporary file which was uploaded
        return null;
    }
}

export {uploadOnCloudinary}