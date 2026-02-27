import { v2 as cloudinary } from 'cloudinary'
import fs from "fs"

 cloudinary.config({ 
        cloud_name: process.env.CLOUDINARY_CLOUD_NAME, 
        api_key: process.env.CLOUDINARY_API_KEY, 
        api_secret: process.env.CLOUDINARY_API_SECRET 
    });

const uploadFileOnCloudinary = async (localFilePath) => {

    if (!localFilePath) return null

    try {
         const response = await cloudinary.uploader.upload(localFilePath, {
            resource_type:'auto',
        });

        fs.unlinkSync(localFilePath);
        return response;
        
    } catch (error) {
        fs.unlinkSync(localFilePath)
         console.error("Cloudinary error while file uploading:", error.message);
        return null
    }
};

const updateFileOnCloudinary = async (localFilePath, publicId) => {

    if (!localFilePath || !publicId) return null

    try {
         const response = await cloudinary.uploader.upload(localFilePath, {
            resource_type:'auto',
            public_id:publicId,
            overwrite:true,
            invalidate: true
        });

        fs.unlinkSync(localFilePath);
        return response;
        
    } catch (error) {
        fs.unlinkSync(localFilePath)
         console.error("Cloudinary error while file updating:", error.message);
        return null
    }
};

const deleteFileOnCloudinary = async (publicId) => {
    if (!publicId) return null;
    try {
        await cloudinary.uploader.destroy(publicId);
    } catch (error) {
        console.error("Cloudinary error while file deleting:", error.message);
        return null
    }
}

export {uploadFileOnCloudinary, updateFileOnCloudinary, deleteFileOnCloudinary}