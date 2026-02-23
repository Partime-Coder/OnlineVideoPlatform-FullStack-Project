import dotenv from "dotenv";
dotenv.config({ path: ".env" });
import connectDB from "./database/index.js";
import { app } from "./app.js";

connectDB()
.then(()=>{
    app.listen(process.env.PORT || 4000, () => {
        console.log(`Server is running at Port : http://localhost:${process.env.PORT}/`);
        
    })
    
})
.catch((error)=>{
    console.log("MONGODB connection failed !!!", error);
    
})