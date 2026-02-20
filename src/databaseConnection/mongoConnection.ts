import mongoose from "mongoose";
export default async function connectMongodb(mongoUrl : string) : Promise<void> {
    if(!mongoUrl){
        throw new Error("Mongo DB usrl is required")
    }
    try {
         await mongoose.connect(mongoUrl)
    } catch (error) {
        const err = error as Error;
        throw new Error(`MongoDB connection failed: ${err.message}`)
    }
}