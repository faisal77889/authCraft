import express, { type Application, type Request, type Response } from "express"
const app:Application = express()
// import { app } from "./auth/auth"

// app.use("/auth",authRouter)












app.listen(3000,()=>{
    console.log("Server is running on port 3000")
})