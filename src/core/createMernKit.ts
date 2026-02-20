import { createConfig } from "../config/createConfig"
import connectMongodb from "../databaseConnection/mongoConnection"


export async function createMernKit(userConfig: any) {
    const config = createConfig(userConfig)

    // connect to mongodb
    if (config.mongoUrl) {
        try {
            await connectMongodb(config.mongoUrl)
        } catch (error) {
            const err = error as Error
            throw new Error(`error while connecting to the database : ${err.message}`)
        }    
    }
    // redis connection 



    // auth module logic 
    if(!config.auth){
        throw new Error("providing auth configuration is must")
    }
    if(!config.auth.jwtSecret){
        throw new Error("providing the jwt secret is must for authentication")
    }
    // const router = authRouter(config.auth)
}

