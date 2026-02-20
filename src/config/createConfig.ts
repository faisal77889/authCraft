
type RawConfig = {
  mongoUrl ?: string;
  redisUrl?: string;
  auth: {
    jwtSecret: string;
    accessExp?: string;
    refreshExp?: string;
  };
};
export function createConfig( raw : RawConfig) {
    if(!raw.auth.jwtSecret){
        throw new Error("auth.jwt secret is required")
    }
    return {
        mongoUrl : raw.mongoUrl ? raw.mongoUrl : null,
        redisUrl : raw.redisUrl ? raw.redisUrl : null,
        auth : {
            jwtSecret : raw.auth.jwtSecret,
            accessExp : raw.auth.accessExp ?? "15m",
            refreshExp : raw.auth.refreshExp ?? "7d"
        }
    }
}