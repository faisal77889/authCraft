import { Router, Request, Response, NextFunction } from "express";
import bcrypt from "bcrypt";
import jwt, { JwtPayload } from "jsonwebtoken";



export type AuthConfig = {
  jwtSecret: string;
  accessExp?: string;   
  refreshExp?: string;  
};

export type AuthAdapter<User = unknown> = {
  findByEmail: (email: string) => Promise<User | null>;

  createUser: (data: {
    email: string;
    passwordHash: string;
  }) => Promise<User>;

  verifyPassword: (user: User, plainPassword: string) => Promise<boolean>;

  getJwtPayload: (user: User) => Record<string, any>;
};

declare global {
  namespace Express {
    interface Request {
      auth?: JwtPayload;
    }
  }
}


export function authRouter<User>(
  config: AuthConfig,
  adapter: AuthAdapter<User>
) {
  const router = Router();

  router.post("/register", async (req: Request, res: Response) => {
    try {
      const { email, password } = req.body;

      if (!email || !password) {
        return res.status(422).json({
          message: "Email and password are required",
        });
      }

      const existingUser = await adapter.findByEmail(email);

      if (existingUser) {
        return res.status(409).json({
          message: "User already exists",
        });
      }

      const passwordHash = await bcrypt.hash(password, 10);

      await adapter.createUser({
        email,
        passwordHash,
      });

      return res.status(201).json({
        message: "User registered successfully",
      });
    } catch {
      return res.status(500).json({
        message: "Internal server error",
      });
    }
  });

 

  router.post("/login", async (req: Request, res: Response) => {
    try {
      const { email, password } = req.body;

      if (!email || !password) {
        return res.status(422).json({
          message: "Email and password are required",
        });
      }

      const user = await adapter.findByEmail(email);

      if (!user) {
        return res.status(404).json({
          message: "User not found",
        });
      }

      const isValidPassword = await adapter.verifyPassword(user, password);

      if (!isValidPassword) {
        return res.status(401).json({
          message: "Invalid credentials",
        });
      }

      const payload = adapter.getJwtPayload(user);

      const accessToken = jwt.sign(
        { ...payload, type: "access" },
        config.jwtSecret,
        { expiresIn: config.accessExp || "15m" }
      );

      const refreshToken = jwt.sign(
        { ...payload, type: "refresh" },
        config.jwtSecret,
        { expiresIn: config.refreshExp || "7d" }
      );

      return res.status(200).json({
        message: "Login successful",
        accessToken,
        refreshToken,
      });
    } catch {
      return res.status(500).json({
        message: "Internal server error",
      });
    }
  });

 

  router.post("/refresh", async (req: Request, res: Response) => {
    try {
      const refreshToken =
        req.headers.authorization?.split(" ")[1];

      if (!refreshToken) {
        return res.status(401).json({
          message: "Refresh token required",
        });
      }

      const decoded = jwt.verify(
        refreshToken,
        config.jwtSecret
      ) as JwtPayload;

      if (decoded.type !== "refresh") {
        return res.status(401).json({
          message: "Invalid refresh token",
        });
      }

      const { type, iat, exp, ...payload } = decoded;

      const newAccessToken = jwt.sign(
        { ...payload, type: "access" },
        config.jwtSecret,
        { expiresIn: config.accessExp || "15m" }
      );

      return res.status(200).json({
        accessToken: newAccessToken,
      });
    } catch {
      return res.status(401).json({
        message: "Invalid or expired refresh token",
      });
    }
  });

  return router;
}

export const roleAuthMiddleware =
  (requiredRole: string, jwtSecret: string) =>
  (req: Request, res: Response, next: NextFunction) => {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
      return res.status(401).json({
        message: "Unauthorized",
      });
    }

    const [scheme, token] = authHeader.split(" ");

    if (scheme !== "Bearer" || !token) {
      return res.status(401).json({
        message: "Invalid authorization format",
      });
    }

    try {
      const decoded = jwt.verify(token, jwtSecret) as JwtPayload;

      if (decoded.type !== "access") {
        return res.status(401).json({
          message: "Invalid token type",
        });
      }

      if (decoded.role !== requiredRole) {
        return res.status(403).json({
          message: "Forbidden",
        });
      }

      req.auth = decoded;
      next();
    } catch {
      return res.status(401).json({
        message: "Invalid or expired token",
      });
    }
  };