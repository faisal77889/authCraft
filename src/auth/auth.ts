import { Router, Request, Response } from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

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
          message: "Email and password are required"
        });
      }

      const existingUser = await adapter.findByEmail(email);

      if (existingUser) {
        return res.status(409).json({
          message: "User already exists"
        });
      }

      const passwordHash = await bcrypt.hash(password, 10);

      await adapter.createUser({
        email,
        passwordHash
      });

      return res.status(201).json({
        message: "User registered successfully"
      });
    } catch (error) {
      return res.status(500).json({
        message: "Internal server error"
      });
    }
  });


  router.post("/login", async (req: Request, res: Response) => {
    try {
      const { email, password } = req.body;

      if (!email || !password) {
        return res.status(422).json({
          message: "Email and password are required"
        });
      }

      const user = await adapter.findByEmail(email);

      if (!user) {
        return res.status(404).json({
          message: "User not found"
        });
      }

      const isValidPassword = await adapter.verifyPassword(user, password);

      if (!isValidPassword) {
        return res.status(401).json({
          message: "Invalid credentials"
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
        refreshToken
      });
    } catch (error) {
      return res.status(500).json({
        message: "Internal server error"
      });
    }
  });

  router.get("/refresh", async (req: Request, res: Response) => {
  try {
    const refreshToken = req.cookies?.refreshToken;

    if (!refreshToken) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    const decoded = jwt.verify(
      refreshToken,
      config.jwtSecret
    ) as jwt.JwtPayload;

    const newAccessToken = jwt.sign(
      { userId: decoded.userId },
      config.jwtSecret,
      { expiresIn: "15m" }
    );

    return res.status(200).json({
      accessToken: newAccessToken,
    });
  } catch (error) {
    return res.status(401).json({
      message: "Invalid or expired refresh token",
    });
  }
});

  return router;
}