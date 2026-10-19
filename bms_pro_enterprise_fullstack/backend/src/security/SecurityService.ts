// ============================================================================
// BMS Pro Enterprise v2.0 - Security Core
// Includes: AES-256-GCM, bcrypt, JWT + Refresh, 60s Dynamic TOTP QR, RBAC
// ============================================================================
import crypto from 'crypto';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { Request, Response, NextFunction } from 'express';

const AES_ALGORITHM = 'aes-256-gcm';
const AES_KEY = Buffer.from(
  process.env.AES_256_SECRET_KEY || '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
  'hex'
);

export const MILITARY_RANK_PRIORITY: Record<string, number> = {
  BRIGADE_CMD: 100,
  SYS_ADMIN: 99,
  BATTALION_CMD: 90,
  OPS_CHIEF: 85,
  HR_CHIEF: 80,
  TRAINING_CHIEF: 78,
  COMPANY_CMD: 70,
  SECURITY_OFFICER: 65,
  DUTY_OFFICER: 60,
  ADMIN_OFFICER: 55,
  TRAINING_OFFICER: 50,
  PLATOON_CMD: 45,
  CLERK: 30,
  SOLDIER: 10
};

export class SecurityService {
  static encryptAES256(plainText: string): string {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv(AES_ALGORITHM, AES_KEY, iv);
    const encrypted = Buffer.concat([cipher.update(plainText, 'utf8'), cipher.final()]);
    const authTag = cipher.getAuthTag();
    return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted.toString('hex')}`;
  }

  static decryptAES256(cipherPayload: string): string {
    const [ivHex, tagHex, contentHex] = cipherPayload.split(':');
    const decipher = crypto.createDecipheriv(AES_ALGORITHM, AES_KEY, Buffer.from(ivHex, 'hex'));
    decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(contentHex, 'hex')),
      decipher.final()
    ]);
    return decrypted.toString('utf8');
  }

  // Dynamic 60-Second Military Smart Card TOTP QR Generator & Verifier
  static generateDynamicQrTotp(militaryId: string, windowSeconds = 60): string {
    const timeStep = Math.floor(Date.now() / 1000 / windowSeconds);
    const hmac = crypto.createHmac('sha256', AES_KEY);
    hmac.update(`${militaryId}:${timeStep}`);
    const digest = hmac.digest('hex').slice(0, 8).toUpperCase();
    return `TOTP-${militaryId}-${digest}`;
  }

  static verifyDynamicQrTotp(militaryId: string, token: string, windowSeconds = 60): boolean {
    const expectedCurrent = this.generateDynamicQrTotp(militaryId, windowSeconds);
    return crypto.timingSafeEqual(Buffer.from(expectedCurrent), Buffer.from(token));
  }

  static async hashPassword(password: string): Promise<string> {
    return bcrypt.hash(password, 12);
  }

  static async verifyPassword(password: string, hash: string): Promise<boolean> {
    return bcrypt.compare(password, hash);
  }

  static signTokens(payload: { userId: string; role: string; permissions: string[] }, rememberMe = false) {
    const accessToken = jwt.sign(payload, process.env.JWT_ACCESS_SECRET || 'bms_access_secret', {
      expiresIn: '15m'
    });
    const refreshToken = jwt.sign(
      { userId: payload.userId },
      process.env.JWT_REFRESH_SECRET || 'bms_refresh_secret',
      { expiresIn: rememberMe ? '30d' : '7d' }
    );
    return { accessToken, refreshToken };
  }
}

export function requirePermission(permissionCode: string) {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = (req as any).user;
    if (!user) {
      return res.status(401).json({ status: 'error', message: 'غير مصرح بالدخول - يرجى تسجيل الدخول' });
    }
    if (user.role === 'SYS_ADMIN' || (user.permissions && user.permissions.includes(permissionCode))) {
      return next();
    }
    return res.status(403).json({
      status: 'forbidden',
      message: `رفض الصلاحية: لا تملك صلاحية (${permissionCode}) لتنفيذ هذا الإجراء العسكري.`
    });
  };
}
