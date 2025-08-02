import { registerAs } from '@nestjs/config';

export default registerAs('cookie', () => ({
  secret: process.env.COOKIE_SECRET,
  options: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    maxAge: 15 * 60 * 1000, // 15 minutes
    path: '/',
    domain:
      process.env.NODE_ENV === 'production'
        ? process.env.COOKIE_DOMAIN
        : undefined,
  },
}));
