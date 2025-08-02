import { MongooseModule } from '@nestjs/mongoose';
import { ConfigModule } from '@nestjs/config';
import { User, UserSchema } from '../src/users/schemas/user.schema';
import {
  RefreshToken,
  RefreshTokenSchema,
} from '../src/refresh-tokens/schemas/refresh-token.schema';
import dbConfig from '../src/config/db.config';
import 'dotenv/config';
import appConfig from '../src/config/app.config';
import jwtConfig from '../src/config/jwt.config';
import cookieConfig from '../src/config/cookie.config';
import googleConfig from '../src/config/google.config';

export function getTestDbConfig() {
  const testDbName = 'test_db';

  process.env.JWT_SECRET = 'test-jwt-secret';
  process.env.JWT_REFRESH_SECRET = 'test-jwt-refresh-secret';
  process.env.JWT_PASSWORD_SECRET = 'test-jwt-password-secret';
  process.env.COOKIE_SECRET = 'test-cookie-secret';

  const mongoUri = process.env.MONGO_URI || 'mongodb://localhost:27017/test_db';

  process.env.MONGO_URI = mongoUri;

  return {
    imports: [
      ConfigModule.forRoot({
        isGlobal: true,
        load: [dbConfig, appConfig, jwtConfig, cookieConfig, googleConfig],
      }),
      MongooseModule.forRoot(mongoUri),
      MongooseModule.forFeature([
        { name: User.name, schema: UserSchema },
        { name: RefreshToken.name, schema: RefreshTokenSchema },
      ]),
    ],
  };
}
