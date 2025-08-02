import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';
import { MailModule } from './mail/mail.module';
import { RefreshTokensModule } from './refresh-tokens/refresh-tokens.module';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { MongooseModule } from '@nestjs/mongoose';
import dbConfiguration from './config/db.config';
import mailerConfig from './config/mailer.config';
import jwtConfig from './config/jwt.config';
import cookieConfig from './config/cookie.config';
import googleConfig from './config/google.config';
import appConfig from './config/app.config';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: [
        dbConfiguration,
        mailerConfig,
        jwtConfig,
        cookieConfig,
        googleConfig,
        appConfig,
      ],
    }),
    MongooseModule.forRootAsync({
      inject: [ConfigService],
      useFactory: async (configService: ConfigService) => ({
        uri: configService.getOrThrow('database').uri,
      }),
    }),
    AuthModule,
    UsersModule,
    RefreshTokensModule,
    MailModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
