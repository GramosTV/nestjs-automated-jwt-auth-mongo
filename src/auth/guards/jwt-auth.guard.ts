import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
  Inject,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import * as jwt from 'jsonwebtoken';
import { AuthService } from '../auth.service';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') implements CanActivate {
  constructor(
    @Inject(AuthService) private readonly authService: AuthService,
    private configService: ConfigService,
  ) {
    super();
  }
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest();
    const res = context.switchToHttp().getResponse();

    const accessToken = req.headers['Authorization']?.split(' ')[1];
    const refreshToken = req.cookies?.['refreshToken'];

    if (!accessToken) {
      return super.canActivate(context) as Promise<boolean>;
    }

    try {
      jwt.verify(
        accessToken,
        this.configService.getOrThrow<string>('jwt.secret'),
      );
    } catch (err) {
      if (refreshToken) {
        try {
          const payload =
            await this.authService.validateRefreshToken(refreshToken);
          const newAccessToken = this.authService.generateAccessToken(payload);

          const cookieOptions = this.configService.getOrThrow('cookie').options;
          res.cookie('accessToken', newAccessToken, cookieOptions);

          req.headers['authorization'] = `Bearer ${newAccessToken}`;
        } catch (err) {
          throw new UnauthorizedException('Invalid refresh token');
        }
      } else {
        throw new UnauthorizedException('Invalid access token');
      }
    }

    return super.canActivate(context) as Promise<boolean>;
  }
}
