import {
  BadRequestException,
  Body,
  Controller,
  Post,
  Req,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register-dto';
import { User } from 'src/generated/prisma/client';
import { LoginDto } from './dto/login-dto';
import type { RequestWithUser } from './interface/request-with-user.interface';
import { Public } from 'src/common/decorators/public.decorator';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Public()
  @Post('register')
  async register(@Body() dto: RegisterDto): Promise<User> {
    return await this.authService.register(dto);
  }

  @Public()
  @Post('login')
  async login(@Body() dto: LoginDto) {
    return await this.authService.login(dto);
  }

  // @Public()
  @Post('refresh')
  async refresh(@Body('refreshToken') refreshToken: string) {
    if (!refreshToken) {
      throw new BadRequestException('Refresh token is required');
    }

    return await this.authService.refreshToken(refreshToken);
  }

  @Post('logout')
  async logout(@Req() req: RequestWithUser) {
    return await this.authService.logout(req.user.id);
  }
}
