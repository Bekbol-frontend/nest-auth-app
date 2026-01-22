import {
  ConflictException,
  Injectable,
  InternalServerErrorException,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from 'src/prisma/prisma.service';
import { RegisterDto } from './dto/register-dto';
import bcrypt from 'bcrypt';
import { LoginDto } from './dto/login-dto';
import { Payload } from './dto/payload-dto';
import { User } from 'src/generated/prisma/client';

@Injectable()
export class AuthService {
  constructor(
    private readonly prismaService: PrismaService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  async register(dto: RegisterDto): Promise<User> {
    try {
      const { email, password, role } = dto;

      const salt = await bcrypt.genSalt();
      const hashedPassword = await bcrypt.hash(password, salt);

      return await this.prismaService.user.create({
        data: {
          email,
          password: hashedPassword,
          role,
        },
      });
    } catch (error) {
      if (error.code === 'P2002') {
        throw new ConflictException('Email already exists');
      }
      throw new InternalServerErrorException(`Error: ${error.message}`);
    }
  }

  async login(dto: LoginDto) {
    try {
      const { email, password } = dto;

      const user = await this.prismaService.user.findUnique({
        where: { email },
      });
      if (!user) {
        throw new UnauthorizedException('Invalid credentials');
      }

      const matchPassword = await bcrypt.compare(password, user.password);
      if (!matchPassword) {
        throw new UnauthorizedException('Invalid credentials');
      }

      const { accessToken, refreshToken } = await this.generatedTokens({
        id: user.id,
        email: user.email,
        role: user.role,
      });

      const salt = await bcrypt.genSalt();
      const hashedRt = await bcrypt.hash(refreshToken, salt);

      await this.prismaService.user.update({
        where: { id: user.id },
        data: { hashedRt },
      });

      return {
        accessToken,
        refreshToken,
      };
    } catch (error) {
      if (error instanceof UnauthorizedException) {
        throw error;
      }

      throw new InternalServerErrorException(`Error: ${error.message}`);
    }
  }

  async refreshToken(refreshToken: string) {
    try {
      const payload = await this.jwtService.verifyAsync<Payload>(refreshToken, {
        secret: this.configService.getOrThrow('REFRESH_SECRET_KEY'),
      });

      const user = await this.prismaService.user.findUnique({
        where: { id: payload.id },
      });
      if (!user || !user.hashedRt) {
        throw new UnauthorizedException('Invalid refresh token');
      }

      const matchRefreshToken = await bcrypt.compare(
        refreshToken,
        user.hashedRt,
      );
      if (!matchRefreshToken) {
        throw new UnauthorizedException('Invalid refresh token');
      }

      const { accessToken, refreshToken: newRefreshToken } =
        await this.generatedTokens({
          id: payload.id,
          email: payload.email,
          role: payload.role,
        });

      const salt = await bcrypt.genSalt();
      const hashedRt = await bcrypt.hash(newRefreshToken, salt);

      await this.prismaService.user.update({
        where: { id: payload.id },
        data: { hashedRt },
      });

      return {
        accessToken,
        refreshToken: newRefreshToken,
      };
    } catch (error) {
      if (error instanceof UnauthorizedException) {
        throw error;
      }

      if (
        error.name === 'JsonWebTokenError' ||
        error.name === 'TokenExpiredError'
      ) {
        throw new UnauthorizedException('Invalid or expired refresh token');
      }

      throw new InternalServerErrorException(`Error: ${error.message}`);
    }
  }

  async logout(id: number) {
    try {
      const user = await this.prismaService.user.findUnique({
        where: { id },
      });

      if (!user) {
        throw new NotFoundException('User not found');
      }

      await this.prismaService.user.update({
        where: { id },
        data: {
          hashedRt: null,
        },
      });

      return {
        message: 'Logout successful',
      };
    } catch (error) {
      if (error instanceof NotFoundException) {
        throw error;
      }

      throw new InternalServerErrorException(`Error: ${error.message}`);
    }
  }

  async generateAccessToken(dto: Payload) {
    return await this.jwtService.signAsync(dto);
  }

  async generateRefreshToken(dto: Payload) {
    return await this.jwtService.signAsync(dto, {
      secret: this.configService.getOrThrow('REFRESH_SECRET_KEY'),
      expiresIn: this.configService.getOrThrow('REFRESH_EXPIRATION'),
    });
  }

  async generatedTokens(dto: Payload) {
    const accessToken = await this.generateAccessToken(dto);
    const refreshToken = await this.generateRefreshToken(dto);

    return {
      accessToken,
      refreshToken,
    };
  }
}
