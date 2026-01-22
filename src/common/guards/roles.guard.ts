import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { RequestWithUser } from 'src/auth/interface/request-with-user.interface';
import { ROLES_KEY } from 'src/common/decorators/roles.decorator';
import { Role } from 'src/generated/prisma/enums';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<Role[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (!requiredRoles) {
      return true;
    }

    const { user } = context.switchToHttp().getRequest<RequestWithUser>();

    if (!user.role) {
      throw new ForbiddenException('Role mavjud emas');
    }

    if (!requiredRoles.includes(user.role)) {
      throw new ForbiddenException('Sizda ruxsat yo‘q');
    }

    return true;
  }
}
