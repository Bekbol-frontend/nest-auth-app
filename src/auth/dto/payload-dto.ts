import { IsEnum } from 'class-validator';
import { Role } from 'src/generated/prisma/enums';

export class Payload {
  id: number;
  email: string;
}
