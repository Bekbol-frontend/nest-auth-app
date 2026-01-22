import type { Request } from 'express';
import { Payload } from '../dto/payload-dto';

export interface RequestWithUser extends Request {
  user: Payload;
}
