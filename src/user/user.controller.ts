import { Controller, Get, UseGuards, Req, Patch } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { User } from '@prisma/client';
import { GetUser } from '../../src/auth/decorator';
import { JwtGaurd } from '../../src/auth/gaurd';

@UseGuards(JwtGaurd)
@Controller('users')
export class UserController {
  @Get('me')
  getMe(@GetUser() user: User, @GetUser('email') email: string) {
    console.log(email);
    return user;
  }
}
