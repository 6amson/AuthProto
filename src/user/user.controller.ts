import { Body, Controller, Delete, Get, HttpStatus, Param, Post, UploadedFiles, Put, Req, Res } from "@nestjs/common";
import { User } from "./schema/user.schema";
import { UserService } from "./user.service";
// import { JwtService } from '@nestjs/jwt'

@Controller('user')
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Post('signup')
  async Signup(@Res() response, @Body() user: User) {
      const newUSer = await this.userService.signup(user);
      return response.status(HttpStatus.CREATED).json({
          newUSer
      })
  }
  @Post('signin')
  async SignIn(@Res() response, @Body() user: User) {
      const token = await this.userService.signin(user);
      return response.status(HttpStatus.OK).json(token)
  }
}