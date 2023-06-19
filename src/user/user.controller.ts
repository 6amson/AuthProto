import { Body, Controller, Delete, Get, HttpStatus, Redirect, Param, Post, Headers, Put, Req, Res } from "@nestjs/common";
import { User } from "./schema/user.schema";
import { UserService } from "./user.service";
import { UserDto } from "./dto/user.dto"
// import { JwtService } from '@nestjs/jwt'

@Controller()
export class UserController {
    constructor(private readonly userService: UserService) { }

    @Get()
    @Redirect('https://documenter.getpostman.com/view/26141564/2s93si2AR7', 301)
    redirectToWebsite() {}


    @Post('user/signup')
    async Signup(@Res() response, @Body() user: User) {
        const newUSer = await this.userService.signup(user);
        return response.status(HttpStatus.CREATED).json({
            newUSer
        })
    }

    @Post('user/signin')
    async SignIn(@Res() response, @Body() user: UserDto) {
        const token = await this.userService.signin(user);
        return response.status(HttpStatus.OK).json(token)
    }

    @Get('user/verify')
    async verifyAuth (@Headers('authorization') authHeader: string, @Req() request: object){
        return this.userService.verifyAuth(authHeader, request)
    }
}
