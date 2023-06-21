import { Injectable, HttpException, HttpStatus, Req } from "@nestjs/common";
import { httpErrorException } from './user.exception';
import { InjectModel } from "@nestjs/mongoose";
import { Model } from "mongoose";
import { User } from "./schema/user.schema";
import * as bcrypt from 'bcryptjs';
import * as jwt from 'jsonwebtoken';
import { config } from 'dotenv';
import { UserDto } from "./dto/user.dto";
import { UnauthorizedException } from '@nestjs/common';
import { Request } from 'express';
// import { JwtService } from '@nestjs/jwt';


config();

const accessTokenSecret: string = process.env.ACCESS_TOKEN_SECRET;
const refreshTokenSecret: string = process.env.REFRESH_TOKEN_SECRET;

@Injectable()
export class UserService {

    constructor(@InjectModel(User.name) private userModel: Model<User>) { }


    private generateAccessToken(payload: any): string {
        return jwt.sign(payload, accessTokenSecret, {
            expiresIn: '5m',
        });
    }

    private generateRefreshToken(payload: any): string {
        return jwt.sign(payload, refreshTokenSecret, {
            expiresIn: "24h",
        });
    }

    validateToken(token: string, secret: string): boolean {
        try {
            jwt.verify(token, secret);
            return true;
        } catch (error) {
            return false;
        }
    }


    async findOne(mail: string): Promise<User> {
        return this.userModel.findOne({ email: mail }).exec();
    }


    async signup(user: User): Promise<User> {
        const existingUser = await this.userModel.findOne({ email: user.email }).exec();
        // console.log(existingUser);

        if (existingUser) {
            throw new httpErrorException('User with this email already exists', HttpStatus.CONFLICT);
            // return (existingUser);
            // throw new HttpException('User with this email already exists', HttpStatus.CONFLICT);
        }

        const hashedPassword = await bcrypt.hash(user.password, 10);

        const newUser = await this.userModel.create({
            ...user,
            password: hashedPassword,
        });

        return newUser.save();


    }

    async signin(user: UserDto): Promise<{ accessToken: string, refreshToken: string }> {
        const foundUser = await this.userModel.findOne({ email: user.email }).exec();


        if (!foundUser) {
            throw new HttpException('Invalid email or password', HttpStatus.UNAUTHORIZED);
        }

        const isPasswordValid = await bcrypt.compare(user.password, foundUser.password);

        if (!isPasswordValid) {
            throw new HttpException('Invalid email or password', HttpStatus.UNAUTHORIZED);
        }

        const accessToken = this.generateAccessToken({ sub: foundUser._id });
        const refreshToken = this.generateRefreshToken({ sub: foundUser._id });


        return {
            accessToken,
            refreshToken,
        }

    }


    public verifyAuth(verifyHeader: string, @Req() request: Request): string {
        const authHeader = request.headers['authorization'];

        //set accessToken directly from header
        const token = authHeader && authHeader.split(' ')[1];

        // const token = authHeader;

        //logic to set accesstoken from request object MAY come in here

        if (token || verifyHeader) {
            try {
                const decodedToken = jwt.verify(token || verifyHeader, accessTokenSecret);
                const userId = decodedToken.sub;

                //if there is accessToken, return a refreshTtoken
                return this.generateRefreshToken(userId);

            } catch (err) {
                throw new UnauthorizedException('Invalid token', err.message);
            }
        }else {
            // throw new UnauthorizedException('No user');
            throw new UnauthorizedException ('No user');
        }
    } 
}

