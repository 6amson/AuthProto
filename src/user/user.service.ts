import { Injectable, HttpException, HttpStatus, Res } from "@nestjs/common";
import { InjectModel } from "@nestjs/mongoose";
import { Model } from "mongoose";
import { User, UserDocument } from "./schema/user.schema";
import * as bcrypt from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';
import * as jwt from 'jsonwebtoken';

const accessTokenSecret: string = process.env.ACCESS_TOKEN_SECRET;
const refreshTokenSecret: string = process.env.REFRESH_TOKEN_SECRET;

@Injectable()
export class UserService {

    constructor(@InjectModel(User.name) private userModel: Model<User>) {}
    

    private generateAccessToken(payload: any): string {
        return jwt.sign(payload, accessTokenSecret, {
            expiresIn: '5m',
        });
    }

    private generateRefreshToken(payload: any): string {
        return jwt.sign(payload, refreshTokenSecret, {
            expiresIn: '7d',
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

    async signup(user: User): Promise<User> {
        const existingUser = await this.userModel.findOne({ email: user.email }).exec();

       try{
        if (existingUser) {
            throw new HttpException('User with this email already exists', HttpStatus.CONFLICT);
        }

        const hashedPassword = await bcrypt.hash(user.password, 10);

        const newUser = await this.userModel.create({
            ...user,
            password: hashedPassword,
        });

        return newUser.save();

       } catch (error){
        console.error('An error occurred:', error.message);
       }
    }

    async signin(user: User): Promise<{ accessToken: string, refreshToken: string }> {
        const foundUser = await this.userModel.findOne({ email: user.email }).exec();

        try{
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
                refreshToken
            };
        } catch (error){
            console.error('An error occurred:', error.message);
        }
    }




}