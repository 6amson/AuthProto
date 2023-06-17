import { Prop, Schema, SchemaFactory } from "@nestjs/mongoose";
import { IsEmail} from 'class-validator';
import { HydratedDocument } from 'mongoose';
// export type UserDocument = User & Document;
export type UserDocument = HydratedDocument<User>;

@Schema()
export class User {
    @Prop({required:true})
    firstname: string;
    @Prop({required:true})
    lastname: string;
    @Prop({required:true, unique:true, lowercase:true})
    @IsEmail()
    email: string;
    @Prop({required:true})
    password: string;
}
export const UserSchema = SchemaFactory.createForClass(User);