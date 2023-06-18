import { Prop, Schema, SchemaFactory } from "@nestjs/mongoose";
import { IsEmail, IsNotEmpty } from 'class-validator';
import { HydratedDocument } from 'mongoose';
// export type UserDocument = User & Document;
export type UserDocument = HydratedDocument<User>;

@Schema()
export class User {
    @Prop({required:true})
    @IsNotEmpty()
    firstname: string;
    @Prop({required:true})
    @IsNotEmpty()
    lastname: string;
    @Prop({required:true, unique:true, lowercase:true})
    @IsEmail()
    email: string;
    @Prop({required:true})
    password: string;
}
export const UserSchema = SchemaFactory.createForClass(User);


// {
//     "firstname": "Layi",
//     "lastname": "Wasabi",
//    "email": "kokomaster5@yahoo.com",
//    "password": "extrovert7"
//  }