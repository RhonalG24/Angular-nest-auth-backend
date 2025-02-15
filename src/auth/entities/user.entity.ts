import { Prop, Schema, SchemaFactory } from "@nestjs/mongoose";

@Schema()
export class User {

    _id?: string;
    
    @Prop({ unique: true, required: true})
    email:string;
    
    @Prop({ required: true })
    name:string;
    
    @Prop({ minlength: 6, required: true })
    password?:string;
    
    @Prop({ default: true })
    isActive:string;
    
    @Prop({ type: [String], defaul: ['user'] })
    roles:string[];
}

export const UserSchema = SchemaFactory.createForClass( User );
