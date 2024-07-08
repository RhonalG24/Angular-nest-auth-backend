import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException, UnsupportedMediaTypeException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { JwtService } from '@nestjs/jwt';
import { Model } from 'mongoose';

import * as bcryptjs from 'bcryptjs';

import { CreateUserDto, UpdateAuthDto, LoginDto, RegisterDto} from './dto';
import { User } from './entities/user.entity';

import { JwtPayload } from './interfaces/jwt-payload';
import { LoginResponse } from './interfaces/login-response';

@Injectable()
export class AuthService {

  constructor(
    @InjectModel( User.name ) 
    private userModel: Model<User>,
    private jwtService: JwtService,

  ) {}

  async create(createUserDto: CreateUserDto): Promise<User> {
   
    try {
      
      // 1.- Encriptar la contraseña
      const { password, ...userData } = createUserDto;
      const newUser = new this.userModel( {
        password: bcryptjs.hashSync( password, 10 ),
        ...userData
      } );
      
      // 2.- guardar el usuario
      await newUser.save();
      
      // 3.- Generar el JWT
       const { password:_, ...user } = newUser.toJSON();
      
      return user;

    } catch (error) {
      if ( error.code === 11000 ){
        throw new BadRequestException(`${ createUserDto.email } already exists!`);
      }
      throw new InternalServerErrorException('Something terrible happen!!')
    }
  }

  async register( registerDto: RegisterDto ): Promise<LoginResponse> {
    const user = await this.create( registerDto );
    return {
      user: user,
      token: this.getJwToken({ id: user._id }),
    }
  }

  async login( loginDto: LoginDto ): Promise<LoginResponse> {
    const { email, password } = loginDto;

    const user = await this.userModel.findOne({ email: email });
    if ( !user ) {
      throw new UnauthorizedException('Not valid credentials - email');
    }
    
    if( !bcryptjs.compareSync( password, user.password )){
      throw new UnauthorizedException('Not valid credentials - password');
    }

    const { password:_, ...rest } = user.toJSON();
    return {
      user: rest,
      token: this.getJwToken( { id: user.id } ),
    }
  }

  findAll() {
    return this.userModel.find();
  }

  async findUserById( id: string ): Promise<User>{
    const user = await this.userModel.findById(id);
    const { password, ...rest } = user.toJSON();
    return rest;
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  getJwToken( payload: JwtPayload ){
    const token = this.jwtService.sign(payload);
    return token;
  }

  // async checkJwToken( auth: string): Promise<LoginResponse>{
  //   // console.log(auth)
  //   const token = auth.replace('Bearer ', '');
  //   const payload = await this.jwtService.verifyAsync<JwtPayload>(
  //     token,
  //     { secret: process.env.JWT_SEED }
  //   )

  //   const user = await this.findUserById( payload.id );
  //   // const token = this.extractTokenFromHeader(request);
  //   return {
  //     user: user,
  //     token: token
  //   };
  // }
  checkJwToken( user: User): LoginResponse{
    // console.log(auth)
    return {
      user: user,
      token: this.getJwToken({ id: user._id})
    };
  }
}
