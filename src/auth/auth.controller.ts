import { Controller, Get, Post, Body, Patch, Param, Delete, UseGuards, Request, Headers } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto, UpdateAuthDto, LoginDto } from './dto';
import { RegisterDto } from './dto/register.dto';
import { AuthGuard } from './guards/auth.guard';
import { LoginResponse } from './interfaces/login-response';
import { User } from './entities/user.entity';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post()
  create(@Body() createUserDto: CreateUserDto) {
    return this.authService.create(createUserDto);
  }

  @Post('/login')
  login(@Body() loginDto: LoginDto ) {
    return this.authService.login( loginDto );
  }

  @Post('/register')
  register(@Body() registerDto: RegisterDto){
    return this.authService.register( registerDto );
  }

  @UseGuards( AuthGuard )
  @Get()
  findAll( @Request() req: Request ) {
    return this.authService.findAll();
  }
  
  @UseGuards( AuthGuard )
  @Get('/check-token')
  checkToken(@Request() req: Request): LoginResponse {
    return this.authService.checkJwToken( req['user'] );
    // return this.authService.checkJwToken( auth )
    // return 'is valid'
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.authService.findOne(+id);
  }

  @Patch(':id')
  update(@Param('id') id: string, @Body() updateAuthDto: UpdateAuthDto) {
    return this.authService.update(+id, updateAuthDto);
  }

  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.authService.remove(+id);
  }
}
