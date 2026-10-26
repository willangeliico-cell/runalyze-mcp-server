import { Injectable, CanActivate, ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Observable } from 'rxjs';
import { IS_PUBLIC_KEY } from './public.decorator';

@Injectable()
export class BearerAuthGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean | Promise<boolean> | Observable<boolean> {
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (isPublic) return true;

    const request = context.switchToHttp().getRequest();
    const authHeader = request.headers['authorization'];
    const configuredRunalyzeToken = process.env.RUNALYZE_API_TOKEN;
    const configuredAccessToken = process.env.MCP_ACCESS_TOKEN;

    if (!authHeader?.startsWith('Bearer ')) {
      throw new UnauthorizedException('Missing Authorization header. Please provide a Bearer token.');
    }

    const token = authHeader.substring(7).trim();
    if (!token) throw new UnauthorizedException('Bearer token is empty');

    if (configuredRunalyzeToken) {
      if (!configuredAccessToken || token !== configuredAccessToken) {
        throw new UnauthorizedException('Invalid MCP access token.');
      }
      return true;
    }

    request.runalyzeToken = token;
    return true;
  }
}
