import { createParamDecorator, ExecutionContext, Logger } from "@nestjs/common";

export const CurrentUser = createParamDecorator(
  (data: unknown, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    const user = request.user;
    const logger = new Logger("CurrentUserDecorator");
    return user;
  }
);
