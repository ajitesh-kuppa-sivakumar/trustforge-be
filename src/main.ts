import { NestFactory } from "@nestjs/core";
import { ValidationPipe } from "@nestjs/common";
import { SwaggerModule, DocumentBuilder } from "@nestjs/swagger";
import { AppModule } from "./app.module";
import { WinstonModule } from "nest-winston";
import * as winston from "winston";
import * as bodyParser from "body-parser";

async function bootstrap() {
  // Configure Winston logger
  const logger = WinstonModule.createLogger({
    transports: [
      new winston.transports.Console({
        format: winston.format.combine(
          winston.format.timestamp(),
          winston.format.colorize(),
          winston.format.printf(({ timestamp, level, message }) => {
            return `${timestamp} [${level}]: ${message}`;
          })
        ),
        level: "debug",
      }),
      new winston.transports.File({
        filename: "logs/error.log",
        level: "debug",
        format: winston.format.combine(
          winston.format.timestamp(),
          winston.format.json()
        ),
      }),
      new winston.transports.File({
        filename: "logs/combined.log",
        format: winston.format.combine(
          winston.format.timestamp(),
          winston.format.json()
        ),
      }),
    ],
  });

  const app = await NestFactory.create(AppModule, { logger });

  // Increase the body size limit
  app.use(bodyParser.json({ limit: "100mb" }));
  app.use(bodyParser.urlencoded({ limit: "100mb", extended: true }));

  // Enable CORS
  app.enableCors({
    origin: "http://localhost:3000",
    methods: "GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS",
    allowedHeaders: "Content-Type, Authorization",
  });

  // Enable validation pipes
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      transform: true,
      forbidNonWhitelisted: true,
    })
  );

  // Setup Swagger
  const config = new DocumentBuilder()
    .setTitle("TrustForge API")
    .setDescription("Mobile App Security Analysis Platform API")
    .setVersion("1.0")
    .addBearerAuth()
    .build();
  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup("api", app, document);

  await app.listen(3001);
}
bootstrap();
